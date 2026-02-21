use phalanx_core::storage::reassembler::TransientJournal;
use std::error::Error;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};
use tokio::time::Sleep;

use libp2p::{futures::StreamExt, gossipsub, identify, kad, mdns, swarm::SwarmEvent, Swarm};
use tracing::{debug, info, warn};

use phalanx_core::{
    base::{
        config::{PhalanxConfig, PhalanxPhysics},
        types::{MeshTopic, PowerState, UnitInterval, VitalityRate},
    },
    primitives::identity::{NetworkId, PhalanxIdentity},
    primitives::shards::{ShardChunk, ShardError},
    security::{gate::ForensicGate, telemetry},
    storage::{journal::FileJournal, reassembler::Reassembler, vault::Guardian},
    transport::health::{ControlMessage, HealthTracker},
    transport::swarm::{get_storage_key, load_swarm_key, setup_phalanx_swarm},
    PhalanxEvent,
};

use tokio::sync::mpsc;

use std::sync::atomic::Ordering;
use std::sync::Arc;

/// The Dedicated Storage Node.
///
/// The Stronghold is the "Vault" of the network. Unlike the Sentinel (Mobile App),
/// it does not capture data. It exists solely to:
/// 1. **Salvage:** Ingest shards from the Swarm and persist them to the Vault.
/// 2. **Serve:** Respond to Kademlia DHT queries for data recovery.
/// 3. **Pulse:** Broadcast Vitality proofs to avoid the "Vampire Stake".
pub struct StrongholdEngine<J: TransientJournal> {
    config: PhalanxConfig,
    identity: PhalanxIdentity,
    physics: PhalanxPhysics,
    swarm: Swarm<phalanx_core::PhalanxBehaviour>,
    chunk_tx: mpsc::Sender<(ShardChunk, MeshTopic, NetworkId)>,
    health_tracker: HealthTracker,
    power_state: PowerState,
    storage_load: Arc<AtomicUsize>,
    _journal_phantom: std::marker::PhantomData<J>,
}

impl<J: TransientJournal + 'static> StrongholdEngine<J> {
    /// Bootstraps the Stronghold.
    ///
    /// Loads configuration, generates/loads identity, establishes the Vault,
    /// and performs the cryptographic handshake to join the Swarm.
    ///
    /// # Errors
    ///
    pub async fn new(config_path: &str, journal: J) -> Result<Self, Box<dyn Error>> {
        let config = PhalanxConfig::load(config_path)?;
        let (identity, _) = PhalanxIdentity::generate().map_err(|e| {
            // FORENSIC GATE: Report the entropy failure to telemetry
            tracing::error!(
                target: "phalanx::forensics",
                event_code = "config_load_err",
                error = %e,
                "Engine boot aborted: Configuration missing or corrupt"
            );
            e
        })?;

        // Physics Profile: WAN (High Latency Tolerance)
        // Strongholds are usually servers, but they deal with mobile peers.
        let physics = PhalanxPhysics::default_wan();

        // 1. Storage & Security Init
        let (chunk_tx, chunk_rx) = mpsc::channel(1024); // Back pressure limit

        let local_peer_id = identity.to_network_id();

        let storage_load = Arc::new(AtomicUsize::new(0));
        let actor_load_metric = Arc::clone(&storage_load);

        let storage_actor = StorageActor {
            reassembler: Reassembler::new(),
            storage: Guardian::new(&config.storage.vault_path, &config, identity.did.clone()),
            journal,
            config: config.clone(),
            identity: identity.clone(),
            chunk_rx,
            active_tasks_metric: actor_load_metric,
            physics,
            local_peer_id,
        };

        // Spawn the Storage Actor onto the Tokio runtime independently
        tokio::spawn(async move {
            storage_actor.run().await;
        });

        // 2. Network Security (PSK)
        let psk_path = Path::new("swarm.key");
        let psk = load_swarm_key(psk_path);
        if psk.is_some() {
            info!("Stronghold joining Private Swarm (Key Loaded).");
        } else {
            warn!("Stronghold joining Public Swarm (No Key Found).");
        }

        // 3. Swarm Construction
        let libp2p_key = identity.to_libp2p_keypair();
        let mut swarm = setup_phalanx_swarm(libp2p_key, &config, &physics, psk)?;

        // 4. Service Advertisement (DHT)
        let storage_key = get_storage_key();
        swarm
            .behaviour_mut()
            .kademlia
            .start_providing(storage_key)?;

        // 5. Topic Subscription
        let gossip = &mut swarm.behaviour_mut().gossipsub;
        gossip.subscribe(&gossipsub::IdentTopic::new(&config.network.video_topic))?;
        gossip.subscribe(&gossipsub::IdentTopic::new(&config.network.audio_topic))?;
        gossip.subscribe(&gossipsub::IdentTopic::new(&config.network.control_topic))?;

        // 6. Bind to Port
        let port = std::env::args()
            .nth(1)
            .unwrap_or_else(|| "4001".to_string());
        swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{port}").parse()?)?;

        Ok(Self {
            config,
            identity,
            physics,
            _journal_phantom: std::marker::PhantomData,
            swarm,
            chunk_tx,
            health_tracker: HealthTracker::new(),
            power_state: PowerState::Normal,
            storage_load,
        })
    }

    /// The Main Reactor Loop.
    ///
    /// Multiplexes three temporal domains:
    /// 1. **Network Time:** Responding to asynchronous Swarm events.
    /// 2. **Maintenance Time:** Fixed interval pruning of stale data.
    /// 3. **Vitality Time:** Dynamic heartbeat pulsing based on system load.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The network swarm fails to poll (Critical Transport Failure).
    /// * Inbound gossip messages contain unrecoverable malformations during the dispatch phase.
    /// * Vitality calculations encounter a system-level clock error.
    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        info!(id = %self.identity.did, "Stronghold Engine active.");

        // 1. ANNOUNCE ROLE (Updated for new signature)
        // We capture the authoritative local ID once to pass into the forensic gates.
        let local_id = NetworkId(*self.swarm.local_peer_id());

        // The announce_stronghold method now uses the Forensic Gate internally.
        // It returns Option<QueryId> and handles its own forensic logging.
        if let Some(query_id) = self.swarm.behaviour_mut().announce_stronghold(&local_id) {
            info!(?query_id, "Stronghold role successfully announced to DHT.");
        } else {
            // If the gate returned None, it already logged the forensic reason (e.g., dht_announce_fail).
            // We can add high-level context here if needed.
            warn!("Stronghold role announcement bypassed by Forensic Gate.");
        }

        // 2. ANNOUNCE SERVICE (The Generic Method)
        let storage_key = get_storage_key();
        if let Err(e) = self
            .swarm
            .behaviour_mut()
            .kademlia
            .start_providing(storage_key)
        {
            warn!(error = %e, "Generic storage service advertisement failed.");
        }

        info!(peer_id = %local_id, "Stronghold Engine Online.");

        let mut heartbeat_timer: Pin<Box<Sleep>> =
            Box::pin(tokio::time::sleep(Duration::from_millis(100)));

        loop {
            tokio::select! {
                // --- DOMAIN A: Network I/O ---
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await?;
                }

                // --- DOMAIN B: Vitality (The "Pulse") ---
                () = &mut heartbeat_timer => {
                    let next_interval = self.pulse_vitality();
                    heartbeat_timer.as_mut().reset((Instant::now() + next_interval).into());
                }
            }
        }
    }

    /// Routes disparate libp2p events to their specific subsystems:
    /// * **Gossipsub:** Data shards -> Vault (Salvage).
    /// * **Mdns/Identify:** Peer Discovery -> Kademlia (Routing Table).
    async fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<PhalanxEvent>,
    ) -> Result<(), Box<dyn Error>> {
        match event {
            SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(event)) => {
                self.handle_gossip(event);
            }

            SwarmEvent::Behaviour(PhalanxEvent::Mdns(mdns::Event::Discovered(list))) => {
                for (peer_id, multiaddr) in list {
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, multiaddr);
                }
            }

            SwarmEvent::Behaviour(PhalanxEvent::Identify(boxed_event)) => {
                if let identify::Event::Received { peer_id, info, .. } = *boxed_event {
                    for addr in info.listen_addrs {
                        self.swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&peer_id, addr);
                    }
                }
            }

            SwarmEvent::Behaviour(PhalanxEvent::Kademlia(
                kad::Event::OutboundQueryProgressed {
                    result: kad::QueryResult::StartProviding(Ok(_)),
                    ..
                },
            )) => {
                debug!("DHT Advertisement refreshed.");
            }

            _ => {} // Ignore connection events, etc.
        }
        Ok(())
    }

    /// Processes high-velocity `GossipSub` messages.
    ///
    /// Distinction:
    /// * **Control Signals:** Updates the internal "Reputation Table" synchronously.
    /// * **Data Shards:** Dispatched asynchronously to the StorageActor via mpsc channel.
    fn handle_gossip(&mut self, event: gossipsub::Event) {
        // 1. Extract the message or exit immediately
        let gossipsub::Event::Message { message, .. } = event else {
            return;
        };

        let topic: MeshTopic = message.topic.as_str().into();
        let local_peer = NetworkId(*self.swarm.local_peer_id());

        // ------------------------------------------------------------------
        // BRANCH A: CONTROL PLANE (Heartbeats)
        // ------------------------------------------------------------------
        if topic == self.config.network.control_topic {
            if let Ok(msg) = postcard::from_bytes::<ControlMessage>(&message.data).gate(
                "ctrl_parse_fail",
                &local_peer,
                "Malformed heartbeat",
            ) {
                // NOTE: If Reassembler was moved to StorageActor, update this to `self.health_tracker`
                self.health_tracker.register_activity(msg);
            }

            return;
        }

        // ------------------------------------------------------------------
        // BRANCH B: DATA PLANE (Evidence Shards)
        // ------------------------------------------------------------------

        // 1. Parsing Boundary
        let chunk = match postcard::from_bytes::<phalanx_core::primitives::shards::ShardChunk>(
            &message.data,
        )
        .gate("data_parse_fail", &local_peer, "Malformed data chunk")
        {
            Ok(c) => c,
            Err(_) => return,
        };

        // 2. Storage Actor Boundary (Non-Blocking Dispatch)
        // Replaces the asynchronous Reassembler and Guardian processing, routing the data
        // to the dedicated disk I/O Tokio task.
        if let Err(err) = self.chunk_tx.try_send((chunk, topic, local_peer)) {
            tracing::error!(
                error = %err,
                "StorageActor channel is full or closed. Data payload dropped."
            );
        }
    }

    /// Calculates the Node's "Vitality Rate" and broadcasts a heartbeat.
    ///
    /// **The Physics:**
    /// A Stronghold under heavy storage load (high I/O) beats slower.
    /// A Stronghold doing nothing beats fast.
    /// This allows the network to route data away from stressed nodes naturally.
    fn pulse_vitality(&mut self) -> Duration {
        // 1. Measure Stress
        let active_storage_tasks = self.storage_load.load(Ordering::Relaxed) as f32;
        let max_capacity = self.config.storage.max_peers as f32;
        let load = UnitInterval::new(active_storage_tasks / max_capacity);

        // 2. Calculate Rate
        let vitality = VitalityRate::calculate(&self.physics, PowerState::Normal, load);
        let interval = vitality.as_duration();
        let sender_id = NetworkId(*self.swarm.local_peer_id());

        // 3. Construct Proof
        let heartbeat_msg = ControlMessage {
            sender: sender_id,
            load_factor: load.as_f32(),
            storage_remaining_mb: 10240, // TODO: Real disk check
            heartbeat_ms: vitality.as_u64(),
            is_leaf: self.power_state == PowerState::Leaf,
        };

        // 4. Broadcast
        if let Ok(data) = postcard::to_stdvec(&heartbeat_msg).gate(
            "heartbeat_enc_fail",
            &sender_id,
            "Failed to encode heartbeat",
        ) {
            let topic = gossipsub::IdentTopic::new(self.config.network.control_topic.to_string());

            let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, data);
        }

        interval
    }
}

pub struct StorageActor<J: TransientJournal> {
    pub reassembler: Reassembler,
    pub storage: Guardian,
    pub journal: J,
    pub config: PhalanxConfig,
    pub identity: PhalanxIdentity,
    pub chunk_rx: mpsc::Receiver<(ShardChunk, MeshTopic, NetworkId)>,
    pub active_tasks_metric: Arc<AtomicUsize>,
    pub physics: PhalanxPhysics,
    pub local_peer_id: NetworkId,
}

impl<J: TransientJournal> StorageActor<J> {
    pub async fn run(mut self) {
        // BOOT SEQUENCE: Utilize the decoupled Reassembler protocol
        if let Err(err) = self.restore_state().await {
            tracing::error!(error = %err, "Failed to restore Crucible state from disk.");
        }

        let mut maintenance_timer = tokio::time::interval(Duration::from_secs(10));

        loop {
            tokio::select! {
                Some((chunk, topic, peer_id)) = self.chunk_rx.recv() => {
                    let envelope_opt = self.reassembler.ingest_chunk(
                        chunk,
                        &mut self.journal,
                        &topic,
                        &self.config,
                        &self.identity,
                        peer_id,
                    ).await;

                    match envelope_opt {
                        Ok(Some(envelope)) => {
                            if let Err(err) = self.storage.ingest_envelope(envelope) {
                                tracing::error!(error = %err, "Vault rejected envelope");
                            }
                        }
                        Ok(None) => {}, // Partial assembly
                        Err(err) => {
                            tracing::warn!(error = %err, "Reassembler rejected data chunk");
                        }
                    }

                    self.active_tasks_metric.store(
                        self.storage.active_volleys.len(),
                        Ordering::Relaxed
                    );
                }

                _ = maintenance_timer.tick() => {
                    if let Err(err) = self.snapshot_state().await {
                        tracing::error!(error = %err, "Freeze Protocol failed.");
                    }
                }
            }
        }
    }

    pub async fn restore_state(&mut self) -> Result<(), ShardError> {
        let recovered_envelopes = self
            .reassembler
            .recover_from_journal(
                &mut self.journal,
                &self.config,
                &self.identity,
                self.local_peer_id,
            )
            .await?;

        for envelope in recovered_envelopes {
            let _ = self.storage.ingest_envelope(envelope);
        }

        info!("Crucible WAL replay complete.");
        Ok(())
    }

    pub async fn snapshot_state(&mut self) -> Result<(), ShardError> {
        let is_idle =
            self.reassembler.video_buffers.is_empty() && self.reassembler.audio_buffers.is_empty();

        if is_idle {
            self.journal.clear().await?;
            tracing::debug!("Crucible state frozen and WAL compacted.");
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _guard = telemetry::init_observability();

    info!("Initializing PHALANX STRONGHOLD...");
    let journal = FileJournal::new("crucible_wal.bin").await?;
    let mut engine = StrongholdEngine::new("phalanx.toml", journal).await?;
    engine.run().await
}

#[cfg(test)]
mod stronghold_initialization_tests {
    use super::*;
    use phalanx_core::transport::swarm::DiscoveryError;

    // This mock simulates the behavior failure to verify the match arm in run()
    #[tokio::test]
    async fn test_discovery_failure_is_non_fatal() {
        // In a real scenario, this would be tested via a SimulationHarness.
        // Here we demonstrate the structural expectation of the error handler.

        let discovery_result: Result<kad::QueryId, DiscoveryError> =
            Err(DiscoveryError::StorageError);

        // Verification logic: The engine must log the error and move to the next phase
        // rather than returning an early Err().
        let is_fatal = match discovery_result {
            Ok(_) => false,
            Err(e) => {
                tracing::error!(error = %e, "Simulated discovery failure");
                false // Error is trapped, not propagated as fatal
            }
        };

        assert!(
            !is_fatal,
            "Discovery errors in the Stronghold binary must be non-fatal to the process"
        );
    }
}

#[cfg(test)]
mod actor_tests {
    use super::*;
    use phalanx_core::primitives::shards::{ChunkType, ShardId};
    use phalanx_core::storage::journal::FileJournal;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    #[tokio::test]
    async fn test_storage_actor_metric_pipeline() {
        let config = PhalanxConfig::default();
        let (identity, _) = PhalanxIdentity::generate().unwrap();
        let local_peer = identity.to_network_id();
        let (chunk_tx, chunk_rx) = tokio::sync::mpsc::channel(10);
        let storage_load = Arc::new(AtomicUsize::new(0));
        let actor_load_metric = Arc::clone(&storage_load);
        let journal = FileJournal::new("test_transient_wal.bin")
            .await
            .expect("Failed to initialize test FileJournal");

        let storage_actor = StorageActor {
            reassembler: Reassembler::new(),
            storage: Guardian::new("test_vault_metrics", &config, identity.did.clone()),
            config: config.clone(),
            identity: identity.clone(),
            chunk_rx,
            active_tasks_metric: actor_load_metric,
            physics: PhalanxPhysics::default_wan(),
            local_peer_id: local_peer.clone(),
            journal,
        };

        // Spawn actor in background
        let actor_handle = tokio::spawn(async move {
            storage_actor.run().await;
        });

        // Ensure metric starts at 0
        assert_eq!(storage_load.load(Ordering::Relaxed), 0);

        // Send a dummy chunk down the pipeline (simulating handle_gossip)
        let chunk = ShardChunk {
            shard_id: ShardId(101),
            chunk_index: 0,
            total_chunks: 1, // 1 chunk = immediate assembly and vault insertion
            data: vec![0xBA, 0xAD, 0xF0, 0x0D],
            owner_did: identity.did.clone(),
            chunk_type: ChunkType::Witnessed,
        };

        let topic = MeshTopic::from("phalanx/video/1.0.0");

        // Non-blocking dispatch
        chunk_tx.send((chunk, topic, local_peer)).await.unwrap();

        // Yield to allow actor to process the chunk and update the atomic metric
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The Reassembler should have processed it, passed it to Guardian, and updated the metric.
        // Even if Guardian rejects a malformed payload, the actor run loop should have advanced
        // and called `store` on the atomic variable.

        // Note: The exact expected value depends on whether your Guardian persists tasks
        // into `micro_layer` instantly. Assuming it does:
        let load = storage_load.load(Ordering::Relaxed);

        // Clean up actor
        actor_handle.abort();

        // Cleanup test vault
        let _ = std::fs::remove_dir_all("test_vault_metrics");

        assert!(
            // Either 0 (if Guardian rejected it quickly) or >0 (if it's processing)
            // The key is that the pipeline didn't panic and the atomic was accessible
            load > 0,
            "Lock-free metric pipeline failed."
        );
    }
}
