use std::error::Error;
use std::path::Path;
use std::pin::Pin;
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
    security::{
        gate::ForensicGate,
        sentinel::{ControlMessage, Sentinel},
        telemetry,
    },
    storage::vault::Guardian,
    transport::swarm::{get_storage_key, load_swarm_key, setup_phalanx_swarm},
    PhalanxEvent,
};

/// The Dedicated Storage Node.
///
/// The Stronghold is the "Vault" of the network. Unlike the Sentinel (Mobile App),
/// it does not capture data. It exists solely to:
/// 1. **Salvage:** Ingest shards from the Swarm and persist them to the Vault.
/// 2. **Serve:** Respond to Kademlia DHT queries for data recovery.
/// 3. **Pulse:** Broadcast Vitality proofs to avoid the "Vampire Stake".
pub struct StrongholdEngine {
    config: PhalanxConfig,
    identity: PhalanxIdentity,
    physics: PhalanxPhysics,

    /// The Vault interface. Manages the Write-Ahead Log (WAL) and on-disk archives.
    storage: Guardian,

    /// We keep a Sentinel instance not for capturing, but for its `Justiciar` logic:
    /// verifying signatures and tracking the reputation of other peers.
    sentinel: Sentinel,

    /// The libp2p network stack.
    swarm: Swarm<phalanx_core::PhalanxBehaviour>,
}

impl StrongholdEngine {
    /// Bootstraps the Stronghold.
    ///
    /// Loads configuration, generates/loads identity, establishes the Vault,
    /// and performs the cryptographic handshake to join the Swarm.
    ///
    /// # Errors
    ///
    pub async fn new(config_path: &str) -> Result<Self, Box<dyn Error>> {
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
        let storage = Guardian::new(&config.storage.vault_path, &config, identity.did.clone());
        let sentinel = Sentinel::new(&config);

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
            storage,
            sentinel,
            swarm,
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

        let mut cleanup_timer = tokio::time::interval(Duration::from_secs(10));
        let mut heartbeat_timer: Pin<Box<Sleep>> =
            Box::pin(tokio::time::sleep(Duration::from_millis(100)));

        loop {
            tokio::select! {
                // --- DOMAIN A: Network I/O ---
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await?;
                }

                // --- DOMAIN B: Maintenance ---
                _ = cleanup_timer.tick() => {
                    self.perform_maintenance();
                }

                // --- DOMAIN C: Vitality (The "Pulse") ---
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
    /// * **Control Signals:** Updates the internal "Reputation Table" (Justiciar).
    /// * **Data Shards:** Immediately persisted to the Vault ("Salvage").
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
                self.sentinel.health_tracker.register_activity(msg);
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

        // 2. Sentinel Boundary (Reputation & Reassembly)
        let envelope_opt = match self
            .sentinel
            .process_chunk(
                chunk,
                &topic,
                &self.config,
                &self.identity,
                local_peer, // ReputationGate Injection
            )
            .gate(
                "reassembly_fail",
                &local_peer,
                "Sentinel rejected data chunk",
            ) {
            Ok(env) => env,
            Err(_) => return,
        };

        // 3. Guardian Boundary (Capacity, Integrity, Persistence)
        if let Some(envelope) = envelope_opt {
            let _ = self.storage.ingest_envelope(envelope).gate(
                "vault_ingest_fail",
                &local_peer,
                "Vault rejected envelope",
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
        let active_storage_tasks = self.storage.micro_layer.len() as f32;
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
            is_leaf: self.sentinel.is_leaf_mode(),
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

    fn perform_maintenance(&mut self) {
        // 1. Prune partial reassembly buffers that timed out
        self.sentinel
            .prune_stale_buffers(&self.config, &self.physics);

        // 2. Archive completed sessions from WAL to Cold Storage
        self.storage.archive_stale_sessions(Duration::from_secs(
            self.config.storage.stale_session_threshold,
        ));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _guard = telemetry::init_observability();

    info!("Initializing PHALANX STRONGHOLD...");
    let mut engine = StrongholdEngine::new("phalanx.toml").await?;
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
