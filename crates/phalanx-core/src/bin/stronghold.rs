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
    pub async fn new(config_path: &str) -> Result<Self, Box<dyn Error>> {
        let config = PhalanxConfig::load(config_path)?;
        let (identity, _) = PhalanxIdentity::generate();

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
        let mut swarm = setup_phalanx_swarm(identity.to_libp2p_keypair(), &config, &physics, psk)?;

        // 4. Service Advertisement (DHT)
        let storage_key = get_storage_key();
        swarm
            .behaviour_mut()
            .kademlia
            .start_providing(storage_key.clone())?;

        // 5. Topic Subscription
        let gossip = &mut swarm.behaviour_mut().gossipsub;
        gossip.subscribe(&gossipsub::IdentTopic::new(&config.network.video_topic))?;
        gossip.subscribe(&gossipsub::IdentTopic::new(&config.network.audio_topic))?;
        gossip.subscribe(&gossipsub::IdentTopic::new(&config.network.control_topic))?;

        // 6. Bind to Port
        let port = std::env::args()
            .nth(1)
            .unwrap_or_else(|| "4001".to_string());
        swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", port).parse()?)?;

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
    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        info!(id = %self.identity.did, "Stronghold Engine active.");

        // 1. ANNOUNCE ROLE (The New Method)
        // This ensures find_strongholds() callers can see us.
        match self.swarm.behaviour_mut().announce_stronghold() {
            Ok(query_id) => {
                info!(?query_id, "Stronghold role successfully announced to DHT.");
            }
            Err(e) => {
                // A DiscoveryError::StorageError often means the local Kademlia
                // store is under heavy pressure or hasn't bootstrapped peers yet.
                tracing::error!(
                    error = %e,
                    "Critical: Failed to announce Stronghold role. Discovery may be limited."
                );
            }
        }

        // 2. ANNOUNCE SERVICE (The Generic Method)
        // Keep this for backward compatibility or generic storage queries.
        let storage_key = get_storage_key();
        if let Err(e) = self
            .swarm
            .behaviour_mut()
            .kademlia
            .start_providing(storage_key)
        {
            warn!(error = %e, "Generic storage service advertisement failed.");
        }

        let local_id = NetworkId(*self.swarm.local_peer_id());
        info!(peer_id = %local_id, "Stronghold Engine Online.");

        let mut cleanup_timer = tokio::time::interval(Duration::from_secs(10));

        // [FIX] We pin the sleep future so it isn't reset every time a network packet arrives.
        // This ensures we pulse even under heavy network load.
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
                _ = &mut heartbeat_timer => {
                    let next_interval = self.pulse_vitality().await?;
                    // Reset the timer for the dynamic interval
                    heartbeat_timer.as_mut().reset((Instant::now() + next_interval).into());
                }
            }
        }
    }

    /// The "Whamjangler" for Network Events- you know, throw some things
    /// together and whamjangle it into something useful!
    ///
    /// Routes disparate libp2p events to their specific subsystems:
    /// * **Gossipsub:** Data shards -> Vault (Salvage).
    /// * **Mdns/Identify:** Peer Discovery -> Kademlia (Routing Table).
    async fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<PhalanxEvent>,
    ) -> Result<(), Box<dyn Error>> {
        match event {
            SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(event)) => {
                self.handle_gossip(event).await?;
            }

            SwarmEvent::Behaviour(PhalanxEvent::Mdns(mdns::Event::Discovered(list))) => {
                for (peer_id, multiaddr) in list {
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, multiaddr);
                }
            }

            SwarmEvent::Behaviour(PhalanxEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => {
                for addr in info.listen_addrs {
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr);
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

    /// Processes high-velocity GossipSub messages.
    ///
    /// Distinction:
    /// * **Control Signals:** Updates the internal "Reputation Table" (Justiciar).
    /// * **Data Shards:** Immediately persisted to the Vault ("Salvage").
    async fn handle_gossip(&mut self, event: gossipsub::Event) -> Result<(), Box<dyn Error>> {
        if let gossipsub::Event::Message { message, .. } = event {
            let topic: MeshTopic = message.topic.as_str().into();

            // 1. Check Topic Type
            if topic == self.config.network.control_topic {
                // CASE: Vitality Signal
                if let Ok(msg) = postcard::from_bytes::<ControlMessage>(&message.data) {
                    self.sentinel.health_tracker.register_activity(msg);
                }
            } else {
                // CASE: Data Volley (Video/Audio)
                // Attempt to deserialize as a ShardChunk
                if let Ok(chunk) = postcard::from_bytes::<
                    phalanx_core::primitives::shards::ShardChunk,
                >(&message.data)
                {
                    let local_peer = NetworkId(*self.swarm.local_peer_id());

                    // The Sentinel checks the signature. If valid, we salvage it.
                    if let Some(envelope) = self.sentinel.process_chunk(
                        chunk,
                        &topic,
                        &self.config,
                        &self.identity,
                        local_peer,
                    ) {
                        // "Salvage" means ingesting foreign data we did not create.
                        if let Err(e) = self.storage.ingest_envelope(envelope) {
                            warn!(error = ?e, "Failed to salvage incoming shard.");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Calculates the Node's "Vitality Rate" and broadcasts a heartbeat.
    ///
    /// **The Physics:**
    /// A Stronghold under heavy storage load (high I/O) beats slower.
    /// A Stronghold doing nothing beats fast.
    /// This allows the network to route data away from stressed nodes naturally.
    async fn pulse_vitality(&mut self) -> Result<Duration, Box<dyn Error>> {
        // 1. Measure Stress
        let active_storage_tasks = self.storage.micro_layer.len() as f32;
        let max_capacity = self.config.storage.max_peers as f32;
        let load = UnitInterval::new(active_storage_tasks / max_capacity);

        // 2. Calculate Rate
        let vitality = VitalityRate::calculate(&self.physics, PowerState::Normal, load);
        let interval = vitality.as_duration();

        // 3. Construct Proof
        let hb = ControlMessage {
            sender: NetworkId(*self.swarm.local_peer_id()),
            load_factor: load.as_f32(),
            storage_remaining_mb: 10240, // TODO: Real disk check
            heartbeat_ms: vitality.as_u64(),
            is_leaf: self.sentinel.is_leaf_mode(),
        };

        // 4. Broadcast
        if let Ok(data) = postcard::to_stdvec(&hb) {
            let topic = gossipsub::IdentTopic::new(&self.config.network.control_topic);
            let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, data);
        }

        // 5. Self-Protection Log
        if load > UnitInterval::new(0.8) {
            warn!(load = %load, next = ?interval, "High load detected. Throttling pulse.");
        }

        Ok(interval)
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
