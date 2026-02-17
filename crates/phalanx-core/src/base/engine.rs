use futures::StreamExt;
use libp2p::swarm::{Swarm, SwarmEvent};
use std::error::Error;
use tokio::sync::mpsc;

use crate::base::config::{PhalanxConfig, PhalanxPhysics};
use crate::primitives::identity::{Did, NetworkId, PhalanxIdentity};
use crate::primitives::shards::{AudioShard, Evidence, VideoShard, WitnessEnvelope};
use crate::storage::strategies::ShardAmalgam;
use crate::storage::vault::Guardian;
use crate::{PhalanxBehaviour, PhalanxEvent};
pub use libp2p::pnet::PreSharedKey;

/// The Central Nervous System of a Phalanx Node.
///
/// The Engine orchestrates the three critical lifecycles of the application:
/// 1. **The Witness Cycle:** Ingesting raw sensor data (Video/Audio), signing it
///    with the Identity ("Ghost Key"), and sealing it into `WitnessEnvelopes`.
/// 2. **The Swarm Cycle:** Managing the libp2p mesh, handling peer discovery,
///    and routing GossipSub messages.
/// 3. **The Storage Cycle:** Directing the `Guardian` to persist evidence to the
///    Vault (Disk/WAL) and preparing it for network distribution.
pub struct PhalanxEngine {
    #[allow(dead_code)]
    config: PhalanxConfig,

    /// The cryptographic identity used to sign all locally generated evidence.
    identity: PhalanxIdentity,

    /// The libp2p network manager. Handles the low-level noise of TCP/UDP/QUIC.
    swarm: Swarm<PhalanxBehaviour>,

    /// The "Jitter Buffer" and Reassembly logic.
    /// Used to reconstruct Volleys from incoming network shards.
    #[allow(dead_code)]
    crucible: crate::storage::crucible::Crucible<ShardAmalgam>,

    /// The interface to the local disk. Manages the Write-Ahead Log (WAL)
    /// and the long-term shard archive.
    guardian: Guardian,

    /// Input channel for raw video frames from the hardware driver.
    video_rx: mpsc::Receiver<VideoShard>,
    /// Input channel for raw audio samples from the hardware driver.
    audio_rx: mpsc::Receiver<AudioShard>,
}

impl PhalanxEngine {
    /// Bootstraps the Phalanx Engine with explicit configuration.
    ///
    /// This constructor performs the "Grand Linkage":
    /// 1. Initializes the **Guardian** at the specified vault path.
    /// 2. Configures the **Swarm** with the provided Identity and Physics.
    /// 3. Establishes the **Sensor Channels** (Video/Audio) for hardware ingestion.
    pub fn new(
        config: PhalanxConfig,
        identity: PhalanxIdentity,
        physics: PhalanxPhysics,
        psk: Option<PreSharedKey>,
    ) -> Result<Self, Box<dyn Error>> {
        let network_keypair = identity.to_libp2p_keypair();

        let local_peer_id = network_keypair.public().to_peer_id();
        let local_did = Did::from(local_peer_id.to_string());

        // The Guardian protects the disk. It must be initialized before the network
        // to ensure we have a place to dump incoming data.
        let guardian = Guardian::new(&config.storage.vault_path, &config, local_did);

        // The Swarm connects us to the world.
        let swarm =
            crate::transport::swarm::setup_phalanx_swarm(network_keypair, &config, &physics, psk)?;

        let (_video_tx, video_rx) = mpsc::channel(config.storage.max_video_buffer);
        let (_audio_tx, audio_rx) = mpsc::channel(config.storage.max_audio_buffer);

        Ok(Self {
            config,
            identity,
            swarm,
            crucible: crate::storage::crucible::Crucible::new(),
            guardian,
            video_rx,
            audio_rx,
        })
    }

    /// FFI Helper: Boots the engine with minimal arguments for Mobile integration.
    ///
    /// Behavior: This is the primary entry point for Android/iOS bindings where
    /// passing complex Rust structs is difficult. It:
    /// 1. Sets the Storage Root to `storage_path`.
    /// 2. Loads (or generates) the default Identity from disk.
    /// 3. Applies the `default_wan()` physics profile (high latency tolerance).
    pub fn new_at_path(storage_path: &str) -> Result<Self, Box<dyn Error>> {
        let mut config = PhalanxConfig::default();
        config.storage.vault_path = storage_path.to_string();

        let identity = crate::init_identity();
        let physics = PhalanxPhysics::default_wan();

        Self::new(config, identity, physics, None)
    }

    /// The Main Event Loop.
    ///
    /// This runs indefinitely, multiplexing between:
    /// * **Network Events:** Inbound GossipSub messages, Peer connections.
    /// * **Sensor Events:** Incoming Video/Audio shards from the hardware.
    ///
    /// This loop is the heartbeat of the node. It drives the `Witness` logic
    /// by pulling raw shards, signing them, and pushing them to the Guardian.
    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let local_peer_id = *self.swarm.local_peer_id();
        let local_network_id = NetworkId::from(local_peer_id);

        loop {
            tokio::select! {
                // Priority 1: Network I/O
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await?;
                }

                // Priority 2: Local Video Witnessing
                Some(shard) = self.video_rx.recv() => {
                    // 1. Wrap raw shard in Evidence Enum
                    let evidence = Evidence::Video(shard);
                    // 2. Sign and Seal into WitnessEnvelope using our Ghost Key
                    let envelope = WitnessEnvelope::new(evidence, &self.identity, local_network_id);
                    // 3. Persist to Disk (WAL) and prepare for distribution
                    self.finalize_reassembly(envelope).await?;
                }

                // Priority 3: Local Audio Witnessing
                Some(shard) = self.audio_rx.recv() => {
                    let evidence = Evidence::Audio(shard);
                    let envelope = WitnessEnvelope::new(evidence, &self.identity, local_network_id);
                    self.finalize_reassembly(envelope).await?;
                }
            }
        }
    }

    /// The "Commit" phase of the Witness Cycle.
    ///
    /// Takes a signed `WitnessEnvelope` and hands it to the Guardian for
    /// persistence. This ensures that even if the network is down or the
    /// app crashes, the evidence is safely stored in the local Write-Ahead Log (WAL).
    async fn finalize_reassembly(
        &mut self,
        envelope: WitnessEnvelope,
    ) -> Result<(), Box<dyn Error>> {
        // 1. Commit to Write-Ahead Log (WAL) and disk.
        // This is a synchronous blocking operation to guarantee data integrity
        // before we attempt any network operations.
        self.guardian.ingest_envelope(envelope)?;

        // Future: Forward to Crucible for aggregation into "Volleys" (Batched Shards)
        // self.crucible.process(...)

        Ok(())
    }

    /// Handles low-level Libp2p events.
    ///
    /// Currently a placeholder for future logic where we will process incoming
    /// GossipSub messages (Foreign Shards) and route them to the Crucible for
    /// salvage or reassembly.
    async fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<PhalanxEvent>,
    ) -> Result<(), Box<dyn Error>> {
        if let SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(_gossip_event)) = event {
            // TODO: Route foreign shards to Guardian::ingest_chunk() for Salvage.
        }

        Ok(())
    }
}
