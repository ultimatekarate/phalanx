use libp2p::{gossipsub, mdns, Swarm, swarm::SwarmEvent};
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use serde::{Serialize, Deserialize};
use tokio::time::Instant;
use tracing::{info, warn, debug, instrument};

use crate::shards::{ReassemblyBuffer, ShardChunk, ShardId, WitnessEnvelope};
use crate::audio;
use crate::{PhalanxBehaviour, PhalanxEvent};
use crate::config::PhalanxConfig;
use crate::identity::{NetworkId, Did};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlMessage {
    pub sender: NetworkId,
    pub load_factor: f32,
    pub is_on_battery: bool,
    pub storage_remaining_mb: u64,
}

/// Specialized manager for peer vitality and capacity tracking
pub struct HealthTracker {
    pub heartbeats: HashMap<NetworkId, Instant>,
    pub capacities: HashMap<NetworkId, ControlMessage>,
    pub pulse_timeout: std::time::Duration,
    pub grace_period: std::time::Duration,
}

impl HealthTracker {
    pub fn new(config: &PhalanxConfig) -> Self {
        Self {
            heartbeats: HashMap::new(),
            capacities: HashMap::new(),
            pulse_timeout: std::time::Duration::from_secs(config.network.pulse_timeout_secs),
            grace_period: std::time::Duration::from_secs(config.network.grace_period),
        }
    }

    pub fn register_activity(&mut self, id: NetworkId) {
        self.heartbeats.insert(id, Instant::now());
    }

    pub fn register_heartbeat(&mut self, id: NetworkId, msg: ControlMessage) {
        self.heartbeats.insert(id, Instant::now());
        self.capacities.insert(id, msg);
    }

    pub fn register_new_peer(&mut self, id: NetworkId) {
        let expiry = Instant::now() + self.grace_period;
        info!(peer = %id, grace_expiry = ?expiry, "Registering peer with forensic grace period");
        self.heartbeats.insert(id, expiry);
    }

    pub fn get_stale_peers(&self, local_id: &NetworkId) -> Vec<NetworkId> {
        let now = Instant::now();
        self.heartbeats
            .iter()
            .filter_map(|(&id, &last_active)| {
                if id == *local_id { return None; }

                // Protect against heartbeats in the future due to initialization
                if last_active > now {
                    let grace_remaining = last_active.duration_since(now);
                    debug!(
                        peer = %id, 
                        status = "PROTECTED", 
                        grace_remaining = ?grace_remaining,
                        "Peer is currently in its grace period"
                    );
                    return None;
                }
                let age = now.duration_since(last_active);
                if age > self.pulse_timeout {
                    info!(
                        peer = %id, 
                        status = "STALE", 
                        age = ?age, 
                        timeout = ?self.pulse_timeout,
                        "Peer exceeded pulse timeout"
                    );
                    Some(id)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn remove_peer(&mut self, id: &NetworkId) {
        self.heartbeats.remove(id);
        self.capacities.remove(id);
    }
}

/// Specialized manager for shard reassembly and identity mapping
pub struct ReassemblyManager {
    pub buffers: HashMap<ShardId, ReassemblyBuffer>,
    pub owners: HashMap<ShardId, NetworkId>,
    pub shard_to_did: HashMap<ShardId, Did>,
}

impl Default for ReassemblyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ReassemblyManager {
    pub fn new() -> Self {
        Self {
            buffers: HashMap::new(),
            owners: HashMap::new(),
            shard_to_did: HashMap::new(),
        }
    }

    pub fn add_chunk(&mut self, source: NetworkId, chunk: ShardChunk) -> Option<WitnessEnvelope> {
        // Track the identity link for forensic salvage
        self.owners.insert(chunk.shard_id, source);
        self.shard_to_did.insert(chunk.shard_id, chunk.owner_did.clone());

        let buffer = self.buffers
            .entry(chunk.shard_id)
            .or_insert_with(|| ReassemblyBuffer::new(chunk.total_chunks as usize));

        if (chunk.chunk_index as usize) < buffer.chunks.len() {
            buffer.chunks[chunk.chunk_index as usize] = Some(chunk.data);
        }

        if buffer.is_complete() {
            let sid = chunk.shard_id;
            let completed_buffer = self.buffers.remove(&sid).unwrap();
            self.owners.remove(&sid);
            self.shard_to_did.remove(&sid);
            
            let full_data: Vec<u8> = completed_buffer.chunks
                .into_iter()
                .flatten()
                .flatten()
                .collect();
                
            return postcard::from_bytes::<WitnessEnvelope>(&full_data).ok();
        }
        None
    }
}

pub struct Sentinel {
    pub topics: NetworkTopics,
    pub health: HealthTracker,
    pub reassembly: ReassemblyManager,

    // Managed Queues
    pub guardian_buffers: HashMap<NetworkId, VecDeque<WitnessEnvelope>>,
    pub audio_buffers: HashMap<NetworkId, VecDeque<audio::AudioShard>>,

    // Constraints from Config
    pub max_peers: usize,
    pub max_audio_buffer: usize,
}

pub struct NetworkTopics {
    pub video: gossipsub::IdentTopic,
    pub audio: gossipsub::IdentTopic,
    pub control: gossipsub::IdentTopic,
}

impl Sentinel {
    pub fn new(config: &PhalanxConfig) -> Self {
        Self {
            topics: NetworkTopics {
                video: gossipsub::IdentTopic::new(&config.network.video_topic),
                audio: gossipsub::IdentTopic::new(&config.network.audio_topic),
                control: gossipsub::IdentTopic::new(&config.network.control_topic),
            },
            health: HealthTracker::new(config),
            reassembly: ReassemblyManager::new(),
            guardian_buffers: HashMap::new(),
            audio_buffers: HashMap::new(),
            max_peers: config.storage.max_peers,
            max_audio_buffer: config.storage.max_audio_buffer,
        }
    }

    pub fn subscribe_all(&self, swarm: &mut Swarm<PhalanxBehaviour>) -> Result<(), Box<dyn Error>> {
        swarm.behaviour_mut().gossipsub.subscribe(&self.topics.video)?;
        swarm.behaviour_mut().gossipsub.subscribe(&self.topics.audio)?;
        swarm.behaviour_mut().gossipsub.subscribe(&self.topics.control)?;
        Ok(())
    }

    pub fn generate_heartbeat(&self, local_id: &NetworkId) -> ControlMessage {
        let current_load = self.guardian_buffers.len() as f32;
        let capacity = self.max_peers as f32;

        ControlMessage {
            sender: *local_id,
            load_factor: (current_load / capacity).min(1.0),
            is_on_battery: false,
            storage_remaining_mb: 1024,
        }
    }

    pub fn ingest_chunk(&mut self, source: NetworkId, chunk: ShardChunk) -> Option<WitnessEnvelope> {
        self.reassembly.add_chunk(source, chunk)
    }

    pub fn register_sim_heartbeat(&mut self, source: NetworkId, message: ControlMessage) {
        self.health.register_heartbeat(source, message);
    }

    pub fn handle_network_event(
        &mut self,
        event: SwarmEvent<PhalanxEvent>,
        swarm: &mut Swarm<PhalanxBehaviour>,
    ) -> Option<WitnessEnvelope> {
        match event {
            SwarmEvent::Behaviour(PhalanxEvent::Mdns(mdns::Event::Discovered(list))) => {
                for (peer_id, multiaddr) in list {
                    if peer_id != *swarm.local_peer_id() {
                        let _ = swarm.dial(multiaddr.clone());
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        self.health.register_new_peer(NetworkId(peer_id));
                    }
                }
            }

            // Match against our custom PhalanxGossipEvent struct
            SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(boxed_event)) => {
                let event = *boxed_event; // Unbox
                
                self.health.register_activity(event.source);
                
                if event.message.topic == self.topics.video.hash() {
                    if let Ok(chunk) = postcard::from_bytes::<ShardChunk>(&event.message.data) {
                        // source is already NetworkId
                        return self.ingest_chunk(event.source, chunk);
                    }
                } 
                else if event.message.topic == self.topics.control.hash() {
                    if let Ok(ctrl) = postcard::from_bytes::<ControlMessage>(&event.message.data) {
                        self.health.register_heartbeat(event.source, ctrl);
                    }
                } 
                else if event.message.topic == self.topics.audio.hash() {
                    if let Ok(a_shard) = postcard::from_bytes::<audio::AudioShard>(&event.message.data) {
                        let buffer = self.audio_buffers.entry(event.source).or_default();
                        buffer.push_back(a_shard);
                        if buffer.len() > self.max_audio_buffer { buffer.pop_front(); }
                    }
                }
            }
            _ => {}
        }
        None
    }


    #[instrument(level = "info", skip(self, local_id), fields(node_id = %local_id))]
    pub fn process_cleanup(&mut self, local_id: NetworkId) -> Vec<(NetworkId, VecDeque<WitnessEnvelope>)> {
        let mut to_archive = Vec::new();
        let stale_peers = self.health.get_stale_peers(&local_id);

        for id in stale_peers {
            info!(peer = %id, "Dark peer detected; initiating salvage");

            // 1. Identify all orphaned shards owned by the dark peer
            let shards_to_clear: Vec<ShardId> = self.reassembly.owners
                .iter()
                .filter(|(_, &owner)| owner == id)
                .map(|(&sid, _)| sid)
                .collect();

            for sid in shards_to_clear {
                if let Some(buffer) = self.reassembly.buffers.remove(&sid) {
                    self.reassembly.owners.remove(&sid);
                    let fallback_did = self.reassembly.shard_to_did.remove(&sid).unwrap_or_default();
                    
                    if let Some(mut salvaged) = buffer.try_salvage() {
                        if salvaged.did.0.is_empty() {
                            salvaged.did = fallback_did;
                        }
                        
                        info!(shard_id = %sid, did = %salvaged.did, "SUCCESS: Salvaged partial shard");
                        let mut queue = VecDeque::new();
                        queue.push_back(salvaged);
                        to_archive.push((id, queue));
                    }
                }
            }

            // 2. Flush supplementary witness buffers
            if let Some(envelopes) = self.guardian_buffers.remove(&id) {
                to_archive.push((id, envelopes));
            }

            // 3. Purge network state
            self.health.remove_peer(&id);
            self.audio_buffers.remove(&id);
        }

        to_archive
    }
}

#[derive(Clone, Debug)]
pub enum SimPacket {
    /// Mimics a Video Topic message: (Sender's NetworkId, The Shard Fragment)
    Chunk(NetworkId, ShardChunk),
    
    /// Mimics a Control Topic message: (Sender's NetworkId, Serialized ControlMessage)
    Heartbeat(NetworkId, Vec<u8>), 
    
    /// Signal to gracefully shut down the virtual node task
    Shutdown,
}

#[cfg(test)]
mod health_tracker_tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::{advance};

    /// Helper to create a default test config
    fn create_test_config() -> PhalanxConfig {
        PhalanxConfig::test_defaults() // pulse_timeout=2s, grace_period=10s
    }

    #[tokio::test(start_paused = true)]
    async fn test_peer_staleness_detection() {
        let config = create_test_config();
        let mut tracker = HealthTracker::new(&config);
        let local_id = NetworkId::random();
        let remote_id = NetworkId::random();

        // 1. Register activity for a remote peer
        tracker.register_activity(remote_id);

        // 2. Advance time but stay within the pulse_timeout (2s)
        advance(Duration::from_secs(1)).await;
        let stale_peers = tracker.get_stale_peers(&local_id);
        assert!(stale_peers.is_empty(), "Peer should not be stale after only 1 second");

        // 3. Advance time past the pulse_timeout
        advance(Duration::from_secs(2)).await;
        let stale_peers = tracker.get_stale_peers(&local_id);
        
        assert_eq!(stale_peers.len(), 1, "Peer should be marked as stale after timeout");
        assert_eq!(stale_peers[0], remote_id);
    }

    #[tokio::test(start_paused = true)]
    async fn test_grace_period_protection() {
        // 1. Force the subscriber to show Phalanx logs
        let _ = tracing_subscriber::fmt()
            .with_env_filter("phalanx=debug")
            .try_init();

        let config = PhalanxConfig::test_defaults(); // 2s pulse, 10s grace
        let mut tracker = HealthTracker::new(&config);
        let local_id = NetworkId::random();
        let remote_id = NetworkId::random();

        info!("STEP 1: Registering peer with 10s grace. Now={:?}", tokio::time::Instant::now());
        tracker.register_new_peer(remote_id);

        // Verify initial state
        let initial_heartbeat = tracker.heartbeats.get(&remote_id).unwrap();
        info!("Peer Heartbeat set to: {:?}", initial_heartbeat);

        // 2. Advance 5s (Halfway through grace)
        tokio::time::advance(Duration::from_secs(5)).await;
        info!("STEP 2: Advanced 5s. Now={:?}", tokio::time::Instant::now());

        let stale_peers = tracker.get_stale_peers(&local_id);
        
        // This should be 0 because T+5 < T+10
        assert!(
            stale_peers.is_empty(), 
            "FAILURE: Peer was stale during grace. Check HealthTracker future-check logic."
        );

        // 3. Advance past grace
        tokio::time::advance(Duration::from_secs(10)).await;
        info!("STEP 3: Advanced another 10s (T+15). Now={:?}", tokio::time::Instant::now());

        let stale_peers = tracker.get_stale_peers(&local_id);
        assert!(
            !stale_peers.is_empty(), 
            "FAILURE: Peer should be stale after 15s elapsed time."
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_heartbeat_resets_timer() {
        let config = create_test_config();
        let mut tracker = HealthTracker::new(&config);
        let local_id = NetworkId::random();
        let remote_id = NetworkId::random();

        tracker.register_activity(remote_id);

        // Advance 1s
        advance(Duration::from_secs(1)).await;

        // 1. Receive a heartbeat message
        let msg = ControlMessage {
            sender: remote_id,
            load_factor: 0.5,
            is_on_battery: false,
            storage_remaining_mb: 500,
        };
        tracker.register_heartbeat(remote_id, msg);

        // 2. Advance another 1.5s (Total 2.5s since start, but only 1.5s since heartbeat)
        advance(Duration::from_millis(1500)).await;
        
        let stale_peers = tracker.get_stale_peers(&local_id);
        assert!(stale_peers.is_empty(), "Heartbeat should have reset the staleness timer");
    }

    #[tokio::test(start_paused = true)]
    async fn test_local_id_exclusion() {
        let config = create_test_config();
        let mut tracker = HealthTracker::new(&config);
        let local_id = NetworkId::random();

        // Register local activity
        tracker.register_activity(local_id);

        // Advance time past timeout
        advance(Duration::from_secs(5)).await;

        // 1. The tracker should never return the local node as a stale peer
        let stale_peers = tracker.get_stale_peers(&local_id);
        assert!(stale_peers.is_empty(), "Tracker must exclude the local PeerId from stale lists");
    }

    #[test]
    fn test_capacity_storage() {
        let config = PhalanxConfig::test_defaults();
        let mut tracker = HealthTracker::new(&config);
        let remote_id = NetworkId::random();

        let msg = ControlMessage {
            sender: remote_id,
            load_factor: 0.75,
            is_on_battery: true,
            storage_remaining_mb: 100,
        };

        tracker.register_heartbeat(remote_id, msg.clone());

        // 1. Verify capacity data is correctly preserved
        let stored_cap = tracker.capacities.get(&remote_id).expect("Capacity record missing");
        assert_eq!(stored_cap.load_factor, 0.75);
        assert!(stored_cap.is_on_battery);
    }
}