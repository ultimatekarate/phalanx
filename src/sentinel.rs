use libp2p::{gossipsub, mdns, PeerId, Swarm, swarm::SwarmEvent};
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use serde::{Serialize, Deserialize};
use tokio::time::Instant;
use tracing::{info, warn, instrument};

use crate::shards::{ReassemblyBuffer, ShardChunk, WitnessEnvelope};
use crate::audio;
use crate::{PhalanxBehaviour, PhalanxEvent};
use crate::config::PhalanxConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlMessage {
    pub sender: String,
    pub load_factor: f32,
    pub is_on_battery: bool,
    pub storage_remaining_mb: u64,
}

/// Specialized manager for peer vitality and capacity tracking
pub struct HealthTracker {
    pub heartbeats: HashMap<PeerId, Instant>,
    pub capacities: HashMap<PeerId, ControlMessage>,
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

    pub fn register_activity(&mut self, id: PeerId) {
        self.heartbeats.insert(id, Instant::now());
    }

    pub fn register_heartbeat(&mut self, id: PeerId, msg: ControlMessage) {
        self.heartbeats.insert(id, Instant::now());
        self.capacities.insert(id, msg);
    }

    pub fn register_new_peer(&mut self, id: PeerId) {
        // New peers get a grace period before they are considered stale
        self.heartbeats.insert(id, Instant::now() + self.grace_period);
    }

    pub fn get_stale_peers(&self, local_id: &PeerId) -> Vec<PeerId> {
        let now = Instant::now();
        self.heartbeats
            .iter()
            .filter_map(|(&id, &last_active)| {
                if id == *local_id { return None; }
                if now > last_active && now.duration_since(last_active) > self.pulse_timeout {
                    Some(id)
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Specialized manager for shard reassembly and identity mapping
pub struct ReassemblyManager {
    pub buffers: HashMap<u32, ReassemblyBuffer>,
    pub owners: HashMap<u32, PeerId>,
    pub shard_to_did: HashMap<u32, String>,
}

impl ReassemblyManager {
    pub fn new() -> Self {
        Self {
            buffers: HashMap::new(),
            owners: HashMap::new(),
            shard_to_did: HashMap::new(),
        }
    }

    pub fn add_chunk(&mut self, source: PeerId, chunk: ShardChunk) -> Option<WitnessEnvelope> {
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
    pub guardian_buffers: HashMap<PeerId, VecDeque<WitnessEnvelope>>,
    pub audio_buffers: HashMap<PeerId, VecDeque<audio::AudioShard>>,

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

    pub fn generate_heartbeat(&self, local_id: &PeerId) -> ControlMessage {
        let current_load = self.guardian_buffers.len() as f32;
        let capacity = self.max_peers as f32;

        ControlMessage {
            sender: local_id.to_string(),
            load_factor: (current_load / capacity).min(1.0),
            is_on_battery: false,
            storage_remaining_mb: 1024,
        }
    }

    pub fn ingest_chunk(&mut self, source: PeerId, chunk: ShardChunk) -> Option<WitnessEnvelope> {
        self.reassembly.add_chunk(source, chunk)
    }

    pub fn register_sim_heartbeat(&mut self, source: PeerId, message: ControlMessage) {
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
                        self.health.register_new_peer(peer_id);
                    }
                }
            }
            SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message, .. })) => {
                self.health.register_activity(propagation_source);
                
                if message.topic == self.topics.video.hash() {
                    if let Ok(chunk) = postcard::from_bytes::<ShardChunk>(&message.data) {
                        return self.ingest_chunk(propagation_source, chunk);
                    }
                } 
                else if message.topic == self.topics.control.hash() {
                    if let Ok(ctrl) = postcard::from_bytes::<ControlMessage>(&message.data) {
                        self.health.register_heartbeat(propagation_source, ctrl);
                    }
                } 
                else if message.topic == self.topics.audio.hash() {
                    if let Ok(a_shard) = postcard::from_bytes::<audio::AudioShard>(&message.data) {
                        let buffer = self.audio_buffers.entry(propagation_source).or_insert_with(VecDeque::new);
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
    pub fn process_cleanup(&mut self, local_id: PeerId) -> Vec<(PeerId, VecDeque<WitnessEnvelope>)> {
        let mut to_archive = Vec::new();
        let stale_peers = self.health.get_stale_peers(&local_id);

        for id in stale_peers {
            info!(peer = %id, "Dark peer detected; initiating salvage");

            // 1. Identify all orphaned shards owned by the dark peer
            let shards_to_clear: Vec<u32> = self.reassembly.owners
                .iter()
                .filter(|(_, &owner)| owner == id)
                .map(|(&sid, _)| sid)
                .collect();

            for sid in shards_to_clear {
                if let Some(buffer) = self.reassembly.buffers.remove(&sid) {
                    self.reassembly.owners.remove(&sid);
                    let fallback_did = self.reassembly.shard_to_did.remove(&sid).unwrap_or_default();
                    
                    if let Some(mut salvaged) = buffer.try_salvage() {
                        if salvaged.did.is_empty() {
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
            self.health.heartbeats.remove(&id);
            self.health.capacities.remove(&id);
            self.audio_buffers.remove(&id);
        }

        to_archive
    }
}

#[derive(Clone, Debug)]
pub enum SimPacket {
    /// Mimics a Video Topic message: (Sender's PeerId, The Shard Fragment)
    Chunk(PeerId, ShardChunk),
    
    /// Mimics a Control Topic message: (Sender's PeerId, Serialized ControlMessage)
    Heartbeat(PeerId, Vec<u8>), 
    
    /// Signal to gracefully shut down the virtual node task
    Shutdown,
}