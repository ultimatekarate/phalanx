use libp2p::{gossipsub, PeerId, Swarm, swarm::SwarmEvent};
use std::time::{Duration};
use std::collections::{HashMap, VecDeque};
use serde::{Serialize, Deserialize};


use tokio::time::Instant;

use tracing::{info, debug, warn, instrument};
use crate::shards::{ReassemblyBuffer, ShardChunk, WitnessEnvelope};
use crate::audio;
use crate::{PhalanxBehaviour, PhalanxEvent};
use crate::config::PhalanxConfig;

use libp2p::mdns;
use std::error::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlMessage {
    pub sender: String,
    pub load_factor: f32,
    pub is_on_battery: bool,
    pub storage_remaining_mb: u64,
}

pub struct HealthTracker {
    pub heartbeats: HashMap<PeerId, Instant>,
    pub capacities: HashMap<PeerId, ControlMessage>,
    pub pulse_timeout_secs: u64,
}

impl HealthTracker {
    pub fn new(pulse_timeout_secs: u64) -> Self {
        Self {
            heartbeats: HashMap::new(),
            capacities: HashMap::new(),
            pulse_timeout_secs,
        }
    }

    pub fn register_heartbeat(&mut self, id: PeerId, msg: ControlMessage) {
        self.heartbeats.insert(id, Instant::now());
        self.capacities.insert(id, msg);
    }
}

pub struct ReassemblyManager {
    pub buffers: HashMap<u32, ReassemblyBuffer>,
    pub owners: HashMap<u32, PeerId>,
}

impl ReassemblyManager {
    pub fn new() -> Self {
        Self {
            buffers: HashMap::new(),
            owners: HashMap::new(),
        }
    }
}


pub struct Sentinel {
    // Topic Management
    pub video_topic: gossipsub::IdentTopic,
    pub audio_topic: gossipsub::IdentTopic,
    pub control_topic: gossipsub::IdentTopic,

    // Mesh Health & Witnessing
    pub peer_heartbeats: HashMap<PeerId, Instant>,
    pub peer_capacities: HashMap<PeerId, ControlMessage>,
    pub guardian_buffers: HashMap<PeerId, VecDeque<WitnessEnvelope>>,
    pub audio_buffers: HashMap<PeerId, VecDeque<audio::AudioShard>>,
    
    // Reassembly State
    pub chunk_reassembly: HashMap<u32, ReassemblyBuffer>,
    pub chunk_owners: HashMap<u32, PeerId>,

    // Constraints
    pub pulse_timeout: Duration,
    pub max_peers: usize,
    pub grace_period: Duration,
    pub max_video_buffer: usize,
    pub max_audio_buffer: usize,

    pub shard_to_did: HashMap<u32, String>,
}

/// Packets sent over the simulated mesh
#[derive(Clone)]
pub enum SimPacket {
    Chunk(PeerId, ShardChunk),
    Heartbeat(PeerId, Vec<u8>), // Serialized ControlMessage
    Shutdown,
}


impl Sentinel {
    pub fn new(config: &PhalanxConfig) -> Self {
        Self {
            video_topic: gossipsub::IdentTopic::new(&config.network.video_topic),
            audio_topic: gossipsub::IdentTopic::new(&config.network.audio_topic),
            control_topic: gossipsub::IdentTopic::new(&config.network.control_topic),
            peer_heartbeats: HashMap::new(),
            peer_capacities: HashMap::new(),
            chunk_owners: HashMap::new(),
            guardian_buffers: HashMap::new(),
            audio_buffers: HashMap::new(),
            chunk_reassembly: HashMap::new(),
            pulse_timeout: Duration::from_secs(config.network.pulse_timeout_secs),
            max_peers: config.storage.max_peers,
            grace_period: Duration::from_secs(config.network.grace_period),
            max_video_buffer: config.storage.max_video_buffer,
            max_audio_buffer: config.storage.max_audio_buffer,
            shard_to_did: HashMap::new(),
        }
    }

    /// Registers managed topics with the libp2p Swarm
    pub fn subscribe_all(&self, swarm: &mut Swarm<PhalanxBehaviour>) -> Result<(), Box<dyn Error>> {
        swarm.behaviour_mut().gossipsub.subscribe(&self.video_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&self.audio_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&self.control_topic)?;
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

    /// Centralized Reassembly Logic
    #[instrument(level = "info", skip(self, chunk), fields(shard_id = %chunk.shard_id))]
    pub fn ingest_chunk(&mut self, source: PeerId, chunk: ShardChunk) -> Option<WitnessEnvelope> {
        debug!(index = %chunk.chunk_index, total = %chunk.total_chunks, "Processing chunk");
        
        // Anchor the shard ID to the DID immediately
        self.chunk_owners.insert(chunk.shard_id, source);
        self.shard_to_did.insert(chunk.shard_id, chunk.owner_did.clone()); 

        let buffer = self.chunk_reassembly
            .entry(chunk.shard_id)
            .or_insert_with(|| ReassemblyBuffer::new(chunk.total_chunks as usize));

        if (chunk.chunk_index as usize) < buffer.chunks.len() {
            buffer.chunks[chunk.chunk_index as usize] = Some(chunk.data);
        }

        // 2. Check for completion
        if buffer.is_complete() {
            let completed_buffer = self.chunk_reassembly.remove(&chunk.shard_id).unwrap();
            self.chunk_owners.remove(&chunk.shard_id);
            self.shard_to_did.remove(&chunk.shard_id); // Cleanup mapping
            
            let full_data: Vec<u8> = completed_buffer.chunks
                .into_iter()
                .flatten()
                .flatten()
                .collect();
                
            return postcard::from_bytes::<WitnessEnvelope>(&full_data).ok();
        }
        None
    }

    pub fn register_sim_heartbeat(&mut self, source: PeerId, message: ControlMessage) {
        let now = Instant::now();
        self.peer_heartbeats.insert(source, now);
        self.peer_capacities.insert(source, message);
    }

    #[instrument(
        level = "debug", 
        skip(self, swarm, event), 
        fields(peer_id)
    )]
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
                        self.peer_heartbeats.insert(peer_id, Instant::now() + self.grace_period);
                    }
                }
            }
            SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message, .. })) => {
                
                tracing::Span::current().record("peer_id", propagation_source.to_string());
                debug!(topic = %message.topic, "Incoming mesh message");
                
                // Update heartbeat for any message received
                self.peer_heartbeats.insert(propagation_source, Instant::now());
                
                // 1. Handle Video (The primary ingestion path)
                if message.topic == self.video_topic.hash() {
                    if let Ok(chunk) = postcard::from_bytes::<ShardChunk>(&message.data) {
                        return self.ingest_chunk(propagation_source, chunk);
                    }
                } 
                // 2. Handle Control Messages
                else if message.topic == self.control_topic.hash() {
                    if let Ok(ctrl) = postcard::from_bytes::<ControlMessage>(&message.data) {
                        self.peer_capacities.insert(propagation_source, ctrl);
                    }
                } 
                // 3. Handle Audio
                else if message.topic == self.audio_topic.hash() {
                    if let Ok(a_shard) = postcard::from_bytes::<audio::AudioShard>(&message.data) {
                        let buffer = self.audio_buffers.entry(propagation_source).or_insert_with(VecDeque::new);
                        buffer.push_back(a_shard);
                        if buffer.len() > self.max_audio_buffer { buffer.pop_front(); }
                    }
                }
            }
            _ => {}
        }
        None // No WitnessEnvelope completed in this event
    }

    /// Identifies peers that have gone dark. 
    /// Returns a list of (PeerId, Shards) to be archived by Stronghold.
    #[instrument(level = "info", skip(self, local_id), fields(node_id = %local_id))]
    pub fn process_cleanup(&mut self, local_id: PeerId) -> Vec<(PeerId, VecDeque<WitnessEnvelope>)> {
        let now = Instant::now();
        let mut to_archive = Vec::new();
        
        debug!(
            heartbeat_count = self.peer_heartbeats.len(),
            "Starting cleanup tick"
        );

        let stale_peers: Vec<PeerId> = self.peer_heartbeats
            .iter()
            .filter_map(|(&id, &last_active)| {
                if id == local_id { return None; }
                
                let age = now.duration_since(last_active);
                if age > self.pulse_timeout {
                    info!(peer = %id, age = ?age, timeout = ?self.pulse_timeout, "Peer identified as STALE");
                    Some(id)
                } else {
                    // Useful for confirming the clock is actually moving in simulation
                    debug!(peer = %id, age = ?age, "Peer is still active");
                    None
                }
            })
            .collect();

        for id in stale_peers {
            let salvage_count = 0;
            let failure_count = 0;

            let shards_to_clear: Vec<u32> = self.chunk_owners
                .iter()
                .filter(|(_, &owner)| owner == id)
                .map(|(&sid, _)| sid)
                .collect();

            info!(
                peer = %id, 
                shards_found = shards_to_clear.len(), 
                "Initiating salvage for dark peer"
            );

            for sid in shards_to_clear {
                if let Some(partial_chunks) = self.chunk_reassembly.remove(&sid) {
                    let fallback_did = self.shard_to_did.remove(&sid).unwrap_or_default();
                    
                    if let Some(mut salvaged) = partial_chunks.try_salvage() {

                        if salvaged.did.is_empty() {
                            salvaged.did = fallback_did;
                        }

                        info!(peer = %id, shard_id = %sid, did = %salvaged.did, "SUCCESS: Salvaged with Identity");
                        
                        let mut salvage_queue = VecDeque::new();
                        salvage_queue.push_back(salvaged);
                        to_archive.push((id, salvage_queue));
                    }
                    
                }
            }
        
            if let Some(envelopes) = self.guardian_buffers.remove(&id) {
                info!(peer = %id, count = envelopes.len(), "Moving guardian buffers to archival");
                to_archive.push((id, envelopes));
            }

        // 4. Final state cleanup
            self.peer_heartbeats.remove(&id);
            self.peer_capacities.remove(&id);
            self.audio_buffers.remove(&id);

            info!(
                peer = %id, 
                salvaged = salvage_count, 
                failed = failure_count, 
                "Cleanup complete for peer"
            );
        }

        if !to_archive.is_empty() {
            info!(total_salvaged = to_archive.len(), "Cleanup tick returning salvaged data to harness");
        }
        
        to_archive
    }
}