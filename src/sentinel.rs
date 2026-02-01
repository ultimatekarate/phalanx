use libp2p::{gossipsub, PeerId, Swarm, swarm::SwarmEvent};
use std::time::{Duration, Instant};
use std::collections::{HashMap, VecDeque};
use serde::{Serialize, Deserialize};

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
}

/// Packets sent over the simulated mesh
#[derive(Clone)]
pub enum SimPacket {
    Chunk(ShardChunk),
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
    pub fn ingest_chunk(&mut self, source: PeerId, chunk: ShardChunk) -> Option<WitnessEnvelope> {
        self.chunk_owners.insert(chunk.shard_id, source);

        let buffer = self.chunk_reassembly
            .entry(chunk.shard_id)
            .or_insert_with(|| ReassemblyBuffer::new(chunk.total_chunks as usize));

        if (chunk.chunk_index as usize) < buffer.chunks.len() {
            buffer.chunks[chunk.chunk_index as usize] = Some(chunk.data);
        }

        // Check for completion
        if buffer.is_complete() {
            let completed_buffer = self.chunk_reassembly.remove(&chunk.shard_id).unwrap();
            self.chunk_owners.remove(&chunk.shard_id);
            
            // Use the same assembly logic but without padding (since it's full)
            let full_data: Vec<u8> = completed_buffer.chunks
                .into_iter()
                .flatten() // removes option
                .flatten()// flatten the inner vec
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
    pub fn process_cleanup(&mut self, local_id: PeerId) -> Vec<(PeerId, VecDeque<WitnessEnvelope>)> {
        let now = Instant::now();
        let mut to_archive = Vec::new();

        let stale_peers: Vec<PeerId> = self.peer_heartbeats
            .iter()
            .filter(|(&id, &last)| id != local_id && now.duration_since(last) > self.pulse_timeout)
            .map(|(&id, _)| id)
            .collect();

        for id in stale_peers {
            println!("ALERT: Witness {} has gone dark. Initiating salvage.", id);
            let shards_to_clear: Vec<u32> = self.chunk_owners
                .iter()
                .filter(|(_, &owner)| owner == id)
                .map(|(&sid, _)| sid)
                .collect();

            for sid in shards_to_clear {
                if let Some(partial_chunks) = self.chunk_reassembly.remove(&sid) {
                    self.chunk_owners.remove(&sid);
                    if let Some(salvaged) = partial_chunks.try_salvage() {
                        tracing::info!(shard_id = %sid, "Salvaged partial data from dark peer {}", id);

                        let mut salvage_queue = std::collections::VecDeque::new();
                        salvage_queue.push_back(salvaged);
                        to_archive.push((id, salvage_queue));
                    } else {
                        tracing::debug!(shard_id = %sid, "Partial shard for {} was too fragmented to salvage", id);
                    }
                    
                    
                }
            }
        
            if let Some(shards) = self.guardian_buffers.remove(&id) {
                to_archive.push((id, shards));
            }

        // 4. Final state cleanup
            self.peer_heartbeats.remove(&id);
            self.peer_capacities.remove(&id);
            self.audio_buffers.remove(&id);
        }
        to_archive
    }
}