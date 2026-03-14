use crate::identity::NetworkId;
use crate::identity::RecordingId;
use crate::prelude::ShardChunk;
use crate::types::{ByteCapacity, UnitInterval, VitalityRate};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum ChaosMode {
    Stable,
    PacketLoss(f32),
    HighLatency(u64),
    Byzantine,
    Hyperactive,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum DiscoverySource {
    Bootstrap,
    Kademlia,
    Mdns,
    Identify,
    Quic,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SimEvent {
    ChunkIngested {
        origin: NetworkId,
        chunk: ShardChunk,
    },
    Heartbeat {
        origin: NetworkId,
        uptime: u64,
        health: VitalityRate,
    },
    OffloadComplete {
        origin: NetworkId,
        target: NetworkId,
        size: ByteCapacity,
    },
    PeerDiscovered {
        peer: NetworkId,
        source: DiscoverySource,
        role: crate::identity::NodeRole,
    }, // Note: Role included for dashboard telemetry
    ShardProcessed {
        peer_id: NetworkId,
        byte_size: ByteCapacity,
    },
    CrucibleFinalized {
        recording_id: RecordingId,
    },
    AttackAttemptBlocked {
        attacker: NetworkId,
        target: NetworkId,
        reason: String,
    },
    SystemStressUpdate(UnitInterval),
    Shutdown,
    ChaosUpdate {
        target: NetworkId,
        mode: ChaosMode,
    },
    ShardPublished {
        origin: NetworkId,
        chunk: ShardChunk,
    },
}
