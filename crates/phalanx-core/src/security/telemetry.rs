// crates/phalanx-core/src/security/telemetry.rs

use std::sync::{Once, OnceLock};
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::{fmt, prelude::*};

use serde::{Deserialize, Serialize};

use crate::{
    base::types::{ByteCapacity, UnitInterval, VitalityRate},
    primitives::{
        identity::NetworkId,
        shards::{ShardChunk, VolleyId},
    },
};
use tokio::sync::broadcast;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum NodeRole {
    Guardian,
    Stronghold,
}

/// The Menu of Disasters for the Chaos Engine.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum ChaosMode {
    /// Normal operation. Ideal network conditions.
    Stable,
    /// Simulates a flaky connection (e.g., weak Wi-Fi).
    /// Parameter: Probability (0.0 - 1.0) of dropping an outgoing packet.
    PacketLoss(f32),
    /// Simulates network congestion or distance.
    /// Parameter: Milliseconds of delay added to message processing.
    HighLatency(u64),
    /// Simulates a compromised or malfunctioning node.
    /// The node will send corrupted/garbage data.
    Byzantine,
    /// Simulates a "Vampire Attack" or resource exhaustion.
    /// The node generates traffic 50x faster than normal.
    Hyperactive,
}

/// Discovery source attribution.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum DiscoverySource {
    Bootstrap, // Changed from Kademlia/Mdns/Identify to generic Bootstrap for Sim
    Kademlia,
    Mdns,
    Identify,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SimEvent {
    // --- Hardware/Network Layer Events ---
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
        role: NodeRole,
        source: DiscoverySource,
    },

    ShardProcessed {
        peer_id: NetworkId,
        byte_size: ByteCapacity,
    },

    CrucibleFinalized {
        volley_id: VolleyId,
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

/// Global telemetry bus for the Phalanx node.
pub struct TelemetryHub {
    _tx: broadcast::Sender<SimEvent>,
}

static TELEMETRY_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();
static INIT: Once = Once::new();

pub fn init_observability() {
    INIT.call_once(|| {
        let file_appender = tracing_appender::rolling::daily("logs", "guardian.log");
        let (non_blocking_file, file_guard) = tracing_appender::non_blocking(file_appender);

        // Store guard globally to prevent dropping
        let _ = TELEMETRY_GUARD.set(file_guard);

        let filter = Targets::new()
            .with_target("phalanx", Level::DEBUG)
            .with_target("phalanx_core", Level::DEBUG)
            .with_default(Level::INFO);

        let registry = tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_target(false).with_thread_ids(true))
            .with(
                fmt::layer()
                    .with_writer(non_blocking_file)
                    .json()
                    .with_target(true),
            );

        // Use try_init to prevent panics in multi-threaded test environments
        let _ = registry.try_init();
    });
}
