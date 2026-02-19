// crates/phalanx-core/src/security/telemetry.rs

use std::sync::Once;
use tracing::Level;
use tracing_appender::rolling;
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

    // REFACTORED: Now carries structured health data instead of raw bytes
    Heartbeat {
        origin: NetworkId,
        uptime: u64,
        health: VitalityRate,
    },

    // REFACTORED: Supports Gossip (Guardian->Guardian) and Archive (Guardian->Stronghold)
    OffloadComplete {
        origin: NetworkId,
        target: NetworkId,
        size: ByteCapacity,
    },

    // --- Orchestration Layer Events ---
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

    // --- System Layer Events ---
    SystemStressUpdate(UnitInterval),
    Shutdown,

    /// A command to alter a node's operating mode.
    /// REFACTORED: Now targets a specific node ID.
    ChaosUpdate {
        target: NetworkId,
        mode: ChaosMode,
    },

    // NEW: Generic broadcast for Echo/Gossip simulation
    ShardPublished {
        origin: NetworkId,
        chunk: ShardChunk,
    },
}

/// Global telemetry bus for the Phalanx node.
pub struct TelemetryHub {
    _tx: broadcast::Sender<SimEvent>,
}

static INIT: Once = Once::new();

/// Initializes the telemetry system (Console + File).
/// Returns a `WorkerGuard` that MUST be held by main() to ensure logs flush on shutdown.
pub fn init_observability() -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let mut guard = None;

    INIT.call_once(|| {
        // 1. Setup File Logging (The Flight Recorder)
        // Rotates daily. Stores in "logs/guardian.log.YYYY-MM-DD"
        let file_appender = rolling::daily("logs", "guardian.log");
        let (non_blocking_file, file_guard) = tracing_appender::non_blocking(file_appender);

        // Save the guard so we can return it (crucial for flushing buffers on crash)
        guard = Some(file_guard);

        // 2. Define the Filters
        // "info" by default, but "debug" for our code (phalanx)
        let filter = Targets::new()
            .with_target("phalanx", Level::DEBUG)
            .with_target("phalanx_core", Level::DEBUG)
            .with_default(Level::INFO);

        // 3. Register Layers
        tracing_subscriber::registry()
            .with(filter)
            // Layer A: Console (Stdout) - For you watching the terminal
            .with(fmt::layer().with_target(false).with_thread_ids(true))
            // Layer B: File (JSON) - Machine readable for later analysis
            .with(
                fmt::layer()
                    .with_writer(non_blocking_file)
                    .json() // structured JSON logs are better for parsing later
                    .with_target(true),
            )
            .init();
    });

    guard
}
