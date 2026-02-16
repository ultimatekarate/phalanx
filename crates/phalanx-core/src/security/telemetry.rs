use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use tracing_appender::rolling;
use std::sync::Once;

use serde::{Serialize, Deserialize};

use tokio::sync::broadcast;
use crate::{base::types::{ByteCapacity, UnitInterval}, primitives::{identity::NetworkId, shards::{ShardChunk, VolleyId}}};


/// Discovery source attribution.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum DiscoverySource {
    Kademlia,
    Mdns,
    Identify,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SimEvent {
    // Hardware/Network Layer Events
    Chunk(NetworkId, ShardChunk),
    Heartbeat(NetworkId, Vec<u8>),
    
    // Orchestration Layer Events
    PeerDiscovered {
        peer: NetworkId,
        source: DiscoverySource,
    },

    ShardProcessed { 
        peer_id: NetworkId, 
        byte_size: ByteCapacity
    },
    CrucibleFinalized { 
        volley_id: VolleyId 
    },
    
    // System Layer Events
    SystemStressUpdate(UnitInterval),
    Shutdown,
}
/// Global telemetry bus for the Phalanx node.
pub struct TelemetryHub {
    tx: broadcast::Sender<SimEvent>,
}

static INIT: Once = Once::new();

/// Initializes the telemetry system (Console + File).
/// Returns a WorkerGuard that MUST be held by main() to ensure logs flush on shutdown.
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
        let env_filter = EnvFilter::from_default_env()
            .add_directive(tracing::Level::INFO.into())
            .add_directive("phalanx=debug".parse().unwrap());

        // 3. Register Layers
        tracing_subscriber::registry()
            .with(env_filter)
            // Layer A: Console (Stdout) - For you watching the terminal
            .with(fmt::layer()
                .with_target(false)
                .with_thread_ids(true))
            // Layer B: File (JSON) - Machine readable for later analysis
            .with(fmt::layer()
                .with_writer(non_blocking_file)
                .json() // structured JSON logs are better for parsing later
                .with_target(true))
            .init();
    });

    guard
}