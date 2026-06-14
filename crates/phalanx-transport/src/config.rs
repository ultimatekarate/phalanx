// crates/phalanx-transport/src/config.rs
//
// Domain-type transport configuration. Zero libp2p types — the factory
// converts these into the appropriate wire types internally.

use crate::adapters::libp2p::AdapterConfig;
use phalanx_proto::types::PhalanxPhysics;

/// Complete mesh transport configuration.
///
/// All network addresses and peer identifiers are plain strings.
/// The factory parses them into Multiaddr / PeerId internally.
pub struct MeshTransportConfig {
    // ── Network ──────────────────────────────────────────────
    pub listen_addresses: Vec<String>,
    pub bootstrap_peers: Vec<String>,
    pub subscribe_topics: Vec<String>,
    pub protocol_version: String,
    pub max_chunk_size_bytes: usize,
    pub physics: PhalanxPhysics,

    // ── Pre-Shared Key ───────────────────────────────────────
    /// Raw 32-byte PSK for private network transport encryption.
    pub psk: Option<[u8; 32]>,
    /// If true, the factory returns an error when `psk` is None.
    pub require_psk: bool,

    // ── Adapter ──────────────────────────────────────────────
    pub adapter: AdapterConfig,

    // ── Kademlia ─────────────────────────────────────────────
    pub kademlia_replication_factor: usize,
    pub kademlia_query_timeout_secs: u64,
    pub kademlia_record_ttl_secs: u64,
    /// Enable `StoreInserts::FilterBoth` for Kademlia record validation.
    pub kademlia_filter_both: bool,

    // ── Connection limits (E1/E5 hardening) ──────────────────
    pub max_established: u32,
    pub max_established_incoming: u32,
    pub max_established_per_peer: u32,
    pub idle_timeout_secs: u64,
}

impl Default for MeshTransportConfig {
    fn default() -> Self {
        Self {
            listen_addresses: vec![],
            bootstrap_peers: vec![],
            subscribe_topics: vec![],
            // Single source of truth: the same constant every node and
            // Stronghold projects from its DeploymentProfile. This feeds the
            // Kademlia StreamProtocol id (factory.rs) and the identify agent
            // string; peers on different versions form different DHTs, so a
            // divergent literal here is a silent partition.
            protocol_version: phalanx_proto::network::deployment::DEFAULT_PROTOCOL_VERSION
                .to_string(),
            // Sized to fit a 100-symbol bundle (100 × 1200 = 120 KB) plus
            // postcard framing overhead with margin. gossipsub max_transmit
            // is derived as 2× this (see builder.rs) → 256 KiB ceiling.
            max_chunk_size_bytes: phalanx_proto::network::deployment::DEFAULT_MAX_CHUNK_SIZE_BYTES,
            physics: PhalanxPhysics::default_wan(),
            psk: None,
            require_psk: false,
            adapter: AdapterConfig::default(),
            kademlia_replication_factor: 20,
            kademlia_query_timeout_secs: 30,
            kademlia_record_ttl_secs: 3600,
            kademlia_filter_both: true,
            max_established: 192,
            max_established_incoming: 128,
            max_established_per_peer: 4,
            idle_timeout_secs: 60,
        }
    }
}
