// crates/phalanx-transport/src/adapters/quic/config.rs
//
// Configuration structs for QUIC server (Stronghold) and client (Phone) modes.

use std::net::SocketAddr;

use phalanx_proto::identity::NetworkId;

/// Configuration for a QUIC server (Stronghold mode).
pub struct QuicServerConfig {
    /// Address to bind the QUIC server (e.g., "0.0.0.0:4433").
    pub bind_address: SocketAddr,
    /// Server TLS certificate chain in PEM format.
    pub cert_pem: Vec<u8>,
    /// Server TLS private key in PEM format.
    pub key_pem: Vec<u8>,
    /// Event channel capacity (default: 2048).
    pub event_channel_capacity: usize,
    /// Maximum concurrent client connections (default: 64). Connections beyond
    /// this limit are dropped immediately to prevent connection-flood DoS.
    pub max_connections: usize,
}

/// Configuration for a QUIC client (Phone mode).
pub struct QuicClientConfig {
    /// Stronghold server address to connect to.
    pub server_address: SocketAddr,
    /// Server name for TLS SNI verification (typically "localhost" or domain).
    pub server_name: String,
    /// CA certificate in PEM format for server TLS verification.
    pub ca_cert_pem: Vec<u8>,
    /// This client's forensic network identity.
    pub local_network_id: NetworkId,
    /// The server's forensic network identity (for event attribution).
    pub server_network_id: NetworkId,
    /// Event channel capacity (default: 2048).
    pub event_channel_capacity: usize,
    /// Maximum reconnection attempts before giving up. `None` = infinite.
    pub max_reconnect_attempts: Option<u32>,
    /// Base delay for exponential backoff (seconds). Default: 5.
    pub base_backoff_secs: u64,
    /// Maximum backoff delay cap (seconds). Default: 300 (5 minutes).
    pub max_backoff_secs: u64,
}
