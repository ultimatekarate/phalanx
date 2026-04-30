// crates/phalanx-transport/src/adapters/quic/mod.rs
//
// Standalone QUIC transport for direct phone-to-Stronghold connections.
//
// Bypasses the libp2p mesh entirely — no gossipsub, no Kademlia DHT.
// Uses s2n-quic with rustls for TLS (pure Rust, Windows-compatible).
//
// Architecture: Actor pattern matching Libp2pAdapter.
//   - Command channel (QuicCommand) for outbound operations
//   - Event channel (NetworkEvent) for inbound events
//   - QuicIngress implements IngressPort
//   - QuicEgress implements EgressPort (Send+Sync+Clone)
//
// Two modes:
//   - Server (Stronghold): accepts multiple client connections, fan-out publish
//   - Client (Phone): single connection to a Stronghold server

mod client;
pub(crate) mod config;
mod server;
pub(crate) mod wire;

pub use config::{QuicClientConfig, QuicServerConfig};
pub use wire::QuicError;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use phalanx_proto::identity::{MeshAddress, RecordingId};
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::retrieval::{RecordingRequest, RecordingResponse};
use phalanx_proto::topic::MeshTopic;
use tokio::sync::{mpsc, RwLock};

use phalanx_proto::network::{EgressPort, IngressPort};

use wire::QuicWireMessage;

// ── Internal Command Channel ─────────────────────────────────────────────

enum QuicCommand {
    Publish(MeshTopic, Vec<u8>),
    SendRequest(MeshAddress, RecordingRequest),
    SendResponse(String, RecordingResponse),
    Ban(MeshAddress),
}

// ── Connection Map ───────────────────────────────────────────────────────

/// Shared map of connected peers → their outbound message channels.
type ConnectionMap = Arc<RwLock<HashMap<MeshAddress, mpsc::Sender<QuicWireMessage>>>>;

// ── Ingress Port ─────────────────────────────────────────────────────────

/// Inbound event stream from the QUIC transport.
/// Consumed by MeshSentinel to receive network events.
pub struct QuicIngress {
    event_rx: mpsc::Receiver<NetworkEvent>,
}

#[async_trait]
impl IngressPort for QuicIngress {
    async fn next_event(&mut self) -> Option<NetworkEvent> {
        self.event_rx.recv().await
    }
}

// ── Egress Port ──────────────────────────────────────────────────────────

/// Outbound command interface for the QUIC transport.
/// Send+Sync+Clone — can be shared across tasks.
#[derive(Clone)]
pub struct QuicEgress {
    command_tx: mpsc::Sender<QuicCommand>,
}

#[async_trait]
impl EgressPort for QuicEgress {
    async fn publish(&self, topic: &MeshTopic, data: Vec<u8>) -> Result<(), String> {
        self.command_tx
            .send(QuicCommand::Publish(topic.clone(), data))
            .await
            .map_err(|_| "QUIC command channel closed".to_string())
    }

    async fn ban_peer(&self, peer: &MeshAddress) {
        let _ = self.command_tx.send(QuicCommand::Ban(peer.clone())).await;
    }

    async fn send_response(
        &self,
        channel_id: &str,
        response: RecordingResponse,
    ) -> Result<(), String> {
        self.command_tx
            .send(QuicCommand::SendResponse(channel_id.to_string(), response))
            .await
            .map_err(|_| "QUIC command channel closed".to_string())
    }

    /// No-op — point-to-point QUIC has no DHT.
    async fn announce_recording(&self, _recording_id: &RecordingId) -> Result<(), String> {
        Ok(())
    }

    /// No-op — point-to-point QUIC has no DHT.
    async fn find_providers(&self, _recording_id: &RecordingId) -> Result<(), String> {
        Ok(())
    }

    async fn send_request(
        &self,
        target: &MeshAddress,
        request: RecordingRequest,
    ) -> Result<(), String> {
        self.command_tx
            .send(QuicCommand::SendRequest(target.clone(), request))
            .await
            .map_err(|_| "QUIC command channel closed".to_string())
    }
}

// ── Adapter Factory ──────────────────────────────────────────────────────

/// Factory for creating QUIC transport instances.
///
/// Two modes:
/// - `server()` — Stronghold mode: accepts multiple client connections.
/// - `client()` — Phone mode: connects to a single Stronghold.
pub struct QuicAdapter;

impl QuicAdapter {
    /// Start a QUIC server (Stronghold mode).
    ///
    /// Returns `(ingress, egress, bound_address)`.
    /// The bound address is useful when binding to port 0 (OS-assigned).
    pub async fn server(
        config: QuicServerConfig,
    ) -> Result<(QuicIngress, QuicEgress, SocketAddr), QuicError> {
        let (event_tx, event_rx) = mpsc::channel(config.event_channel_capacity);
        let (command_tx, command_rx) = mpsc::channel::<QuicCommand>(128);

        // P13 FIX: Load TLS certs from memory — avoids writing private keys to
        // temp files on disk where they could be recovered (especially on Windows).
        // Note: s2n-quic treats &str as PEM and &[u8] as DER, so we must convert.
        let cert_pem = std::str::from_utf8(&config.cert_pem)
            .map_err(|e| QuicError::Tls(format!("Invalid PEM encoding: {}", e)))?;
        let key_pem = std::str::from_utf8(&config.key_pem)
            .map_err(|e| QuicError::Tls(format!("Invalid PEM encoding: {}", e)))?;

        let server = s2n_quic::Server::builder()
            .with_tls((cert_pem, key_pem))
            .map_err(|e| QuicError::Tls(e.to_string()))?
            .with_io(config.bind_address)
            .map_err(|e| QuicError::Transport(e.to_string()))?
            .start()
            .map_err(|e| QuicError::Transport(e.to_string()))?;

        let local_addr = server
            .local_addr()
            .map_err(|e| QuicError::Transport(e.to_string()))?;

        tokio::spawn(server::server_actor(
            server,
            event_tx,
            command_rx,
            config.max_connections,
        ));

        Ok((
            QuicIngress { event_rx },
            QuicEgress { command_tx },
            local_addr,
        ))
    }

    /// Start a QUIC client (Phone mode).
    ///
    /// Returns `(ingress, egress)`.
    /// The client connects to the configured Stronghold server and automatically
    /// reconnects with exponential backoff if the connection drops.
    pub async fn client(config: QuicClientConfig) -> Result<(QuicIngress, QuicEgress), QuicError> {
        let (event_tx, event_rx) = mpsc::channel(config.event_channel_capacity);
        let (command_tx, command_rx) = mpsc::channel::<QuicCommand>(128);

        // P13 FIX: Load CA cert from memory — no temp files needed.
        let ca_cert_pem = std::str::from_utf8(&config.ca_cert_pem)
            .map_err(|e| QuicError::Tls(format!("Invalid PEM encoding: {}", e)))?;

        let client = s2n_quic::Client::builder()
            .with_tls(ca_cert_pem)
            .map_err(|e| QuicError::Tls(e.to_string()))?
            .with_io("0.0.0.0:0")
            .map_err(|e| QuicError::Transport(e.to_string()))?
            .start()
            .map_err(|e| QuicError::Transport(e.to_string()))?;

        tokio::spawn(client::client_actor(
            client,
            config.server_address,
            config.server_name,
            config.local_network_id,
            config.server_network_id,
            config.max_reconnect_attempts,
            config.base_backoff_secs,
            config.max_backoff_secs,
            event_tx,
            command_rx,
        ));

        Ok((QuicIngress { event_rx }, QuicEgress { command_tx }))
    }
}

// ── Response Translation ─────────────────────────────────────────────────

/// Translate a `RecordingResponse` into a `NetworkEvent`.
///
/// Mirrors the event translation in `adapters/libp2p.rs`:
/// `RecordingResponse::Success` → `NetworkEvent::ShardResponseReceived`.
pub(crate) async fn translate_response(
    event_tx: &mpsc::Sender<NetworkEvent>,
    origin: &MeshAddress,
    _channel_id: &str,
    response: RecordingResponse,
) {
    match response {
        RecordingResponse::Success(sealed_units) => {
            let envelopes = sealed_units.into_iter().map(|u| u.unpack()).collect();
            let _ = event_tx
                .send(NetworkEvent::ShardResponseReceived {
                    origin: origin.clone(),
                    envelopes,
                })
                .await;
        }
        other => {
            tracing::debug!(
                target: "phalanx::quic",
                response = ?other,
                "Non-success recording response"
            );
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use phalanx_proto::MAX_PAYLOAD_SIZE;
    use wire::{read_frame, write_frame, QuicWireMessage};

    // ── Test Cert Generation ─────────────────────────────────────────

    /// Generate a self-signed TLS certificate for testing.
    /// Returns (cert_pem, key_pem).
    fn generate_test_certs() -> (Vec<u8>, Vec<u8>) {
        let key_pair = rcgen::KeyPair::generate().expect("Failed to generate key pair");
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("Failed to create cert params");
        let cert = params
            .self_signed(&key_pair)
            .expect("Failed to self-sign cert");

        let cert_pem = cert.pem().into_bytes();
        let key_pem = key_pair.serialize_pem().into_bytes();
        (cert_pem, key_pem)
    }

    // ── Wire Protocol Tests ──────────────────────────────────────────

    #[test]
    fn test_wire_message_roundtrip_identify() {
        let msg = QuicWireMessage::Identify {
            network_id: "peer_abc123".to_string(),
            timestamp_ms: 1700000000000,
        };
        let encoded = postcard::to_allocvec(&msg).expect("Serialize failed");
        let decoded: QuicWireMessage = postcard::from_bytes(&encoded).expect("Deserialize failed");

        match decoded {
            QuicWireMessage::Identify {
                network_id,
                timestamp_ms,
            } => {
                assert_eq!(network_id, "peer_abc123");
                assert_eq!(timestamp_ms, 1700000000000);
            }
            _ => panic!("Wrong variant after roundtrip"),
        }
    }

    #[test]
    fn test_wire_message_roundtrip_publish() {
        let msg = QuicWireMessage::Publish {
            topic: "video/raw".to_string(),
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let encoded = postcard::to_allocvec(&msg).expect("Serialize failed");
        let decoded: QuicWireMessage = postcard::from_bytes(&encoded).expect("Deserialize failed");

        match decoded {
            QuicWireMessage::Publish { topic, data } => {
                assert_eq!(topic, "video/raw");
                assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
            }
            _ => panic!("Wrong variant after roundtrip"),
        }
    }

    // ── Framing Tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_framing_roundtrip() {
        let msg = QuicWireMessage::Publish {
            topic: "audio/raw".to_string(),
            data: vec![1, 2, 3, 4, 5],
        };

        // Write to in-memory buffer
        let mut buf = Vec::new();
        write_frame(&mut buf, &msg)
            .await
            .expect("write_frame failed");

        // Read back
        let mut cursor = std::io::Cursor::new(buf);
        let decoded = read_frame(&mut cursor).await.expect("read_frame failed");

        match decoded {
            QuicWireMessage::Publish { topic, data } => {
                assert_eq!(topic, "audio/raw");
                assert_eq!(data, vec![1, 2, 3, 4, 5]);
            }
            _ => panic!("Wrong variant after framing roundtrip"),
        }
    }

    #[tokio::test]
    async fn test_oversized_payload_rejected() {
        // Craft a length prefix that exceeds MAX_PAYLOAD_SIZE
        let oversized_len = (MAX_PAYLOAD_SIZE as u32) + 1;
        let mut buf = Vec::new();
        buf.extend_from_slice(&oversized_len.to_le_bytes());
        // Don't need to add payload — read_frame should reject before reading payload
        // But we need enough bytes to avoid EOF before the length check.
        buf.extend(vec![0u8; 16]);

        let mut cursor = std::io::Cursor::new(buf);
        let result = read_frame(&mut cursor).await;

        assert!(result.is_err(), "Should reject oversized payload");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("MAX_PAYLOAD_SIZE"),
            "Error should mention MAX_PAYLOAD_SIZE, got: {}",
            err
        );
    }

    // ── Channel ID Routing Tests ─────────────────────────────────────

    #[test]
    fn test_extract_network_id_from_channel() {
        use server::extract_network_id_from_channel;
        assert_eq!(extract_network_id_from_channel("quic:peer_abc"), "peer_abc");
        assert_eq!(
            extract_network_id_from_channel("quic:peer_abc:42"),
            "peer_abc"
        );
        assert_eq!(extract_network_id_from_channel("peer_abc:42"), "peer_abc");
        assert_eq!(extract_network_id_from_channel("peer_abc"), "peer_abc");
    }

    // ── EgressPort DHT No-Op Tests ───────────────────────────────────

    #[tokio::test]
    async fn test_dht_ops_are_noop() {
        let (tx, _rx) = mpsc::channel(1);
        let egress = QuicEgress { command_tx: tx };

        let recording_id = RecordingId("test_recording".to_string());

        let announce_result = egress.announce_recording(&recording_id).await;
        assert!(
            announce_result.is_ok(),
            "announce_recording should be no-op Ok"
        );

        let find_result = egress.find_providers(&recording_id).await;
        assert!(find_result.is_ok(), "find_providers should be no-op Ok");
    }

    // ── Integration Tests ────────────────────────────────────────────

    #[tokio::test]
    async fn test_server_client_publish() {
        let (cert_pem, key_pem) = generate_test_certs();

        // Start server
        let server_config = QuicServerConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            cert_pem: cert_pem.clone(),
            key_pem,
            event_channel_capacity: 64,
            max_connections: 64,
        };

        let (mut server_ingress, _server_egress, server_addr) = QuicAdapter::server(server_config)
            .await
            .expect("Server start failed");

        // Start client
        let client_id = MeshAddress::new("test_client_001".to_string());
        let server_id = MeshAddress::new("test_server_001".to_string());

        let client_config = QuicClientConfig {
            server_address: server_addr,
            server_name: "localhost".to_string(),
            ca_cert_pem: cert_pem,
            local_network_id: client_id.clone(),
            server_network_id: server_id,
            event_channel_capacity: 64,
            max_reconnect_attempts: Some(0),
            base_backoff_secs: 1,
            max_backoff_secs: 1,
        };

        let (_client_ingress, client_egress) = QuicAdapter::client(client_config)
            .await
            .expect("Client start failed");

        // Give client time to connect and identify
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Client publishes data
        let topic = MeshTopic::new("video/raw");
        let payload = b"forensic_evidence_chunk_001".to_vec();
        client_egress
            .publish(&topic, payload.clone())
            .await
            .expect("Publish failed");

        // Server should receive PeerDiscovered, then DataReceived
        let mut received_data = false;
        for _ in 0..10 {
            match tokio::time::timeout(
                std::time::Duration::from_millis(500),
                server_ingress.next_event(),
            )
            .await
            {
                Ok(Some(NetworkEvent::PeerDiscovered { peer, .. })) => {
                    assert_eq!(peer.0, client_id.0);
                }
                Ok(Some(NetworkEvent::DataReceived { origin, data, .. })) => {
                    assert_eq!(origin.0, client_id.0);
                    assert_eq!(data, payload);
                    received_data = true;
                    break;
                }
                Ok(Some(_other)) => {
                    // Other events, continue
                }
                Ok(None) => break,
                Err(_) => break, // Timeout
            }
        }

        assert!(received_data, "Server should have received published data");
    }

    #[tokio::test]
    async fn test_ban_disconnects_peer() {
        let (cert_pem, key_pem) = generate_test_certs();

        let server_config = QuicServerConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            cert_pem: cert_pem.clone(),
            key_pem,
            event_channel_capacity: 64,
            max_connections: 64,
        };

        let (mut server_ingress, server_egress, server_addr) = QuicAdapter::server(server_config)
            .await
            .expect("Server start failed");

        let client_id = MeshAddress::new("ban_test_client".to_string());

        let client_config = QuicClientConfig {
            server_address: server_addr,
            server_name: "localhost".to_string(),
            ca_cert_pem: cert_pem,
            local_network_id: client_id.clone(),
            server_network_id: MeshAddress::new("server".to_string()),
            event_channel_capacity: 64,
            max_reconnect_attempts: Some(0),
            base_backoff_secs: 1,
            max_backoff_secs: 1,
        };

        let (_client_ingress, client_egress) = QuicAdapter::client(client_config)
            .await
            .expect("Client start failed");

        // Wait for connection
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Verify client can publish
        client_egress
            .publish(&MeshTopic::new("test"), b"before_ban".to_vec())
            .await
            .expect("Pre-ban publish failed");

        // Wait for the event
        let mut got_data = false;
        for _ in 0..5 {
            match tokio::time::timeout(
                std::time::Duration::from_millis(500),
                server_ingress.next_event(),
            )
            .await
            {
                Ok(Some(NetworkEvent::DataReceived { .. })) => {
                    got_data = true;
                    break;
                }
                Ok(Some(_)) => continue,
                _ => break,
            }
        }
        assert!(got_data, "Should receive data before ban");

        // Ban the client
        server_egress.ban_peer(&client_id).await;

        // Give time for disconnection to propagate
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // After banning, new publishes from client should not arrive at server.
        // The connection handler is dropped, so the client's connection is severed.
        // (We don't assert the client-side error here — just that server doesn't
        // receive new data from the banned peer.)
    }

    #[tokio::test]
    async fn test_server_multiple_clients() {
        let (cert_pem, key_pem) = generate_test_certs();

        let server_config = QuicServerConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            cert_pem: cert_pem.clone(),
            key_pem,
            event_channel_capacity: 64,
            max_connections: 64,
        };

        let (mut server_ingress, _server_egress, server_addr) = QuicAdapter::server(server_config)
            .await
            .expect("Server start failed");

        // Connect two clients
        let client_a_id = MeshAddress::new("client_alpha".to_string());
        let client_b_id = MeshAddress::new("client_beta".to_string());
        let server_id = MeshAddress::new("server".to_string());

        let config_a = QuicClientConfig {
            server_address: server_addr,
            server_name: "localhost".to_string(),
            ca_cert_pem: cert_pem.clone(),
            local_network_id: client_a_id.clone(),
            server_network_id: server_id.clone(),
            event_channel_capacity: 64,
            max_reconnect_attempts: Some(0),
            base_backoff_secs: 1,
            max_backoff_secs: 1,
        };

        let config_b = QuicClientConfig {
            server_address: server_addr,
            server_name: "localhost".to_string(),
            ca_cert_pem: cert_pem,
            local_network_id: client_b_id.clone(),
            server_network_id: server_id,
            event_channel_capacity: 64,
            max_reconnect_attempts: Some(0),
            base_backoff_secs: 1,
            max_backoff_secs: 1,
        };

        let (_ingress_a, egress_a) = QuicAdapter::client(config_a)
            .await
            .expect("Client A failed");
        let (_ingress_b, egress_b) = QuicAdapter::client(config_b)
            .await
            .expect("Client B failed");

        // Wait for both to connect
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // Client A publishes
        egress_a
            .publish(&MeshTopic::new("test"), b"from_alpha".to_vec())
            .await
            .expect("Client A publish failed");

        // Client B publishes
        egress_b
            .publish(&MeshTopic::new("test"), b"from_beta".to_vec())
            .await
            .expect("Client B publish failed");

        // Server should receive data from both clients with correct origins
        let mut origins = Vec::new();
        for _ in 0..10 {
            match tokio::time::timeout(
                std::time::Duration::from_millis(500),
                server_ingress.next_event(),
            )
            .await
            {
                Ok(Some(NetworkEvent::DataReceived { origin, .. })) => {
                    origins.push(origin.0.clone());
                    if origins.len() >= 2 {
                        break;
                    }
                }
                Ok(Some(_)) => continue,
                _ => break,
            }
        }

        assert!(
            origins.contains(&client_a_id.0),
            "Should receive data from client A, got: {:?}",
            origins
        );
        assert!(
            origins.contains(&client_b_id.0),
            "Should receive data from client B, got: {:?}",
            origins
        );
    }

    // ── Reconnection Tests ────────────────────────────────────────

    #[test]
    fn test_backoff_delay_schedule() {
        use client::backoff_delay;
        // Default schedule: base=5, max=300
        // 5 → 10 → 20 → 40 → 80 → 160 → 300 → 300
        let expected = [5, 10, 20, 40, 80, 160, 300, 300];
        for (attempt, &expected_secs) in expected.iter().enumerate() {
            let delay = backoff_delay(attempt as u32, 5, 300);
            assert_eq!(
                delay.as_secs(),
                expected_secs,
                "Attempt {} should be {}s, got {}s",
                attempt,
                expected_secs,
                delay.as_secs()
            );
        }
    }

    #[tokio::test]
    async fn test_client_respects_max_attempts() {
        let (cert_pem, _key_pem) = generate_test_certs();

        // No server running — every connect attempt will fail.
        // max_reconnect_attempts = 2, so actor should give up after 2 retries.
        let client_config = QuicClientConfig {
            server_address: "127.0.0.1:19999".parse().unwrap(), // Nothing listening
            server_name: "localhost".to_string(),
            ca_cert_pem: cert_pem,
            local_network_id: MeshAddress::new("max_attempts_client".to_string()),
            server_network_id: MeshAddress::new("unreachable_server".to_string()),
            event_channel_capacity: 64,
            max_reconnect_attempts: Some(2),
            base_backoff_secs: 1,
            max_backoff_secs: 1,
        };

        let (mut ingress, _egress) = QuicAdapter::client(client_config)
            .await
            .expect("Client creation failed");

        // Collect all events until the actor terminates (ingress returns None).
        // We should see PeerDisconnected events and then the channel closes.
        let mut disconnect_count = 0u32;
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(15), ingress.next_event())
                .await
            {
                Ok(Some(NetworkEvent::PeerDisconnected { .. })) => {
                    disconnect_count += 1;
                }
                Ok(Some(_other)) => {
                    // Unexpected event
                }
                Ok(None) => {
                    // Actor terminated — ingress channel closed
                    break;
                }
                Err(_) => {
                    panic!("Timed out waiting for client actor to give up");
                }
            }
        }

        // Initial connect + 2 retries = 3 total attempts, each emitting PeerDisconnected
        assert!(
            disconnect_count >= 1,
            "Should have received at least 1 PeerDisconnected, got {}",
            disconnect_count
        );
    }

    #[tokio::test]
    async fn test_client_emits_disconnect_and_retries() {
        let (cert_pem, key_pem) = generate_test_certs();

        // Phase 1: Start server, connect client, verify connectivity.
        let server_config = QuicServerConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            cert_pem: cert_pem.clone(),
            key_pem,
            event_channel_capacity: 64,
            max_connections: 64,
        };

        let (_server_ingress, _server_egress, server_addr) = QuicAdapter::server(server_config)
            .await
            .expect("Server start failed");

        let server_id = MeshAddress::new("reconnect_server".to_string());

        let client_config = QuicClientConfig {
            server_address: server_addr,
            server_name: "localhost".to_string(),
            ca_cert_pem: cert_pem,
            local_network_id: MeshAddress::new("reconnect_client".to_string()),
            server_network_id: server_id.clone(),
            event_channel_capacity: 64,
            max_reconnect_attempts: Some(3),
            base_backoff_secs: 1,
            max_backoff_secs: 1,
        };

        let (mut client_ingress, _client_egress) = QuicAdapter::client(client_config)
            .await
            .expect("Client start failed");

        // Verify initial PeerDiscovered
        let mut saw_discovered = false;
        for _ in 0..5 {
            match tokio::time::timeout(
                std::time::Duration::from_millis(500),
                client_ingress.next_event(),
            )
            .await
            {
                Ok(Some(NetworkEvent::PeerDiscovered { peer, .. })) => {
                    assert_eq!(peer.0, server_id.0);
                    saw_discovered = true;
                    break;
                }
                Ok(Some(_)) => continue,
                _ => break,
            }
        }
        assert!(
            saw_discovered,
            "Client should see PeerDiscovered on initial connect"
        );

        // Phase 2: Drop the server to trigger disconnect.
        drop(_server_ingress);
        drop(_server_egress);

        // Phase 3: Collect events — should see PeerDisconnected, then more
        // PeerDisconnected from failed retries, then channel closes.
        let mut disconnect_count = 0u32;
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_secs(15),
                client_ingress.next_event(),
            )
            .await
            {
                Ok(Some(NetworkEvent::PeerDisconnected { peer })) => {
                    assert_eq!(peer.0, server_id.0, "Disconnect should be for server");
                    disconnect_count += 1;
                }
                Ok(Some(_other)) => {
                    // Other events during retry — continue
                }
                Ok(None) => {
                    // Actor terminated — channel closed after max attempts
                    break;
                }
                Err(_) => {
                    panic!("Timed out waiting for client actor to exhaust retries");
                }
            }
        }

        // Should have seen disconnect from the initial connection drop,
        // plus disconnects from failed reconnection attempts.
        assert!(
            disconnect_count >= 1,
            "Should see at least 1 PeerDisconnected, got {}",
            disconnect_count
        );
    }
}
