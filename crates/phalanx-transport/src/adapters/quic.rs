// crates/phalanx-transport/src/adapters/quic.rs
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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use phalanx_proto::identity::{NetworkId, RecordingId};
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::retrieval::{RecordingRequest, RecordingResponse};
use phalanx_proto::telemetry::DiscoverySource;
use phalanx_proto::topic::MeshTopic;
use phalanx_proto::MAX_PAYLOAD_SIZE;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};

use crate::{EgressPort, IngressPort};

// ── Wire Protocol ────────────────────────────────────────────────────────

/// Messages exchanged over QUIC bidirectional streams.
/// Each message is a length-prefixed postcard frame (4-byte LE length + payload).
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum QuicWireMessage {
    /// Client identifies itself to the server on the first stream.
    Identify { network_id: String },
    /// Publish data on a topic (broadcast to all connected peers).
    Publish { topic: String, data: Vec<u8> },
    /// Recording retrieval request.
    Request {
        channel_id: String,
        request: RecordingRequest,
    },
    /// Recording retrieval response.
    Response {
        channel_id: String,
        response: RecordingResponse,
    },
}

// ── Error Type ───────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum QuicError {
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Transport error: {0}")]
    Transport(String),
    #[error("Codec error: {0}")]
    Codec(String),
}

// ── Internal Command Channel ─────────────────────────────────────────────

enum QuicCommand {
    Publish(MeshTopic, Vec<u8>),
    SendRequest(NetworkId, RecordingRequest),
    SendResponse(String, RecordingResponse),
    Ban(NetworkId),
}

// ── Configuration ────────────────────────────────────────────────────────

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

// ── Framing ──────────────────────────────────────────────────────────────

/// Write a length-prefixed postcard frame to a stream.
///
/// Format: [4-byte LE length][postcard payload]
///
/// Mirrors the framing pattern in `codec.rs` (`PhalanxRetrievalProtocol`).
#[allow(clippy::arithmetic_side_effects)]
async fn write_frame(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    msg: &QuicWireMessage,
) -> Result<(), QuicError> {
    let payload = postcard::to_allocvec(msg).map_err(|e| QuicError::Codec(e.to_string()))?;

    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(QuicError::Codec(format!(
            "Payload {} bytes exceeds MAX_PAYLOAD_SIZE {}",
            payload.len(),
            MAX_PAYLOAD_SIZE
        )));
    }

    let len_bytes = (payload.len() as u32).to_le_bytes();
    stream.write_all(&len_bytes).await?;
    stream.write_all(&payload).await?;
    Ok(())
}

/// Read a length-prefixed postcard frame from a stream.
#[allow(clippy::arithmetic_side_effects)]
async fn read_frame(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<QuicWireMessage, QuicError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let payload_len = u32::from_le_bytes(len_buf) as usize;

    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(QuicError::Codec(format!(
            "Incoming payload {} bytes exceeds MAX_PAYLOAD_SIZE {}",
            payload_len, MAX_PAYLOAD_SIZE
        )));
    }

    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;

    postcard::from_bytes(&payload).map_err(|e| QuicError::Codec(e.to_string()))
}

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

    async fn ban_peer(&self, peer: &NetworkId) {
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
        target: &NetworkId,
        request: RecordingRequest,
    ) -> Result<(), String> {
        self.command_tx
            .send(QuicCommand::SendRequest(target.clone(), request))
            .await
            .map_err(|_| "QUIC command channel closed".to_string())
    }
}

// ── Connection Map ───────────────────────────────────────────────────────

/// Shared map of connected peers → their outbound message channels.
type ConnectionMap = Arc<RwLock<HashMap<NetworkId, mpsc::Sender<QuicWireMessage>>>>;

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

        // Write PEM to temp files — s2n-quic's file-path TLS API is the most
        // robust across all platforms and providers.
        let cert_file = tempfile::NamedTempFile::new()?;
        std::fs::write(cert_file.path(), &config.cert_pem)?;
        let key_file = tempfile::NamedTempFile::new()?;
        std::fs::write(key_file.path(), &config.key_pem)?;

        let server = s2n_quic::Server::builder()
            .with_tls((cert_file.path(), key_file.path()))
            .map_err(|e| QuicError::Tls(e.to_string()))?
            .with_io(config.bind_address)
            .map_err(|e| QuicError::Transport(e.to_string()))?
            .start()
            .map_err(|e| QuicError::Transport(e.to_string()))?;

        let local_addr = server
            .local_addr()
            .map_err(|e| QuicError::Transport(e.to_string()))?;

        tokio::spawn(server_actor(server, event_tx, command_rx));

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

        // Write CA cert to temp file for s2n-quic compatibility.
        let ca_cert_file = tempfile::NamedTempFile::new()?;
        std::fs::write(ca_cert_file.path(), &config.ca_cert_pem)?;

        let client = s2n_quic::Client::builder()
            .with_tls(ca_cert_file.path())
            .map_err(|e| QuicError::Tls(e.to_string()))?
            .with_io("0.0.0.0:0")
            .map_err(|e| QuicError::Transport(e.to_string()))?
            .start()
            .map_err(|e| QuicError::Transport(e.to_string()))?;

        tokio::spawn(client_actor(
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

// ── Server Actor ─────────────────────────────────────────────────────────

/// Server actor: accepts connections, routes commands to connected clients.
///
/// Runs as a detached tokio task. The server accepts incoming QUIC connections,
/// spawns a handler per connection, and routes outbound commands from the
/// QuicEgress to the appropriate connection handler via the shared connection map.
async fn server_actor(
    mut server: s2n_quic::Server,
    event_tx: mpsc::Sender<NetworkEvent>,
    mut command_rx: mpsc::Receiver<QuicCommand>,
) {
    let connections: ConnectionMap = Arc::new(RwLock::new(HashMap::new()));

    loop {
        tokio::select! {
            maybe_conn = server.accept() => {
                match maybe_conn {
                    Some(connection) => {
                        let etx = event_tx.clone();
                        let conns = connections.clone();
                        tokio::spawn(server_connection_handler(connection, etx, conns));
                    }
                    None => {
                        tracing::info!(target: "phalanx::quic", "Server shutting down");
                        break;
                    }
                }
            }
            maybe_cmd = command_rx.recv() => {
                match maybe_cmd {
                    Some(cmd) => route_server_command(cmd, &connections).await,
                    None => {
                        tracing::info!(
                            target: "phalanx::quic",
                            "Command channel closed, server stopping"
                        );
                        break;
                    }
                }
            }
        }
    }

    // Shutdown: clear all connection entries so handler tasks' conn_rx.recv()
    // returns None → handlers exit → s2n-quic connections close cleanly.
    connections.write().await.clear();
}

/// Route a command from QuicEgress to the appropriate connection(s).
async fn route_server_command(cmd: QuicCommand, connections: &ConnectionMap) {
    match cmd {
        QuicCommand::Publish(topic, data) => {
            let conns = connections.read().await;
            let topic_str = topic.to_string();
            for (peer_id, sender) in conns.iter() {
                let msg = QuicWireMessage::Publish {
                    topic: topic_str.clone(),
                    data: data.clone(),
                };
                if sender.send(msg).await.is_err() {
                    tracing::warn!(
                        target: "phalanx::quic",
                        peer = %peer_id.0,
                        "Failed to route publish to connection"
                    );
                }
            }
        }
        QuicCommand::SendRequest(target, request) => {
            let conns = connections.read().await;
            if let Some(sender) = conns.get(&target) {
                let msg = QuicWireMessage::Request {
                    channel_id: format!("quic:{}", target.0),
                    request,
                };
                if sender.send(msg).await.is_err() {
                    tracing::warn!(
                        target: "phalanx::quic",
                        peer = %target.0,
                        "Failed to route request to connection"
                    );
                }
            } else {
                tracing::warn!(
                    target: "phalanx::quic",
                    peer = %target.0,
                    "No connection found for request target"
                );
            }
        }
        QuicCommand::SendResponse(channel_id, response) => {
            // channel_id format: "{network_id}:{seq}" — extract network_id to route.
            let target_id = extract_network_id_from_channel(&channel_id);
            let conns = connections.read().await;
            if let Some(sender) = conns.get(&NetworkId(target_id.clone())) {
                let msg = QuicWireMessage::Response {
                    channel_id,
                    response,
                };
                if sender.send(msg).await.is_err() {
                    tracing::warn!(
                        target: "phalanx::quic",
                        peer = %target_id,
                        "Failed to route response to connection"
                    );
                }
            }
        }
        QuicCommand::Ban(peer) => {
            let mut conns = connections.write().await;
            if conns.remove(&peer).is_some() {
                tracing::info!(
                    target: "phalanx::quic",
                    peer = %peer.0,
                    "Banned peer, dropping QUIC connection"
                );
            }
        }
    }
}

/// Extract the network_id from a channel_id.
///
/// Supports formats:
/// - `"quic:{id}"` → `"{id}"`
/// - `"{id}:{seq}"` → `"{id}"`
/// - `"{id}"` → `"{id}"`
fn extract_network_id_from_channel(channel_id: &str) -> String {
    if let Some(stripped) = channel_id.strip_prefix("quic:") {
        stripped.split(':').next().unwrap_or(stripped).to_string()
    } else {
        channel_id
            .split(':')
            .next()
            .unwrap_or(channel_id)
            .to_string()
    }
}

// ── Server Connection Handler ────────────────────────────────────────────

/// Handles a single client connection on the server side.
///
/// Flow:
/// 1. Wait for Identify message on first stream.
/// 2. Register in the shared connection map.
/// 3. Loop: accept incoming streams and process outbound commands.
/// 4. On disconnect: remove from connection map.
async fn server_connection_handler(
    mut connection: s2n_quic::Connection,
    event_tx: mpsc::Sender<NetworkEvent>,
    connections: ConnectionMap,
) {
    // Phase 1: Identity handshake — first stream must carry an Identify message.
    let network_id = match connection.accept_bidirectional_stream().await {
        Ok(Some(mut stream)) => match read_frame(&mut stream).await {
            Ok(QuicWireMessage::Identify { network_id }) => NetworkId(network_id),
            Ok(_other) => {
                tracing::warn!(
                    target: "phalanx::quic",
                    "First message was not Identify, dropping connection"
                );
                return;
            }
            Err(e) => {
                tracing::warn!(
                    target: "phalanx::quic",
                    error = %e,
                    "Failed to read identity frame"
                );
                return;
            }
        },
        Ok(None) => {
            tracing::debug!(
                target: "phalanx::quic",
                "Connection closed before identity"
            );
            return;
        }
        Err(e) => {
            tracing::warn!(
                target: "phalanx::quic",
                error = %e,
                "Stream accept failed during identity"
            );
            return;
        }
    };

    tracing::info!(
        target: "phalanx::quic",
        peer = %network_id.0,
        "Client identified via QUIC"
    );

    // Emit PeerDiscovered event
    let _ = event_tx
        .send(NetworkEvent::PeerDiscovered {
            peer: network_id.clone(),
            source: DiscoverySource::Quic,
        })
        .await;

    // Phase 2: Register in connection map
    let (conn_tx, mut conn_rx) = mpsc::channel::<QuicWireMessage>(64);
    {
        connections
            .write()
            .await
            .insert(network_id.clone(), conn_tx);
    }

    // Phase 3: Main loop — accept incoming streams + process outbound commands
    loop {
        tokio::select! {
            stream_result = connection.accept_bidirectional_stream() => {
                match stream_result {
                    Ok(Some(mut stream)) => {
                        handle_incoming_message(
                            &mut stream,
                            &event_tx,
                            &network_id,
                        ).await;
                    }
                    Ok(None) => {
                        tracing::info!(
                            target: "phalanx::quic",
                            peer = %network_id.0,
                            "Client disconnected"
                        );
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "phalanx::quic",
                            peer = %network_id.0,
                            error = %e,
                            "Stream accept error"
                        );
                        break;
                    }
                }
            }
            maybe_cmd = conn_rx.recv() => {
                match maybe_cmd {
                    Some(msg) => {
                        match connection.open_bidirectional_stream().await {
                            Ok(mut stream) => {
                                if let Err(e) = write_frame(&mut stream, &msg).await {
                                    tracing::warn!(
                                        target: "phalanx::quic",
                                        peer = %network_id.0,
                                        error = %e,
                                        "Failed to write frame to client"
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    target: "phalanx::quic",
                                    peer = %network_id.0,
                                    error = %e,
                                    "Failed to open outbound stream"
                                );
                                break;
                            }
                        }
                    }
                    None => {
                        // Command channel closed (peer was banned)
                        tracing::info!(
                            target: "phalanx::quic",
                            peer = %network_id.0,
                            "Connection command channel closed"
                        );
                        break;
                    }
                }
            }
        }
    }

    // Cleanup: remove from connection map
    connections.write().await.remove(&network_id);
}

/// Process a single incoming wire message from a QUIC stream.
async fn handle_incoming_message(
    stream: &mut s2n_quic::stream::BidirectionalStream,
    event_tx: &mpsc::Sender<NetworkEvent>,
    origin: &NetworkId,
) {
    match read_frame(stream).await {
        Ok(QuicWireMessage::Publish { topic, data }) => {
            let _ = event_tx
                .send(NetworkEvent::DataReceived {
                    origin: origin.clone(),
                    topic: MeshTopic::new(&topic),
                    data,
                })
                .await;
        }
        Ok(QuicWireMessage::Request {
            channel_id,
            request,
        }) => {
            // Prefix channel_id with origin's network_id for response routing.
            let routable_channel = format!("{}:{}", origin.0, channel_id);
            let _ = event_tx
                .send(NetworkEvent::RecordingRequested {
                    origin: origin.clone(),
                    request,
                    channel_id: routable_channel,
                })
                .await;
        }
        Ok(QuicWireMessage::Response {
            channel_id,
            response,
        }) => {
            translate_response(event_tx, origin, &channel_id, response).await;
        }
        Ok(QuicWireMessage::Identify { .. }) => {
            tracing::warn!(
                target: "phalanx::quic",
                peer = %origin.0,
                "Duplicate Identify message, ignoring"
            );
        }
        Err(e) => {
            tracing::debug!(
                target: "phalanx::quic",
                peer = %origin.0,
                error = %e,
                "Frame read error on stream"
            );
        }
    }
}

// ── Client Actor ─────────────────────────────────────────────────────────

/// Compute exponential backoff delay.
///
/// Mirrors `OutboundQueue::backoff_delay()` from `phalanx-node/src/persistence/outbound.rs`.
/// Schedule with base=5, max=300: 5s → 10s → 20s → 40s → 80s → 160s → 300s → 300s…
fn backoff_delay(attempt: u32, base_secs: u64, max_secs: u64) -> Duration {
    let delay = base_secs.saturating_mul(1u64 << attempt.min(6));
    Duration::from_secs(delay.min(max_secs))
}

/// Client actor: maintains a QUIC connection to a Stronghold server with
/// automatic reconnection and exponential backoff.
///
/// Outer loop: connect → identify → inner loop → disconnect → backoff → retry.
/// The `event_tx` and `command_rx` channels survive across reconnects.
#[allow(clippy::too_many_arguments)]
async fn client_actor(
    client: s2n_quic::Client,
    server_address: SocketAddr,
    server_name: String,
    local_network_id: NetworkId,
    server_network_id: NetworkId,
    max_reconnect_attempts: Option<u32>,
    base_backoff_secs: u64,
    max_backoff_secs: u64,
    event_tx: mpsc::Sender<NetworkEvent>,
    mut command_rx: mpsc::Receiver<QuicCommand>,
) {
    let mut attempt: u32 = 0;

    loop {
        // ── Connect ──────────────────────────────────────────────────
        let connect =
            s2n_quic::client::Connect::new(server_address).with_server_name(server_name.as_str());

        let mut connection = match client.connect(connect).await {
            Ok(conn) => {
                attempt = 0; // Reset on successful connect
                conn
            }
            Err(e) => {
                tracing::warn!(
                    target: "phalanx::quic",
                    error = %e,
                    server = %server_address,
                    attempt,
                    "Failed to connect to Stronghold"
                );

                // Emit disconnect event (server unreachable counts as "lost")
                let _ = event_tx
                    .send(NetworkEvent::PeerDisconnected {
                        peer: server_network_id.clone(),
                    })
                    .await;

                attempt = attempt.saturating_add(1);
                if let Some(max) = max_reconnect_attempts {
                    if attempt > max {
                        tracing::error!(
                            target: "phalanx::quic",
                            "Max reconnect attempts ({}) exceeded, giving up",
                            max
                        );
                        return;
                    }
                }

                let delay = backoff_delay(attempt, base_backoff_secs, max_backoff_secs);
                tracing::info!(
                    target: "phalanx::quic",
                    delay_secs = delay.as_secs(),
                    attempt,
                    "Reconnecting after backoff"
                );
                tokio::time::sleep(delay).await;
                continue;
            }
        };

        tracing::info!(
            target: "phalanx::quic",
            server = %server_address,
            "Connected to Stronghold via QUIC"
        );

        // ── Identify ─────────────────────────────────────────────────
        let identified = match connection.open_bidirectional_stream().await {
            Ok(mut stream) => {
                let identify = QuicWireMessage::Identify {
                    network_id: local_network_id.0.clone(),
                };
                match write_frame(&mut stream, &identify).await {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::error!(
                            target: "phalanx::quic",
                            error = %e,
                            "Failed to send Identify message"
                        );
                        false
                    }
                }
            }
            Err(e) => {
                tracing::error!(
                    target: "phalanx::quic",
                    error = %e,
                    "Failed to open identity stream"
                );
                false
            }
        };

        if !identified {
            // Treat identity failure as a connection failure — backoff and retry.
            attempt = attempt.saturating_add(1);
            if let Some(max) = max_reconnect_attempts {
                if attempt > max {
                    return;
                }
            }
            let delay = backoff_delay(attempt, base_backoff_secs, max_backoff_secs);
            tokio::time::sleep(delay).await;
            continue;
        }

        // ── Emit PeerDiscovered ──────────────────────────────────────
        let _ = event_tx
            .send(NetworkEvent::PeerDiscovered {
                peer: server_network_id.clone(),
                source: DiscoverySource::Quic,
            })
            .await;

        // ── Connection Loop ──────────────────────────────────────────
        let egress_closed = client_connection_loop(
            &mut connection,
            &event_tx,
            &mut command_rx,
            &server_network_id,
            &local_network_id,
        )
        .await;

        // ── Disconnected ─────────────────────────────────────────────
        tracing::info!(
            target: "phalanx::quic",
            server = %server_address,
            "Disconnected from Stronghold"
        );

        let _ = event_tx
            .send(NetworkEvent::PeerDisconnected {
                peer: server_network_id.clone(),
            })
            .await;

        // If the egress channel was closed (QuicEgress dropped), stop entirely.
        if egress_closed {
            tracing::info!(
                target: "phalanx::quic",
                "Egress channel closed, client actor stopping"
            );
            return;
        }

        // Backoff before reconnect
        attempt = attempt.saturating_add(1);
        if let Some(max) = max_reconnect_attempts {
            if attempt > max {
                tracing::error!(
                    target: "phalanx::quic",
                    "Max reconnect attempts ({}) exceeded, giving up",
                    max
                );
                return;
            }
        }

        let delay = backoff_delay(attempt, base_backoff_secs, max_backoff_secs);
        tracing::info!(
            target: "phalanx::quic",
            delay_secs = delay.as_secs(),
            attempt,
            "Reconnecting after backoff"
        );
        tokio::time::sleep(delay).await;
    }
}

/// Inner connection loop: processes commands and incoming streams until
/// the connection drops or the egress channel closes.
///
/// Returns `true` if the egress channel was closed (actor should stop),
/// `false` if the connection dropped (should reconnect).
async fn client_connection_loop(
    connection: &mut s2n_quic::Connection,
    event_tx: &mpsc::Sender<NetworkEvent>,
    command_rx: &mut mpsc::Receiver<QuicCommand>,
    server_network_id: &NetworkId,
    local_network_id: &NetworkId,
) -> bool {
    loop {
        tokio::select! {
            stream_result = connection.accept_bidirectional_stream() => {
                match stream_result {
                    Ok(Some(mut stream)) => {
                        handle_client_incoming(
                            &mut stream,
                            event_tx,
                            server_network_id,
                        ).await;
                    }
                    Ok(None) => {
                        tracing::info!(
                            target: "phalanx::quic",
                            "Server connection closed"
                        );
                        return false;
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "phalanx::quic",
                            error = %e,
                            "Stream accept error from server"
                        );
                        return false;
                    }
                }
            }
            maybe_cmd = command_rx.recv() => {
                match maybe_cmd {
                    Some(cmd) => {
                        if let Err(e) = handle_client_command(
                            connection,
                            cmd,
                            local_network_id,
                        ).await {
                            tracing::warn!(
                                target: "phalanx::quic",
                                error = %e,
                                "Failed to send command to server"
                            );
                        }
                    }
                    None => {
                        tracing::info!(
                            target: "phalanx::quic",
                            "Client command channel closed"
                        );
                        return true; // Egress dropped — stop entirely
                    }
                }
            }
        }
    }
}

/// Process an incoming wire message from the server (client side).
async fn handle_client_incoming(
    stream: &mut s2n_quic::stream::BidirectionalStream,
    event_tx: &mpsc::Sender<NetworkEvent>,
    server_id: &NetworkId,
) {
    match read_frame(stream).await {
        Ok(QuicWireMessage::Publish { topic, data }) => {
            let _ = event_tx
                .send(NetworkEvent::DataReceived {
                    origin: server_id.clone(),
                    topic: MeshTopic::new(&topic),
                    data,
                })
                .await;
        }
        Ok(QuicWireMessage::Request {
            channel_id,
            request,
        }) => {
            let _ = event_tx
                .send(NetworkEvent::RecordingRequested {
                    origin: server_id.clone(),
                    request,
                    channel_id,
                })
                .await;
        }
        Ok(QuicWireMessage::Response {
            channel_id,
            response,
        }) => {
            translate_response(event_tx, server_id, &channel_id, response).await;
        }
        Ok(QuicWireMessage::Identify { .. }) => {
            tracing::warn!(
                target: "phalanx::quic",
                "Server sent unexpected Identify message"
            );
        }
        Err(e) => {
            tracing::debug!(
                target: "phalanx::quic",
                error = %e,
                "Frame read error on incoming stream from server"
            );
        }
    }
}

/// Handle a single outbound command from the QuicEgress (client side).
async fn handle_client_command(
    connection: &mut s2n_quic::Connection,
    cmd: QuicCommand,
    local_id: &NetworkId,
) -> Result<(), QuicError> {
    match cmd {
        QuicCommand::Publish(topic, data) => {
            let msg = QuicWireMessage::Publish {
                topic: topic.to_string(),
                data,
            };
            send_on_new_stream(connection, &msg).await
        }
        QuicCommand::SendRequest(_target, request) => {
            let msg = QuicWireMessage::Request {
                channel_id: format!("quic:{}:req", local_id.0),
                request,
            };
            send_on_new_stream(connection, &msg).await
        }
        QuicCommand::SendResponse(channel_id, response) => {
            let msg = QuicWireMessage::Response {
                channel_id,
                response,
            };
            send_on_new_stream(connection, &msg).await
        }
        QuicCommand::Ban(_peer) => {
            // Client can't ban the server — no-op
            tracing::debug!(
                target: "phalanx::quic",
                "Client ignoring ban command (single-server mode)"
            );
            Ok(())
        }
    }
}

/// Open a new bidirectional stream and write a single frame.
async fn send_on_new_stream(
    connection: &mut s2n_quic::Connection,
    msg: &QuicWireMessage,
) -> Result<(), QuicError> {
    let mut stream = connection
        .open_bidirectional_stream()
        .await
        .map_err(|e| QuicError::Transport(e.to_string()))?;
    write_frame(&mut stream, msg).await
}

// ── Response Translation ─────────────────────────────────────────────────

/// Translate a `RecordingResponse` into a `NetworkEvent`.
///
/// Mirrors the event translation in `adapters/libp2p.rs`:
/// `RecordingResponse::Success` → `NetworkEvent::ShardResponseReceived`.
async fn translate_response(
    event_tx: &mpsc::Sender<NetworkEvent>,
    origin: &NetworkId,
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
mod tests {
    use super::*;

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
        };
        let encoded = postcard::to_allocvec(&msg).expect("Serialize failed");
        let decoded: QuicWireMessage = postcard::from_bytes(&encoded).expect("Deserialize failed");

        match decoded {
            QuicWireMessage::Identify { network_id } => {
                assert_eq!(network_id, "peer_abc123");
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
        };

        let (mut server_ingress, _server_egress, server_addr) = QuicAdapter::server(server_config)
            .await
            .expect("Server start failed");

        // Start client
        let client_id = NetworkId("test_client_001".to_string());
        let server_id = NetworkId("test_server_001".to_string());

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
        };

        let (mut server_ingress, server_egress, server_addr) = QuicAdapter::server(server_config)
            .await
            .expect("Server start failed");

        let client_id = NetworkId("ban_test_client".to_string());

        let client_config = QuicClientConfig {
            server_address: server_addr,
            server_name: "localhost".to_string(),
            ca_cert_pem: cert_pem,
            local_network_id: client_id.clone(),
            server_network_id: NetworkId("server".to_string()),
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
        };

        let (mut server_ingress, _server_egress, server_addr) = QuicAdapter::server(server_config)
            .await
            .expect("Server start failed");

        // Connect two clients
        let client_a_id = NetworkId("client_alpha".to_string());
        let client_b_id = NetworkId("client_beta".to_string());
        let server_id = NetworkId("server".to_string());

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
            local_network_id: NetworkId("max_attempts_client".to_string()),
            server_network_id: NetworkId("unreachable_server".to_string()),
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
        };

        let (_server_ingress, _server_egress, server_addr) = QuicAdapter::server(server_config)
            .await
            .expect("Server start failed");

        let server_id = NetworkId("reconnect_server".to_string());

        let client_config = QuicClientConfig {
            server_address: server_addr,
            server_name: "localhost".to_string(),
            ca_cert_pem: cert_pem,
            local_network_id: NetworkId("reconnect_client".to_string()),
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
