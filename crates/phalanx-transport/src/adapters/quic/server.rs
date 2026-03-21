// crates/phalanx-transport/src/adapters/quic/server.rs
//
// Server actor: accepts QUIC connections from phones, routes commands to clients.
// Runs as a detached tokio task in Stronghold mode.

use std::sync::Arc;

use phalanx_proto::identity::NetworkId;
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::telemetry::DiscoverySource;
use phalanx_proto::topic::MeshTopic;
use tokio::sync::{mpsc, RwLock};

use super::wire::{read_frame, write_frame, QuicWireMessage};
use super::{translate_response, ConnectionMap, QuicCommand};

// ── Server Actor ─────────────────────────────────────────────────────────

/// Server actor: accepts connections, routes commands to connected clients.
///
/// Runs as a detached tokio task. The server accepts incoming QUIC connections,
/// spawns a handler per connection, and routes outbound commands from the
/// QuicEgress to the appropriate connection handler via the shared connection map.
pub(super) async fn server_actor(
    mut server: s2n_quic::Server,
    event_tx: mpsc::Sender<NetworkEvent>,
    mut command_rx: mpsc::Receiver<QuicCommand>,
    max_connections: usize,
) {
    let connections: ConnectionMap = Arc::new(RwLock::new(std::collections::HashMap::new()));

    loop {
        tokio::select! {
            maybe_conn = server.accept() => {
                match maybe_conn {
                    Some(connection) => {
                        // P6 FIX: Enforce connection limit to prevent connection-flood DoS.
                        let current = connections.read().await.len();
                        if current >= max_connections {
                            tracing::warn!(
                                target: "phalanx::quic",
                                current,
                                max = max_connections,
                                "Connection limit reached, dropping new connection"
                            );
                            drop(connection);
                            continue;
                        }
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
pub(super) fn extract_network_id_from_channel(channel_id: &str) -> String {
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
    // P5 FIX: Verify timestamp freshness to prevent replay of captured Identify frames.
    let network_id = match connection.accept_bidirectional_stream().await {
        Ok(Some(mut stream)) => match read_frame(&mut stream).await {
            Ok(QuicWireMessage::Identify {
                network_id,
                timestamp_ms,
            }) => {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let age_ms = now_ms.saturating_sub(timestamp_ms);
                if age_ms > 30_000 {
                    tracing::warn!(
                        target: "phalanx::quic",
                        claimed_id = %network_id,
                        age_ms,
                        "Identify timestamp too old (>30s), rejecting"
                    );
                    return;
                }
                NetworkId(network_id)
            }
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
