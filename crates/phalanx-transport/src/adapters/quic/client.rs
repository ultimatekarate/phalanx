// crates/phalanx-transport/src/adapters/quic/client.rs
//
// Client actor: maintains a QUIC connection to a Stronghold server
// with automatic reconnection and exponential backoff.

use std::net::SocketAddr;
use std::time::Duration;

use phalanx_proto::identity::NetworkId;
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::telemetry::DiscoverySource;
use phalanx_proto::topic::MeshTopic;
use tokio::sync::mpsc;

use super::wire::{read_frame, write_frame, QuicError, QuicWireMessage};
use super::{translate_response, QuicCommand};

// ── Backoff ──────────────────────────────────────────────────────────────

/// Compute exponential backoff delay.
///
/// Mirrors `OutboundQueue::backoff_delay()` from `phalanx-node/src/persistence/outbound.rs`.
/// Schedule with base=5, max=300: 5s → 10s → 20s → 40s → 80s → 160s → 300s → 300s…
pub(super) fn backoff_delay(attempt: u32, base_secs: u64, max_secs: u64) -> Duration {
    let delay = base_secs.saturating_mul(1u64 << attempt.min(6));
    Duration::from_secs(delay.min(max_secs))
}

// ── Client Actor ─────────────────────────────────────────────────────────

/// Client actor: maintains a QUIC connection to a Stronghold server with
/// automatic reconnection and exponential backoff.
///
/// Outer loop: connect → identify → inner loop → disconnect → backoff → retry.
/// The `event_tx` and `command_rx` channels survive across reconnects.
#[allow(clippy::too_many_arguments)]
pub(super) async fn client_actor(
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
                    timestamp_ms: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
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
