// crates/phalanx-transport/src/adapters/quic/client.rs
//
// Client actor: maintains a QUIC connection to a Stronghold server
// with automatic reconnection and exponential backoff.

use std::net::SocketAddr;
use std::time::Duration;

use phalanx_proto::identity::MeshAddress;
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::telemetry::DiscoverySource;
use phalanx_proto::topic::MeshTopic;
use phalanx_proto::topology::{SubnetBucket, TransportClass};
use tokio::sync::mpsc;

use super::wire::{QuicError, QuicWireMessage, read_frame, write_frame};
use super::{QuicCommand, translate_response};

// ── Backoff ──────────────────────────────────────────────────────────────

/// Compute exponential backoff delay.
///
/// Mirrors `OutboundQueue::backoff_delay()` from `phalanx-node/src/persistence/outbound.rs`.
/// Schedule with base=5, max=300: 5s → 10s → 20s → 40s → 80s → 160s → 300s → 300s…
pub(super) fn backoff_delay(attempt: u32, base_secs: u64, max_secs: u64) -> Duration {
    let delay = base_secs.saturating_mul(1u64 << attempt.min(6));
    Duration::from_secs(delay.min(max_secs))
}

/// Extract a `SubnetBucket` from a `SocketAddr`.
fn subnet_bucket_from_addr(addr: SocketAddr) -> SubnetBucket {
    match addr {
        SocketAddr::V4(v4) => {
            let octets = v4.ip().octets();
            SubnetBucket::from_ipv4_prefix(octets[0], octets[1])
        }
        SocketAddr::V6(v6) => {
            let octets = v6.ip().octets();
            SubnetBucket::from_ipv6_prefix(&octets[..6])
        }
    }
}

// ── Client Actor ─────────────────────────────────────────────────────────

/// Outcome of a single connect-identify-loop cycle.
enum CycleOutcome {
    /// Connection dropped — should reconnect after backoff.
    Reconnect,
    /// Egress channel closed — actor should stop entirely.
    EgressClosed,
}

/// Attempt a QUIC connection to the server.
///
/// On success, returns the connection and resets `attempt` to 0.
/// On failure, emits a PeerDisconnected event and returns `None`.
async fn attempt_connect(
    client: &s2n_quic::Client,
    server_address: SocketAddr,
    server_name: &str,
    attempt: &mut u32,
    server_network_id: &MeshAddress,
    event_tx: &mpsc::Sender<NetworkEvent>,
) -> Option<s2n_quic::Connection> {
    let connect = s2n_quic::client::Connect::new(server_address).with_server_name(server_name);

    match client.connect(connect).await {
        Ok(conn) => {
            *attempt = 0; // Reset on successful connect
            Some(conn)
        }
        Err(e) => {
            tracing::warn!(
                target: "phalanx::quic",
                error = %e,
                server = %server_address,
                attempt = *attempt,
                "Failed to connect to Stronghold"
            );

            // Emit disconnect event (server unreachable counts as "lost")
            let _ = event_tx
                .send(NetworkEvent::PeerDisconnected {
                    peer: server_network_id.clone(),
                })
                .await;

            None
        }
    }
}

/// Send an Identify message on a new bidirectional stream.
///
/// Returns `true` if identification succeeded, `false` otherwise.
async fn attempt_identify(
    connection: &mut s2n_quic::Connection,
    local_network_id: &MeshAddress,
) -> bool {
    match connection.open_bidirectional_stream().await {
        Ok(mut stream) => {
            let identify = QuicWireMessage::Identify {
                network_id: local_network_id.0.clone(),
                #[allow(clippy::cast_possible_truncation)] // Epoch millis fits in u64 for centuries
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
    }
}

/// Increment `attempt`, check against max, log and sleep for backoff.
///
/// Returns `true` if the actor should continue retrying, `false` if
/// `max_reconnect_attempts` was exceeded and the actor should stop.
async fn apply_backoff(
    attempt: &mut u32,
    max_reconnect_attempts: Option<u32>,
    base_backoff_secs: u64,
    max_backoff_secs: u64,
) -> bool {
    *attempt = attempt.saturating_add(1);
    if let Some(max) = max_reconnect_attempts {
        if *attempt > max {
            tracing::error!(
                target: "phalanx::quic",
                "Max reconnect attempts ({}) exceeded, giving up",
                max
            );
            return false;
        }
    }

    let delay = backoff_delay(*attempt, base_backoff_secs, max_backoff_secs);
    tracing::info!(
        target: "phalanx::quic",
        delay_secs = delay.as_secs(),
        attempt = *attempt,
        "Reconnecting after backoff"
    );
    tokio::time::sleep(delay).await;
    true
}

/// Run a single connect-identify-loop cycle.
///
/// Returns `CycleOutcome::Reconnect` if the connection dropped (should retry),
/// or `CycleOutcome::EgressClosed` if the egress channel was closed (should stop).
async fn run_connection_cycle(
    server_address: SocketAddr,
    local_network_id: &MeshAddress,
    server_network_id: &MeshAddress,
    event_tx: &mpsc::Sender<NetworkEvent>,
    command_rx: &mut mpsc::Receiver<QuicCommand>,
    mut connection: s2n_quic::Connection,
) -> CycleOutcome {
    tracing::info!(
        target: "phalanx::quic",
        server = %server_address,
        "Connected to Stronghold via QUIC"
    );

    // ── Identify ─────────────────────────────────────────────────
    if !attempt_identify(&mut connection, local_network_id).await {
        return CycleOutcome::Reconnect;
    }

    // ── Emit PeerDiscovered ──────────────────────────────────────
    let bucket = connection
        .remote_addr()
        .ok()
        .map(subnet_bucket_from_addr)
        .unwrap_or_else(|| subnet_bucket_from_addr(server_address));
    let _ = event_tx
        .send(NetworkEvent::PeerDiscovered {
            peer: server_network_id.clone(),
            source: DiscoverySource::Quic,
            bucket,
            transport: TransportClass::from_discovery_source(DiscoverySource::Quic),
        })
        .await;

    // ── Connection Loop ──────────────────────────────────────────
    let egress_closed = client_connection_loop(
        &mut connection,
        event_tx,
        command_rx,
        server_network_id,
        local_network_id,
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

    if egress_closed {
        tracing::info!(
            target: "phalanx::quic",
            "Egress channel closed, client actor stopping"
        );
        CycleOutcome::EgressClosed
    } else {
        CycleOutcome::Reconnect
    }
}

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
    local_network_id: MeshAddress,
    server_network_id: MeshAddress,
    max_reconnect_attempts: Option<u32>,
    base_backoff_secs: u64,
    max_backoff_secs: u64,
    event_tx: mpsc::Sender<NetworkEvent>,
    mut command_rx: mpsc::Receiver<QuicCommand>,
) {
    let mut attempt: u32 = 0;

    loop {
        // ── Connect ──────────────────────────────────────────────────
        let connection = match attempt_connect(
            &client,
            server_address,
            server_name.as_str(),
            &mut attempt,
            &server_network_id,
            &event_tx,
        )
        .await
        {
            Some(conn) => conn,
            None => {
                if !apply_backoff(
                    &mut attempt,
                    max_reconnect_attempts,
                    base_backoff_secs,
                    max_backoff_secs,
                )
                .await
                {
                    return;
                }
                continue;
            }
        };

        // ── Run Connection Cycle ─────────────────────────────────────
        let outcome = run_connection_cycle(
            server_address,
            &local_network_id,
            &server_network_id,
            &event_tx,
            &mut command_rx,
            connection,
        )
        .await;

        match outcome {
            CycleOutcome::EgressClosed => return,
            CycleOutcome::Reconnect => {
                // Backoff before reconnect
                if !apply_backoff(
                    &mut attempt,
                    max_reconnect_attempts,
                    base_backoff_secs,
                    max_backoff_secs,
                )
                .await
                {
                    return;
                }
            }
        }
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
    server_network_id: &MeshAddress,
    local_network_id: &MeshAddress,
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
    server_id: &MeshAddress,
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
    local_id: &MeshAddress,
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
