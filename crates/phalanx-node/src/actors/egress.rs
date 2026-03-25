use crate::clock::TrustedClock;
use crate::vitals::{Homeostasis, SystemGovernor};
use phalanx_proto::identity::{NetworkId, RecordingId};
use phalanx_proto::network::EgressPort;
use phalanx_proto::prelude::*;
use phalanx_proto::retrieval::RecordingRequest;
use phalanx_proto::storage::PendingEgress;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{interval, Duration, Instant};

pub enum EgressCommand {
    Dispatch {
        channel_id: String,
        response: RecordingResponse,
    },
    DrainForSalvage {
        reply_to: oneshot::Sender<Vec<PendingEgress>>,
    },
    AnnounceRecording(RecordingId),
    FindProviders(RecordingId),
    /// Send a shard retrieval request to a specific peer.
    RequestShards {
        target: NetworkId,
        request: RecordingRequest,
    },
    /// Eclipse remediation: actively disconnect a peer rejected or evicted by TopologyGate.
    DisconnectPeer(NetworkId),
    /// Eclipse remediation: re-dial bootstrap peers and trigger Kademlia random walk.
    ReBootstrap(Vec<String>),
}

pub struct EgressActor<E: EgressPort> {
    port: E,
    pending: VecDeque<PendingEgress>,
    rx: mpsc::Receiver<EgressCommand>,
    /// Connection pressure: queue depth feeds the c integral via record_connection_pressure.
    system_governor: Arc<SystemGovernor>,
    /// P7 FIX: Dedup window for DHT announces to prevent post-partition spam.
    /// Recordings announced in the current window are skipped. Window clears every 30s.
    announced: HashSet<RecordingId>,
    last_announce_clear: Instant,
    /// Trusted clock for forensic timestamps.
    clock: Arc<TrustedClock>,
}

/// DHT announce dedup window duration.
const ANNOUNCE_DEDUP_WINDOW: Duration = Duration::from_secs(30);

/// P11 FIX: Maximum pending retry queue size. When exceeded, oldest items
/// are shed to prevent unbounded memory growth during sustained transport failure.
const MAX_PENDING_RETRIES: usize = 64;

impl<E: EgressPort> EgressActor<E> {
    pub fn new(
        port: E,
        rx: mpsc::Receiver<EgressCommand>,
        salvaged: Vec<PendingEgress>,
        system_governor: Arc<SystemGovernor>,
        clock: Arc<TrustedClock>,
    ) -> Self {
        Self {
            port,
            pending: VecDeque::from(salvaged),
            rx,
            system_governor,
            announced: HashSet::new(),
            last_announce_clear: Instant::now(),
            clock,
        }
    }

    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Counter increments and duration arithmetic.
    pub async fn run(mut self) {
        let mut retry_tick = interval(Duration::from_millis(500));

        loop {
            tokio::select! {
                _ = retry_tick.tick() => {
                    self.process_pending().await;
                }
                Some(cmd) = self.rx.recv() => {
                    match cmd {
                        EgressCommand::Dispatch { channel_id, response } => {
                            self.dispatch(channel_id, response).await;
                        }
                        EgressCommand::DrainForSalvage { reply_to } => {
                            let _ = reply_to.send(self.pending.drain(..).collect());
                            break;
                        }
                        EgressCommand::AnnounceRecording(recording_id) => {
                            // P7 FIX: Dedup DHT announces within a 30s window.
                            // Prevents per-shard announce storms and post-partition spam.
                            let now = Instant::now();
                            if now.duration_since(self.last_announce_clear) > ANNOUNCE_DEDUP_WINDOW {
                                self.announced.clear();
                                self.last_announce_clear = now;
                            }
                            if !self.announced.insert(recording_id.clone()) {
                                tracing::debug!(
                                    recording = %recording_id,
                                    "DHT: Skipping duplicate announce (dedup window)"
                                );
                                continue;
                            }
                            if let Err(e) = self.port.announce_recording(&recording_id).await {
                                tracing::warn!(
                                    recording = %recording_id,
                                    error = %e,
                                    "DHT: Failed to announce recording"
                                );
                            }
                        }
                        EgressCommand::FindProviders(recording_id) => {
                            if let Err(e) = self.port.find_providers(&recording_id).await {
                                tracing::warn!(
                                    recording = %recording_id,
                                    error = %e,
                                    "DHT: Failed to query providers"
                                );
                            }
                        }
                        EgressCommand::RequestShards { target, request } => {
                            if let Err(e) = self.port.send_request(&target, request).await {
                                tracing::warn!(
                                    peer = %target,
                                    error = %e,
                                    "DHT: Failed to send shard request"
                                );
                            }
                        }
                        EgressCommand::DisconnectPeer(peer) => {
                            self.port.disconnect_peer(&peer).await;
                        }
                        EgressCommand::ReBootstrap(peers) => {
                            if let Err(e) = self.port.rebootstrap(&peers).await {
                                tracing::warn!(
                                    error = %e,
                                    "Eclipse: Re-bootstrap failed"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[allow(clippy::arithmetic_side_effects)] // Timestamp arithmetic for retry scheduling.
    async fn dispatch(&mut self, channel_id: String, response: RecordingResponse) {
        if self
            .port
            .send_response(&channel_id, response.clone())
            .await
            .is_err()
        {
            tracing::warn!(channel = %channel_id, "Response dispatch failed, queuing for retry");
            // P11 FIX: Shed oldest entries when queue exceeds cap.
            while self.pending.len() >= MAX_PENDING_RETRIES {
                if let Some(shed) = self.pending.pop_front() {
                    tracing::warn!(
                        channel = %shed.channel_id,
                        attempts = shed.attempt_count,
                        "Egress queue full, shedding oldest pending response"
                    );
                }
            }

            self.pending.push_back(PendingEgress {
                channel_id,
                response,
                attempt_count: 1,
                next_attempt: PhalanxTimestamp::from_millis(
                    self.clock.now().unwrap_or_default().0 + 1000,
                ),
            });
        }
    }

    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Retry backoff arithmetic.
    async fn process_pending(&mut self) {
        let now = self.clock.now().unwrap_or_default();
        let mut retry_queue = VecDeque::new();

        while let Some(mut pending) = self.pending.pop_front() {
            if pending.next_attempt > now {
                retry_queue.push_back(pending);
                continue;
            }

            // Try to resend
            if self
                .port
                .send_response(&pending.channel_id, pending.response.clone())
                .await
                .is_ok()
            {
                tracing::info!(channel = %pending.channel_id, "Redelivery successful");
            } else {
                pending.attempt_count += 1;
                if pending.attempt_count < 3 {
                    let delay = Duration::from_millis(500 * (2u64.pow(pending.attempt_count)));
                    pending.next_attempt =
                        PhalanxTimestamp::from_millis(now.0 + delay.as_millis() as u64);
                    retry_queue.push_back(pending);
                } else {
                    tracing::error!(
                        channel = %pending.channel_id,
                        attempts = pending.attempt_count,
                        "Egress response abandoned after max retries"
                    );
                }
            }
        }
        self.pending = retry_queue;

        // Connection pressure: queue depth reflects sustained dispatch failures.
        self.system_governor
            .record_connection_pressure(self.pending.len(), MAX_PENDING_RETRIES);
    }
}
