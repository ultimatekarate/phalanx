use crate::actors::shutdown::ShutdownSignal;
use crate::clock::TrustedClock;
use crate::vitals::{Homeostasis, SystemGovernor};
use phalanx_proto::archive::ArchiveRequest;
use phalanx_proto::identity::{MeshAddress, RecordingId};
use phalanx_proto::kademlia::DhtPayload;
use phalanx_proto::network::EgressPort;
use phalanx_proto::prelude::*;
use phalanx_proto::retrieval::RecordingRequest;
use phalanx_proto::revocation::RevocationToken;
use phalanx_proto::storage::PendingEgress;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, Instant, interval};

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
        target: MeshAddress,
        request: RecordingRequest,
    },
    /// Directed archive PUSH of a recording to a Stronghold custody peer.
    PushArchive {
        target: MeshAddress,
        request: ArchiveRequest,
    },
    /// Eclipse remediation: actively disconnect a peer rejected or evicted by TopologyGate.
    DisconnectPeer(MeshAddress),
    /// Eclipse remediation: re-dial bootstrap peers and trigger Kademlia random walk.
    ReBootstrap(Vec<String>),
    /// Cryptographic Forgetting: publish a revocation token to the gossipsub topic.
    PublishRevocation(RevocationToken),
    /// Cryptographic Forgetting: remove local provider records for a revoked recording.
    WithdrawProvider(RecordingId),
    /// Cryptographic Forgetting: publish a DHT tombstone for a revoked recording.
    AnnounceTombstone(RecordingId, DhtPayload),
    /// Silent Canary / Heartbeat: publish an encrypted blob on a mesh-style
    /// topic. The payload is opaque to the EgressActor — the publisher (e.g.
    /// `MeshSentinel::broadcast_canary_alert`, `vitals_handle` heartbeat
    /// loop) handles community-key derivation and ChaCha20-Poly1305
    /// encryption upstream.
    PublishMesh {
        topic: phalanx_proto::topic::MeshTopic,
        data: Vec<u8>,
    },
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
    /// Shared cancellation signal. The run loop's select! polls this arm with
    /// `biased;` priority so cancel wins deterministically at shutdown.
    shutdown: Arc<ShutdownSignal>,
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
        shutdown: Arc<ShutdownSignal>,
    ) -> Self {
        Self {
            port,
            pending: VecDeque::from(salvaged),
            rx,
            system_governor,
            announced: HashSet::new(),
            last_announce_clear: Instant::now(),
            clock,
            shutdown,
        }
    }

    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Counter increments and duration arithmetic.
    pub async fn run(mut self) {
        let mut retry_tick = interval(Duration::from_millis(500));

        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => break,
                Some(cmd) = self.rx.recv() => {
                    if self.handle_command(cmd).await {
                        break;
                    }
                }
                _ = retry_tick.tick() => {
                    self.process_pending().await;
                }
            }
        }

        // Post-loop drain: process any queued commands — notably
        // DrainForSalvage from MeshSentinel::handle_shutdown — so the
        // salvage contract still completes after cancellation fires.
        while let Ok(cmd) = self.rx.try_recv() {
            if self.handle_command(cmd).await {
                break;
            }
        }
    }

    // ── Command Handlers ────────────────────────────────────────────────

    /// Dispatches a single egress command. Returns `true` if the run loop should exit.
    #[allow(
        clippy::arithmetic_side_effects, // Dedup window duration arithmetic.
        clippy::cognitive_complexity     // Flat dispatch on a wire-format enum.
    )]
    async fn handle_command(&mut self, cmd: EgressCommand) -> bool {
        match cmd {
            EgressCommand::Dispatch {
                channel_id,
                response,
            } => {
                self.dispatch(channel_id, response).await;
            }
            EgressCommand::DrainForSalvage { reply_to } => {
                let _ = reply_to.send(self.pending.drain(..).collect());
                return true;
            }
            EgressCommand::AnnounceRecording(recording_id) => {
                self.handle_announce(recording_id).await;
            }
            EgressCommand::FindProviders(recording_id) => {
                self.handle_find_providers(recording_id).await;
            }
            EgressCommand::RequestShards { target, request } => {
                self.handle_request_shards(target, request).await;
            }
            EgressCommand::PushArchive { target, request } => {
                if let Err(e) = self.port.send_archive_request(&target, request).await {
                    tracing::warn!(
                        peer = %target,
                        error = %e,
                        "Archive: failed to push recording to custody peer"
                    );
                }
            }
            EgressCommand::DisconnectPeer(peer) => {
                self.port.disconnect_peer(&peer).await;
            }
            EgressCommand::ReBootstrap(peers) => {
                self.handle_rebootstrap(peers).await;
            }
            EgressCommand::PublishRevocation(token) => {
                if let Err(e) = self.port.publish_revocation(&token).await {
                    tracing::warn!(
                        recording = %token.recording_id,
                        error = %e,
                        "Failed to publish revocation token"
                    );
                }
            }
            EgressCommand::WithdrawProvider(recording_id) => {
                if let Err(e) = self.port.withdraw_provider(&recording_id).await {
                    tracing::warn!(
                        recording = %recording_id,
                        error = %e,
                        "Failed to withdraw provider record"
                    );
                }
            }
            EgressCommand::AnnounceTombstone(recording_id, payload) => {
                // Publish the tombstone to the DHT keyed by the RecordingId
                let data = postcard::to_allocvec(&payload).unwrap_or_default();
                let topic = phalanx_proto::topic::MeshTopic::revocation();
                if let Err(e) = self.port.publish(&topic, data).await {
                    tracing::warn!(
                        recording = %recording_id,
                        error = %e,
                        "Failed to announce DHT tombstone"
                    );
                }
            }
            EgressCommand::PublishMesh { topic, data } => {
                if let Err(e) = self.port.publish(&topic, data).await {
                    tracing::warn!(
                        topic = %topic,
                        error = %e,
                        "Failed to publish mesh message"
                    );
                }
            }
        }
        false
    }

    /// P7 FIX: Dedup DHT announces within a 30s window.
    /// Prevents per-shard announce storms and post-partition spam.
    async fn handle_announce(&mut self, recording_id: RecordingId) {
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
            return;
        }
        if let Err(e) = self.port.announce_recording(&recording_id).await {
            tracing::warn!(
                recording = %recording_id,
                error = %e,
                "DHT: Failed to announce recording"
            );
        }
    }

    async fn handle_find_providers(&mut self, recording_id: RecordingId) {
        if let Err(e) = self.port.find_providers(&recording_id).await {
            tracing::warn!(
                recording = %recording_id,
                error = %e,
                "DHT: Failed to query providers"
            );
        }
    }

    async fn handle_request_shards(&mut self, target: MeshAddress, request: RecordingRequest) {
        if let Err(e) = self.port.send_request(&target, request).await {
            tracing::warn!(
                peer = %target,
                error = %e,
                "DHT: Failed to send shard request"
            );
        }
    }

    async fn handle_rebootstrap(&mut self, peers: Vec<String>) {
        if let Err(e) = self.port.rebootstrap(&peers).await {
            tracing::warn!(
                error = %e,
                "Eclipse: Re-bootstrap failed"
            );
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
