use phalanx_proto::identity::{NetworkId, RecordingId};
use phalanx_proto::prelude::*;
use phalanx_proto::retrieval::RecordingRequest;
use phalanx_transport::EgressPort;
use std::collections::VecDeque;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{interval, Duration};

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
}

pub struct EgressActor<E: EgressPort> {
    port: E,
    pending: VecDeque<PendingEgress>,
    rx: mpsc::Receiver<EgressCommand>,
}

impl<E: EgressPort> EgressActor<E> {
    pub fn new(port: E, rx: mpsc::Receiver<EgressCommand>, salvaged: Vec<PendingEgress>) -> Self {
        Self {
            port,
            pending: VecDeque::from(salvaged),
            rx,
        }
    }

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
                    }
                }
            }
        }
    }

    async fn dispatch(&mut self, channel_id: String, response: RecordingResponse) {
        if self
            .port
            .send_response(&channel_id, response.clone())
            .await
            .is_err()
        {
            tracing::warn!(channel = %channel_id, "Response dispatch failed, queuing for retry");
            self.pending.push_back(PendingEgress {
                channel_id,
                response,
                attempt_count: 1,
                next_attempt: PhalanxTimestamp::from_millis(PhalanxTimestamp::now().0 + 1000),
            });
        }
    }

    async fn process_pending(&mut self) {
        let now = PhalanxTimestamp::now();
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
                }
            }
        }
        self.pending = retry_queue;
    }
}
