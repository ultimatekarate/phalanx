use crate::actors::egress::EgressCommand;
use crate::actors::storage::StorageCommand;
use crate::actors::trust_actor::TrustCommand;
use crate::clock::TrustedClock;
use crate::identity::PhalanxNodeIdentityExt;
use crate::trust::{ReputationProjection, TrustOracle};
use crate::vitals::Homeostasis;
use crate::vitals::{FinalizationScale, SystemGovernor};
use phalanx_forensics::crucible::EvidenceExt;
use phalanx_forensics::gate::IntegrityGate;
use phalanx_forensics::policy::EgressGovernor;
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::prelude::*;
use phalanx_proto::trust::Offense;
use phalanx_proto::types::{ForensicUnit, TaskCost, Verified};
use phalanx_proto::RecordingRequest;
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};
// Command for the RetrievalActor itself
pub enum RetrievalCommand {
    SecureRetrieval {
        origin: NetworkId,
        request: RecordingRequest,
        channel_id: String,
    },
}

pub struct RetrievalActor {
    identity: Arc<PhalanxIdentity>,
    clock: Arc<TrustedClock>,
    system_governor: Arc<SystemGovernor>,
    storage_tx: mpsc::Sender<StorageCommand>,
    egress_tx: mpsc::Sender<EgressCommand>,
    trust_oracle: ReputationProjection,   // For reads
    trust_tx: mpsc::Sender<TrustCommand>, // For writes
    network_key: Arc<SymmetricKey>,
    rx: mpsc::Receiver<RetrievalCommand>,
}

impl RetrievalActor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: Arc<PhalanxIdentity>,
        clock: Arc<TrustedClock>,
        system_governor: Arc<SystemGovernor>,
        storage_tx: mpsc::Sender<StorageCommand>,
        egress_tx: mpsc::Sender<EgressCommand>,
        trust_oracle: ReputationProjection,
        trust_tx: mpsc::Sender<TrustCommand>,
        network_key: Arc<SymmetricKey>,
        rx: mpsc::Receiver<RetrievalCommand>,
    ) -> Self {
        Self {
            identity,
            clock,
            system_governor,
            storage_tx,
            egress_tx,
            trust_oracle,
            trust_tx,
            network_key,
            rx,
        }
    }

    pub async fn run(mut self) {
        while let Some(cmd) = self.rx.recv().await {
            match cmd {
                RetrievalCommand::SecureRetrieval {
                    origin,
                    request,
                    channel_id,
                } => {
                    self.execute_secure_retrieval(origin, request, channel_id)
                        .await;
                }
            }
        }
    }

    async fn execute_secure_retrieval(
        &mut self,
        origin: NetworkId,
        request: RecordingRequest,
        channel_id: String,
    ) {
        let local_id = &self.identity.network_id;
        let io_scale: FinalizationScale = self.system_governor.finalization_scaler();

        if io_scale.0 < 0.2 {
            tracing::warn!(
                target: "phalanx::retrieval",
                io_scale = io_scale.0,
                peer = %origin,
                "I/O Digestion integral saturated. Sending Busy response."
            );
            // P8 FIX: Send Busy response instead of silent drop so the requesting
            // peer knows to retry later rather than waiting indefinitely.
            self.dispatch_resilient_response(channel_id, RecordingResponse::Busy)
                .await;
            return;
        }

        if !self.system_governor.check_permission(TaskCost::Heavy) {
            tracing::warn!(target: "phalanx::egress", "Retrieval rejected: System thermal/battery limits exceeded");
            self.dispatch_resilient_response(channel_id, RecordingResponse::Unauthorized)
                .await;
            return;
        }

        if PhalanxNodeIdentityExt::verify_retrieval_auth(&*self.identity, &request).is_err() {
            tracing::warn!(peer = %origin, recording = %request.recording_id, "Privacy Gate: Unauthorized retrieval attempt blocked");
            let _ = self
                .trust_tx
                .send(TrustCommand::RecordOffense {
                    did: request.target_did.clone(),
                    offense: Offense::InvalidSignature,
                })
                .await;
            self.dispatch_resilient_response(channel_id, RecordingResponse::Unauthorized)
                .await;
            return;
        }

        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .storage_tx
            .send(StorageCommand::Retrieval {
                recording_id: request.recording_id.clone(),
                owner_did: Some(request.target_did.clone()),
                reply_to: reply_tx,
            })
            .await
            .is_err()
        {
            self.dispatch_resilient_response(channel_id, RecordingResponse::NotFound)
                .await;
            return;
        }

        let io_start = tokio::time::Instant::now();
        let raw_envelopes = reply_rx.await.unwrap_or_default();
        self.system_governor.record_io_pressure(io_start.elapsed());

        let mut sealed_units = Vec::new();
        let current_stress = self.system_governor.current_stress();
        let target_trust = self.trust_oracle.check_trust_by_did(&request.target_did);

        for env in raw_envelopes {
            let sequence_id = env.evidence.sequence_id();
            if let Ok(valid_env) = env.check_integrity(
                local_id,
                &*self.clock,
                std::time::Duration::from_millis(10_000),
                None,
            ) {
                let unit = ForensicUnit::<WitnessEnvelope, Verified>::new_verified(valid_env);
                if let Ok(sealed) = EgressGovernor::authorize(
                    unit,
                    &target_trust,
                    &current_stress,
                    &self.network_key,
                ) {
                    sealed_units.push(sealed);
                } else {
                    tracing::warn!(seq = %sequence_id, "Egress denied by policy");
                }
            } else {
                tracing::error!(seq = %sequence_id, "CRITICAL: Integrity validation failed for local vault data");
            }
        }

        let response = if sealed_units.is_empty() {
            RecordingResponse::NotFound
        } else {
            RecordingResponse::Success(sealed_units)
        };
        self.dispatch_resilient_response(channel_id, response).await;
    }

    async fn dispatch_resilient_response(
        &mut self,
        channel_id: String,
        response: RecordingResponse,
    ) {
        let _ = self
            .egress_tx
            .send(EgressCommand::Dispatch {
                channel_id,
                response,
            })
            .await;
    }
}
