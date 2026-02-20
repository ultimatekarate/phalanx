use crate::base::config::PhalanxConfig;
use crate::base::types::MeshTopic;
use crate::primitives::identity::{Did, NetworkId, PhalanxIdentity};
use crate::primitives::shards::{ShardChunk, ShardError};
use crate::primitives::time::TrustedClock;
use crate::security::sentinel::Sentinel;
use crate::security::trust::{Offense, ReputationGate, TrustRegistry};
use crate::storage::vault::{Guardian, GuardianError};

pub struct IngressContext<'a> {
    pub config: &'a PhalanxConfig,
    pub identity: &'a PhalanxIdentity,
    pub network_id: NetworkId,
    pub clock: &'a TrustedClock,
}

pub struct SecurityPipeline<'a> {
    pub sentinel: &'a mut Sentinel,
    pub guardian: &'a mut Guardian,
    pub trust_registry: &'a mut TrustRegistry,
}

#[derive(Debug, thiserror::Error)]
pub enum IngressError {
    #[error("Peer is blacklisted: {0}")]
    Blacklisted(Did),

    #[error("Sentinel rejected payload: {0}")]
    SentinelRejected(#[from] ShardError),

    #[error("Guardian rejected payload: {0}")]
    GuardianRejected(#[from] GuardianError),
}

pub struct IngressOrchestrator;

impl IngressOrchestrator {
    /// Unifies the ingress pipeline for both PhalanxEngine and SimNode.
    pub async fn process_chunk(
        chunk: ShardChunk,
        topic: &MeshTopic,
        ctx: &IngressContext<'_>,
        pipeline: &mut SecurityPipeline<'_>,
    ) -> Result<Option<u64>, IngressError> {
        let sender_did = chunk.owner_did.clone();
        let payload_size = chunk.data.len() as u64;

        // 1. Preemptive Gating
        if pipeline.trust_registry.is_blacklisted(&sender_did) {
            return Err(IngressError::Blacklisted(sender_did));
        }

        // 2. Transient Validation (Sentinel)
        match pipeline.sentinel.process_chunk(
            chunk,
            topic,
            ctx.config,
            ctx.identity,
            ctx.network_id,
        ).await {
            Ok(Some(envelope)) => {
                // 3. Persistent Validation (Guardian)
                match pipeline.guardian.ingest_envelope(envelope) {
                    Ok(_) => Ok(Some(payload_size)),
                    Err(guardian_error) => {
                        let mapped_offense = match &guardian_error {
                            GuardianError::InvalidSignature(_) => Some(Offense::InvalidSignature),
                            GuardianError::ReplayDetected(_) => Some(Offense::ReplayAttack),
                            GuardianError::QuotaExceeded(_) => Some(Offense::QuotaExceeded),
                            _ => None,
                        };

                        if let Some(offense) = mapped_offense {
                            pipeline
                                .trust_registry
                                .record_offense(&sender_did, offense, ctx.clock)
                                .await;
                        }

                        Err(IngressError::GuardianRejected(guardian_error))
                    }
                }
            }
            Ok(None) => Ok(None), // Benign: Reassembly is ongoing
            Err(shard_error) => {
                let mapped_offense = match &shard_error {
                    ShardError::SigningError(_) => Some(Offense::InvalidSignature),
                    ShardError::CapacityExceeded(_) => Some(Offense::QuotaExceeded),
                    ShardError::InvalidConfiguration(_)
                    | ShardError::Serialization(_)
                    | ShardError::Encryption(_) => Some(Offense::MalformedPacket),
                    _ => None,
                };

                if let Some(offense) = mapped_offense {
                    pipeline
                        .trust_registry
                        .record_offense(&sender_did, offense, ctx.clock)
                        .await;
                }

                Err(IngressError::SentinelRejected(shard_error))
            }
        }
    }
}
