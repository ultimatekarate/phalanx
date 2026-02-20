use crate::base::config::PhalanxConfig;
use crate::base::types::MeshTopic;
use crate::primitives::identity::{Did, NetworkId, PhalanxIdentity};
use crate::primitives::shards::{ShardChunk, ShardError};
use crate::primitives::time::TrustedClock;
use crate::security::sentinel::Sentinel;
use crate::security::trust::{Offense, ReputationGate, TrustRegistry};
use crate::storage::vault::{Guardian, GuardianError};

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
    /// Intercepts stateless errors, maps them to offenses, and mutates the TrustRegistry.
    pub async fn process_chunk(
        chunk: ShardChunk,
        topic: &MeshTopic,
        config: &PhalanxConfig,
        identity: &PhalanxIdentity,
        local_network_id: NetworkId,
        sentinel: &mut Sentinel,
        guardian: &mut Guardian,
        trust_registry: &mut TrustRegistry,
        clock: &TrustedClock,
    ) -> Result<Option<u64>, IngressError> {
        let sender_did = chunk.owner_did.clone();
        let payload_size = chunk.data.len() as u64;

        // 1. Preemptive Gating
        if trust_registry.is_blacklisted(&sender_did) {
            return Err(IngressError::Blacklisted(sender_did));
        }

        // 2. Transient Validation (Sentinel)
        match sentinel.process_chunk(chunk, topic, config, identity, local_network_id) {
            Ok(Some(envelope)) => {
                // 3. Persistent Validation (Guardian)
                match guardian.ingest_envelope(envelope) {
                    Ok(_) => Ok(Some(payload_size)),
                    Err(guardian_error) => {
                        let mapped_offense = match &guardian_error {
                            GuardianError::InvalidSignature(_) => Some(Offense::InvalidSignature),
                            GuardianError::ReplayDetected(_) => Some(Offense::ReplayAttack),
                            GuardianError::QuotaExceeded(_) => Some(Offense::QuotaExceeded),
                            _ => None,
                        };

                        if let Some(offense) = mapped_offense {
                            trust_registry
                                .record_offense(&sender_did, offense, clock)
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
                    trust_registry
                        .record_offense(&sender_did, offense, clock)
                        .await;
                }

                Err(IngressError::SentinelRejected(shard_error))
            }
        }
    }
}
