use crate::base::config::PhalanxConfig;
use crate::base::types::{MeshTopic, NodeMode, TrafficGovernor};
use crate::primitives::identity::{Did, NetworkId, PhalanxIdentity};
use crate::primitives::shards::{ShardChunk, ShardError};
use crate::primitives::time::TrustedClock;
use crate::security::trust::{Offense, TrustLevel, TrustRegistry};
use crate::storage::reassembler::{Reassembler, TransientJournal};
use crate::storage::vault::{Guardian, GuardianError};
use crate::transport::health::HealthTracker;

pub struct IngressContext<'a> {
    pub config: &'a PhalanxConfig,
    pub identity: &'a PhalanxIdentity,
    pub network_id: NetworkId,
    pub clock: &'a TrustedClock,
    pub governor: &'a TrafficGovernor,
    pub mode: NodeMode,
}

pub struct SecurityPipeline<'a, J: TransientJournal> {
    pub reassembler: &'a mut Reassembler,
    pub journal: &'a mut J,
    pub guardian: &'a mut Guardian,
    pub trust_registry: &'a mut TrustRegistry,
    pub health_tracker: &'a mut HealthTracker,
}

#[derive(Debug, thiserror::Error)]
pub enum IngressError {
    #[error("Peer is blacklisted: {0}")]
    Blacklisted(Did),

    #[error("Traffic rejected by Governor")]
    Throttled,

    #[error("Reassembler rejected payload: {0}")]
    ReassemblerRejected(#[from] ShardError),

    #[error("Guardian rejected payload: {0}")]
    GuardianRejected(#[from] GuardianError),
}

pub struct IngressOrchestrator;

impl IngressOrchestrator {
    pub async fn process_chunk<J: TransientJournal>(
        chunk: ShardChunk,
        topic: &MeshTopic,
        ctx: &IngressContext<'_>,
        pipeline: &mut SecurityPipeline<'_, J>,
    ) -> Result<Option<()>, IngressError> {
        let sender_did = chunk.owner_did.clone();

        // 3. Trust Gate: Check reputation
        let trust_level = pipeline.trust_registry.check_trust(&sender_did);
        if matches!(trust_level, TrustLevel::Blocked) {
            return Err(IngressError::Blacklisted(sender_did));
        }

        // 4. Reassembly Phase
        // Utilizing your existing `process_chunk` which currently handles WAL internally.
        match pipeline
            .reassembler
            .ingest_chunk(
                chunk,
                pipeline.journal,
                topic,
                ctx.config,
                ctx.identity,
                ctx.network_id,
            )
            .await
        {
            Ok(Some(envelope)) => {
                // 5. Finalization Phase (Archival)
                match pipeline.guardian.ingest_envelope(envelope).await {
                    Ok(_) => Ok(Some(())),
                    Err(guardian_error) => {
                        Self::report_offense(&sender_did, &guardian_error, ctx, pipeline).await;
                        Err(IngressError::GuardianRejected(guardian_error))
                    }
                }
            }
            Ok(None) => Ok(None), // Reassembly ongoing
            Err(shard_error) => {
                // Map shard errors to reputation offenses
                Err(IngressError::ReassemblerRejected(shard_error))
            }
        }
    }

    async fn report_offense<J: TransientJournal>(
        did: &Did,
        error: &GuardianError,
        ctx: &IngressContext<'_>,
        pipeline: &mut SecurityPipeline<'_, J>,
    ) {
        let offense = match error {
            GuardianError::InvalidSignature(_) => Some(Offense::InvalidSignature),
            GuardianError::QuotaExceeded(_) => Some(Offense::QuotaExceeded),
            _ => None,
        };

        if let Some(offense) = offense {
            pipeline
                .trust_registry
                .record_offense(did, offense, ctx.clock)
                .await;
        }
    }
}
