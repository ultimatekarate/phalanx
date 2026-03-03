use std::collections::HashSet;
use tracing::{debug, instrument};

// Dictionary Nouns
use crate::trust::TrustRegistry;
use crate::vitals::HealthTracker;
use crate::Guardian;
use crate::NodeConfig;
use phalanx_forensics::prelude::TransientJournal;

use phalanx_forensics::Reassembler;
use phalanx_forensics::TrafficGovernor;
use phalanx_proto::prelude::*;
use phalanx_proto::trust::Offense;
use phalanx_proto::types::NodeMode;

pub struct IngressContext<'a> {
    pub config: &'a NodeConfig,
    pub identity: &'a PhalanxIdentity,
    pub network_id: NetworkId,
    pub clock: &'a dyn TrustedClock,
    pub governor: &'a TrafficGovernor,
    pub mode: NodeMode,
}

pub struct SecurityPipeline<'a, J: TransientJournal> {
    pub reassembler: &'a mut Reassembler,
    pub journal: &'a mut J,
    pub guardian: &'a mut Guardian,
    pub trust_registry: &'a mut TrustRegistry,
    pub health_tracker: &'a mut HealthTracker,
    // Deduplication gate
    pub seen_cache: &'a mut HashSet<(ShardId, u32)>,
}

#[derive(Debug, thiserror::Error)]
pub enum IngressError {
    #[error("Peer is blacklisted: {0}")]
    Blacklisted(Did),

    #[error("Traffic rejected by Governor")]
    Throttled,

    #[error("Reassembler rejected chunk: {0}")]
    ReassemblerRejected(#[from] ShardError),

    #[error("Guardian rejected envelope: {0}")]
    GuardianRejected(#[from] GuardianError),
}

pub struct IngressOrchestrator;

impl IngressOrchestrator {
    #[instrument(skip(pipeline, ctx, chunk), level = "info")]
    pub async fn process_chunk<J: TransientJournal>(
        chunk: ShardChunk,
        topic: &MeshTopic,
        ctx: &IngressContext<'_>,
        pipeline: &mut SecurityPipeline<'_, J>,
    ) -> Result<Option<()>, IngressError> {
        let sender_did = chunk.owner_did.clone();
        let chunk_id = (chunk.shard_id, chunk.chunk_index);

        // 1. DEDUPLICATION GATE
        if !pipeline.seen_cache.insert(chunk_id) {
            debug!(?chunk_id, "Ingress: Dropping duplicate chunk.");
            return Ok(None);
        }

        // 2. TRUST GATE
        let trust_level = pipeline.trust_registry.check_trust(&sender_did);
        if matches!(trust_level, TrustLevel::Blocked) {
            return Err(IngressError::Blacklisted(sender_did));
        }

        // 3. REASSEMBLY PHASE
        match pipeline
            .reassembler
            .ingest_chunk(chunk, pipeline.journal)
            .await
        {
            Ok(Some(state)) => {
                // 4. GUARDIAN PHASE
                // ingest_envelope now expects the full EnvelopeState (Intact or Fragmented)
                match pipeline.guardian.ingest_envelope(state).await {
                    Ok(_) => Ok(Some(())),
                    Err(guardian_error) => {
                        Self::report_offense(&sender_did, &guardian_error, ctx, pipeline).await;
                        Err(IngressError::GuardianRejected(guardian_error))
                    }
                }
            }
            Ok(None) => Ok(None),
            Err(shard_error) => Err(IngressError::ReassemblerRejected(shard_error)),
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
