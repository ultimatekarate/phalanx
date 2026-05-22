// crates/phalanx-stronghold/src/actors/aggregation.rs
//
// AggregationActor: receives ShardChunks from the mesh, reassembles via
// dual Crucible pipeline, stores encrypted recordings by community.
// Never decrypts — grants are provided at corroboration time.
//
// Hands layer. Owns Crucible<ShardMold> and Crucible<RecordingAmalgam>.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use phalanx_forensics::bloom::RotatingBloomFilter;
use phalanx_forensics::crucible::{Crucible, RecordingAmalgam};
use phalanx_forensics::gate::PromotionGate;
use phalanx_forensics::reassembler::ShardMold;
use phalanx_forensics::unit::ForensicUnit;
use phalanx_proto::community::CommunityId;
use phalanx_proto::corroboration::ProximityWitness;
use phalanx_proto::evidence::{Evidence, Recording};
use phalanx_proto::identity::{Did, RecordingId};
use phalanx_proto::prelude::ShardChunk;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::error::StrongholdError;
use crate::governor::StrongholdGovernor;
use crate::persistence::evidence_store::EvidenceStore;
use phalanx_forensics::policy::Homeostasis;

// ── Constants ────────────────────────────────────────────────────────────

/// Crucible capacity for the Stronghold (server-grade). Much larger than
/// the phone's 1,000 — a Stronghold aggregates for many peers.
const SHARD_CRUCIBLE_CAPACITY: usize = 100_000;

/// Recording amalgam capacity: how many concurrent recording assemblies.
const RECORDING_CRUCIBLE_CAPACITY: usize = 100_000;

/// Stale context TTL: contexts untouched for this long are flushed.
const STALE_TTL: Duration = Duration::from_secs(300);

/// Maintenance tick interval for stale flushing and bloom rotation.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(30);

// ── Command ──────────────────────────────────────────────────────────────

pub enum AggregationCommand {
    IngestChunk {
        chunk: ShardChunk,
    },
    FetchRecordings {
        community_id: CommunityId,
        recording_ids: Vec<RecordingId>,
        reply_to: oneshot::Sender<Result<Vec<Recording>, StrongholdError>>,
    },
    FetchProximity {
        community_id: CommunityId,
        reply_to: oneshot::Sender<Result<Vec<ProximityWitness>, StrongholdError>>,
    },
    /// Refresh the community routing cache from CommunityActor.
    RefreshRouting {
        routing: HashMap<Did, Vec<CommunityId>>,
    },
    /// Cryptographic Forgetting: destroy all evidence for a recording.
    Revoke {
        recording_id: RecordingId,
    },
}

// ── Actor ────────────────────────────────────────────────────────────────

pub struct AggregationActor {
    shard_crucible: Crucible<ShardMold>,
    recording_crucible: Crucible<RecordingAmalgam>,
    evidence_store: EvidenceStore,
    community_routing: HashMap<Did, Vec<CommunityId>>,
    governor: Arc<StrongholdGovernor>,
    replay_filter: RotatingBloomFilter,
    proximity_log: Vec<ProximityWitness>,
    rx: mpsc::Receiver<AggregationCommand>,
}

impl AggregationActor {
    pub fn new(
        evidence_store: EvidenceStore,
        governor: Arc<StrongholdGovernor>,
        rx: mpsc::Receiver<AggregationCommand>,
    ) -> Self {
        Self {
            shard_crucible: Crucible::new(
                ShardMold,
                Duration::from_secs(1),
                SHARD_CRUCIBLE_CAPACITY,
            ),
            recording_crucible: Crucible::new(
                RecordingAmalgam,
                Duration::from_secs(1),
                RECORDING_CRUCIBLE_CAPACITY,
            ),
            evidence_store,
            community_routing: HashMap::new(),
            governor,
            replay_filter: RotatingBloomFilter::new(RotatingBloomFilter::DEFAULT_CAPACITY),
            proximity_log: Vec::new(),
            rx,
        }
    }

    /// Run the actor loop. Returns when the channel is closed.
    pub async fn run(mut self) {
        info!("AggregationActor: entering run loop");

        let mut maintenance = tokio::time::interval(MAINTENANCE_INTERVAL);

        loop {
            tokio::select! {
                cmd = self.rx.recv() => {
                    match cmd {
                        Some(command) => self.handle(command).await,
                        None => {
                            info!("AggregationActor: channel closed, shutting down");
                            break;
                        }
                    }
                }
                _ = maintenance.tick() => {
                    self.perform_maintenance();
                }
            }
        }
    }

    async fn handle(&mut self, cmd: AggregationCommand) {
        match cmd {
            AggregationCommand::IngestChunk { chunk } => {
                self.handle_ingest(chunk).await;
            }
            AggregationCommand::FetchRecordings {
                community_id,
                recording_ids,
                reply_to,
            } => {
                let result = self
                    .handle_fetch_recordings(community_id, recording_ids)
                    .await;
                let _ = reply_to.send(result);
            }
            AggregationCommand::FetchProximity {
                community_id,
                reply_to,
            } => {
                let result = self.evidence_store.list_proximity(&community_id).await;
                let _ = reply_to.send(result);
            }
            AggregationCommand::RefreshRouting { routing } => {
                self.community_routing = routing;
                debug!(
                    dids = self.community_routing.len(),
                    "AggregationActor: routing cache refreshed"
                );
            }
            AggregationCommand::Revoke { recording_id } => {
                // Remove from in-memory recording crucible
                self.recording_crucible.contexts.remove(&recording_id);
                // Remove from evidence store (disk)
                if let Err(e) = self.evidence_store.revoke_recording(&recording_id).await {
                    warn!(recording = %recording_id, error = %e, "Failed to revoke from evidence store");
                } else {
                    info!(recording = %recording_id, "Recording revoked from Stronghold");
                }
            }
        }
    }

    // ── IngestChunk Flow ─────────────────────────────────────────────────

    /// Pre-ingest gate checks: throttle, routing, bandwidth, replay.
    ///
    /// Returns `Some(communities)` if the chunk passes all gates,
    /// or `None` if it should be dropped.
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Throttle arithmetic and duration cast.
    async fn pre_ingest_gates(&mut self, chunk: &ShardChunk) -> Option<Vec<CommunityId>> {
        // 1. Ingestion scaler: sleep-throttle under system pressure.
        let ingestion_headroom = self.governor.ingestion_scaler().0;
        if ingestion_headroom < 0.1 {
            // Safety: ingestion_headroom is clamped to [0.0, 1.0], so (1.0 - x) * 100.0 is in [0, 100].
            #[allow(clippy::cast_sign_loss)]
            tokio::time::sleep(Duration::from_millis(
                ((1.0 - ingestion_headroom) * 100.0) as u64,
            ))
            .await;
        }

        // 2. Community routing check: drop if unknown DID.
        let owner_did = &chunk.owner_did;
        let communities = match self.community_routing.get(owner_did) {
            Some(c) if !c.is_empty() => c.clone(),
            _ => {
                debug!(
                    did = %owner_did,
                    "AggregationActor: unknown DID, dropping chunk"
                );
                return None;
            }
        };

        // 3. Per-peer bandwidth check via governor integral.
        let peer_id = owner_did.to_string();
        if !self.governor.is_peer_bandwidth_ok(&peer_id) {
            warn!(
                peer = %peer_id,
                "AggregationActor: per-peer bandwidth exceeded, dropping chunk"
            );
            return None;
        }
        self.governor.record_peer_bandwidth(&peer_id);

        // 4. Replay filter check.
        let chunk_hash = blake3::hash(&chunk.data);
        if self.replay_filter.contains(chunk_hash.as_bytes()) {
            debug!("AggregationActor: replay detected, dropping chunk");
            return None;
        }
        self.replay_filter.insert(chunk_hash.as_bytes());

        Some(communities)
    }

    /// Store an assembled recording and collect proximity evidence.
    #[allow(clippy::cast_possible_truncation)] // estimated_bytes arithmetic
    async fn store_recording(&mut self, recording: &Recording, communities: &[CommunityId]) {
        // Store via evidence_store for each community the DID belongs to.
        for community_id in communities {
            for artifact in &recording.artifacts {
                if let Err(e) = self
                    .evidence_store
                    .append_envelope(community_id, &recording.id, artifact)
                    .await
                {
                    warn!(
                        community = ?community_id,
                        recording = %recording.id,
                        error = %e,
                        "AggregationActor: failed to store envelope"
                    );
                }
            }
        }

        // Record storage pressure after writes.
        // Use a rough estimate based on artifact count * average size.
        #[allow(clippy::arithmetic_side_effects)] // Artifact count × 4096 won't overflow u64.
        let estimated_bytes = recording.artifacts.len() as u64 * 4096;
        self.governor
            .record_storage_pressure(estimated_bytes, 100 * 1024 * 1024 * 1024);

        info!(
            recording = %recording.id,
            artifacts = recording.artifacts.len(),
            communities = communities.len(),
            "AggregationActor: recording stored"
        );

        // If any artifact is Proximity evidence, push to proximity_log.
        for artifact in &recording.artifacts {
            if let Evidence::Proximity(pw) = &artifact.evidence {
                self.proximity_log.push(pw.clone());
            }
        }
    }

    async fn handle_ingest(&mut self, chunk: ShardChunk) {
        let communities = match self.pre_ingest_gates(&chunk).await {
            Some(c) => c,
            None => return,
        };

        // R2-2 FIX: Save claimed DID before chunk is consumed by shard_crucible.
        let claimed_did = chunk.owner_did.clone();

        // 5. Feed into shard_crucible. On decode -> WitnessEnvelope.
        let envelope = match self.shard_crucible.process(chunk) {
            Ok(Some(env)) => env,
            Ok(None) => return, // Accumulating, not ready yet.
            Err(e) => {
                warn!(error = ?e, "AggregationActor: shard crucible rejected chunk");
                return;
            }
        };

        // Record memory pressure from shard crucible buffers.
        let buffer_bytes: usize = self
            .shard_crucible
            .contexts
            .values()
            .map(|ctx| ctx.accumulator.accumulated_bytes())
            .sum();
        self.governor.record_memory_pressure(buffer_bytes);

        // 6. Signature verification, folded into the typestate transition:
        // promote_signed runs WitnessAuthority::verify_envelope (Ed25519
        // verify_strict over the serialized evidence) and yields a Verified
        // unit only on success. Verify-don't-trust (design Q3).
        let unit = match ForensicUnit::new(envelope).promote_signed() {
            Ok(u) => u,
            Err(_) => {
                warn!("AggregationActor: envelope signature verification failed, dropping");
                return;
            }
        };

        // R2-2 FIX: Assert chunk.owner_did matches the verified envelope signer.
        // Prevents an attacker from routing evidence into communities they don't belong to
        // by spoofing owner_did in the ShardChunk while signing as a different DID.
        if claimed_did != unit.data().did {
            warn!(
                claimed = %claimed_did,
                actual = %unit.data().did,
                "AggregationActor: chunk owner_did does not match envelope signer, dropping"
            );
            return;
        }

        // 7. Feed into recording_crucible.
        let recording = match self.recording_crucible.process(unit) {
            Ok(Some(rec)) => rec,
            Ok(None) => return, // Accumulating, not ready yet.
            Err(e) => {
                warn!(error = ?e, "AggregationActor: recording crucible rejected envelope");
                return;
            }
        };

        // 8. Storage scaler soft gate.
        if self.governor.storage_scaler().0 < 0.05 {
            warn!("AggregationActor: storage pressure critical, dropping assembled recording");
            return;
        }

        // 9-10. Store and collect proximity evidence.
        self.store_recording(&recording, &communities).await;
    }

    // ── FetchRecordings ──────────────────────────────────────────────────

    async fn handle_fetch_recordings(
        &self,
        community_id: CommunityId,
        recording_ids: Vec<RecordingId>,
    ) -> Result<Vec<Recording>, StrongholdError> {
        let mut recordings = Vec::with_capacity(recording_ids.len());
        for rid in &recording_ids {
            match self.evidence_store.read_recording(&community_id, rid).await {
                Ok(rec) => recordings.push(rec),
                Err(e) => {
                    warn!(
                        recording = %rid,
                        error = %e,
                        "AggregationActor: failed to read recording"
                    );
                    // Continue reading others; don't fail the entire batch.
                }
            }
        }
        Ok(recordings)
    }

    // ── Maintenance ──────────────────────────────────────────────────────

    fn perform_maintenance(&mut self) {
        // Flush stale shard contexts.
        let flushed_envelopes = self.shard_crucible.flush_stale(STALE_TTL);
        if !flushed_envelopes.is_empty() {
            info!(
                count = flushed_envelopes.len(),
                "AggregationActor: flushed stale shard contexts"
            );
        }

        // Flush stale recording contexts.
        let flushed_recordings = self.recording_crucible.flush_stale(STALE_TTL);
        if !flushed_recordings.is_empty() {
            info!(
                count = flushed_recordings.len(),
                "AggregationActor: flushed stale recording contexts"
            );
        }

        // Rotate the bloom filter.
        self.replay_filter.rotate();
    }
}
