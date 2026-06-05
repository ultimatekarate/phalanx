// crates/phalanx-stronghold/src/actors/aggregation.rs
//
// AggregationActor: receives ShardChunks from the mesh, reassembles via
// dual Crucible pipeline, stores encrypted recordings by community.
// Never decrypts — grants are provided at corroboration time.
//
// Hands layer. Owns Crucible<ShardMold> and Crucible<RecordingAmalgam>.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use phalanx_forensics::bloom::RotatingBloomFilter;
use phalanx_forensics::crucible::{Crucible, RecordingAmalgam};
use phalanx_forensics::gate::PromotionGate;
use phalanx_forensics::reassembler::ShardMold;
use phalanx_forensics::unit::ForensicUnit;
use phalanx_proto::community::CommunityId;
use phalanx_proto::corroboration::ProximityWitness;
use phalanx_proto::evidence::{Evidence, Recording, WitnessEnvelope};
use phalanx_proto::identity::{Did, RecordingId};
use phalanx_proto::prelude::ShardChunk;
use phalanx_proto::time::PhalanxTimestamp;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::StrongholdConfig;
use crate::custody::{CustodyCaps, CustodyLedger};
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
    /// Directed archive PUSH: persist a set of already-assembled, owner-signed
    /// envelopes (bypassing the ShardChunk reassembly crucibles), gated by the
    /// per-owner custody fairness ledger. Replies with the admission outcome so
    /// the sentinel can sign a custody receipt.
    PersistEnvelopes {
        recording_id: RecordingId,
        envelopes: Vec<WitnessEnvelope>,
        owner_did: Did,
        reply_to: oneshot::Sender<ArchiveAdmit>,
    },
    /// Custody TTL sweep: reclaim recordings whose `held_until` has passed.
    SweepExpired,
}

/// Outcome of an archive-push admission + persist, returned to the sentinel so
/// it can build the appropriate (signed) `ArchiveReceipt`.
#[derive(Debug, Clone)]
pub enum ArchiveAdmit {
    /// Admitted and persisted; the actor's clock fixed these custody bounds.
    Stored {
        envelope_count: u32,
        stored_at: PhalanxTimestamp,
        held_until: PhalanxTimestamp,
    },
    /// A per-owner / per-community / global storage cap would be exceeded.
    QuotaExceeded,
    /// Structurally/cryptographically refused (non-member, bad signature).
    Rejected,
}

/// In-memory custody bookkeeping for the TTL sweep. Transient by design — lost
/// on restart, at which point the publisher re-pushes (custody is not permanent
/// storage). Carries everything needed to release ledger bytes on reclamation.
struct CustodyEntry {
    held_until: PhalanxTimestamp,
    owner: Did,
    communities: Vec<CommunityId>,
    bytes: u64,
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
    config: Arc<StrongholdConfig>,
    /// Per-owner storage fairness — the balancing ratio. Owned by the actor
    /// (single-threaded over its mailbox), so no lock is needed.
    custody_ledger: CustodyLedger,
    /// Per-recording custody deadlines for the TTL sweep.
    custody_deadlines: HashMap<RecordingId, CustodyEntry>,
    rx: mpsc::Receiver<AggregationCommand>,
}

impl AggregationActor {
    pub fn new(
        evidence_store: EvidenceStore,
        governor: Arc<StrongholdGovernor>,
        config: Arc<StrongholdConfig>,
        rx: mpsc::Receiver<AggregationCommand>,
    ) -> Self {
        let caps = CustodyCaps {
            max_storage_bytes: config.storage.max_storage_bytes,
            max_per_community_bytes: config.storage.max_per_community_bytes,
            max_bytes_per_owner: config.storage.max_bytes_per_owner,
            owner_fair_share_ratio: config.storage.owner_fair_share_ratio,
        };
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
            config,
            custody_ledger: CustodyLedger::new(caps),
            custody_deadlines: HashMap::new(),
            rx,
        }
    }

    /// Wall-clock milliseconds since the UNIX epoch. The actor's governor uses a
    /// monotonic `Instant` epoch for the integral domain; custody deadlines need
    /// wall-clock time, hence `SystemTime` here.
    fn now_millis() -> u64 {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
        )
        .unwrap_or(u64::MAX)
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
            AggregationCommand::PersistEnvelopes {
                recording_id,
                envelopes,
                owner_did,
                reply_to,
            } => {
                let outcome = self
                    .handle_persist_envelopes(recording_id, envelopes, owner_did)
                    .await;
                let _ = reply_to.send(outcome);
            }
            AggregationCommand::SweepExpired => {
                self.handle_sweep_expired().await;
            }
        }
    }

    // ── Archive PUSH: persist pre-assembled envelopes ────────────────────

    /// Persist a directed archive push. Membership + per-envelope signature are
    /// verified here (verify-don't-trust), then the shared fairness gate +
    /// persist path runs. Returns the admission outcome for the receipt.
    async fn handle_persist_envelopes(
        &mut self,
        recording_id: RecordingId,
        envelopes: Vec<WitnessEnvelope>,
        owner_did: Did,
    ) -> ArchiveAdmit {
        // Membership: the owner must route to a community this Stronghold serves.
        let communities = match self.community_routing.get(&owner_did) {
            Some(c) if !c.is_empty() => c.clone(),
            _ => {
                debug!(did = %owner_did, "archive push from unknown DID, rejecting");
                return ArchiveAdmit::Rejected;
            }
        };

        // Verify-don't-trust: every envelope must carry a valid owner signature
        // and name the claimed owner. Reject the whole push otherwise.
        for env in &envelopes {
            if ForensicUnit::new(env.clone()).promote_signed().is_err() {
                warn!(recording = %recording_id, "archive push envelope failed signature verification, rejecting");
                return ArchiveAdmit::Rejected;
            }
            if env.did != owner_did {
                warn!(recording = %recording_id, "archive push envelope signer != sender_did, rejecting");
                return ArchiveAdmit::Rejected;
            }
        }

        self.persist_and_account(&recording_id, &owner_did, &envelopes, &communities, true)
            .await
    }

    /// Custody TTL sweep: delete recordings whose custody window has closed and
    /// release their bytes from the fairness ledger. Eviction ≠ revocation — the
    /// recording still exists at the owner / other replicas and may be re-pushed.
    async fn handle_sweep_expired(&mut self) {
        let now = Self::now_millis();
        let expired: Vec<RecordingId> = self
            .custody_deadlines
            .iter()
            .filter(|(_, e)| e.held_until.as_u64() <= now)
            .map(|(rid, _)| rid.clone())
            .collect();
        for rid in expired {
            let Some(entry) = self.custody_deadlines.remove(&rid) else {
                continue;
            };
            // Delete only the (community, recording) copies this entry tracked —
            // scoped, so an identically-named recording in a DIFFERENT community
            // is never collaterally deleted (unlike the global revoke_recording).
            for community_id in &entry.communities {
                if let Err(e) = self
                    .evidence_store
                    .reclaim_recording(community_id, &rid)
                    .await
                {
                    warn!(
                        recording = %rid,
                        community = ?community_id,
                        error = %e,
                        "custody sweep: failed to delete expired recording copy"
                    );
                }
            }
            // Always release the ledger: the custody window has closed, so the
            // bytes are reclaimed regardless of any disk-delete error (logged
            // above). This avoids an infinite re-insert/retry that would leak the
            // owner's quota if a delete failure were permanent.
            for community_id in &entry.communities {
                self.custody_ledger
                    .release(community_id, &entry.owner, entry.bytes);
            }
            info!(recording = %rid, "custody sweep: expired recording reclaimed");
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

    /// Store a gossipsub-assembled recording through the shared persist path.
    /// `custody = false`: the per-owner fairness gate applies (anti-flood), but
    /// the recording is retained indefinitely (not TTL-swept), preserving the
    /// prior passive-collection semantics. Over-quota recordings are dropped
    /// (the gossipsub path has no receipt to return).
    async fn store_recording(&mut self, recording: &Recording, communities: &[CommunityId]) {
        match self
            .persist_and_account(
                &recording.id,
                &recording.owner_did,
                &recording.artifacts,
                communities,
                false,
            )
            .await
        {
            ArchiveAdmit::Stored { .. } => {
                info!(
                    recording = %recording.id,
                    artifacts = recording.artifacts.len(),
                    communities = communities.len(),
                    "AggregationActor: recording stored"
                );
            }
            ArchiveAdmit::QuotaExceeded => {
                info!(
                    recording = %recording.id,
                    owner = %recording.owner_did,
                    "AggregationActor: recording dropped — custody fairness cap exceeded"
                );
            }
            ArchiveAdmit::Rejected => {}
        }
    }

    /// Shared custody persist path used by BOTH the gossipsub ingest and the
    /// directed archive push: run the hard per-owner fairness gate, persist each
    /// envelope to every community the owner belongs to, record the bytes in the
    /// fairness ledger, set a custody deadline, and collect proximity evidence.
    ///
    /// Admission order (fail-closed): per-owner share → per-community → global,
    /// checked against EVERY community before any write (all-or-nothing).
    async fn persist_and_account(
        &mut self,
        recording_id: &RecordingId,
        owner: &Did,
        artifacts: &[WitnessEnvelope],
        communities: &[CommunityId],
        custody: bool,
    ) -> ArchiveAdmit {
        // Serialized byte size of this recording (per copy).
        let bytes: u64 = artifacts
            .iter()
            .map(|e| {
                postcard::to_allocvec(e)
                    .map(|v| u64::try_from(v.len()).unwrap_or(u64::MAX))
                    .unwrap_or(0)
            })
            .sum();

        // Idempotency: if this recording was already persisted (a re-push or a
        // re-assembly), release its prior ledger contribution first — the new
        // copy overwrites the same shard files on disk, so without this the
        // ledger would double-count and never fully release (a permanent leak).
        // Restored below if the fresh admission is refused.
        let prior = self.custody_deadlines.remove(recording_id);
        if let Some(ref p) = prior {
            for community_id in &p.communities {
                self.custody_ledger.release(community_id, &p.owner, p.bytes);
            }
        }

        // Fairness admission against every target community (all-or-nothing).
        let mut admitted = true;
        for community_id in communities {
            if !self
                .custody_ledger
                .check_admit(community_id, owner, bytes)
                .is_admitted()
            {
                admitted = false;
                break;
            }
        }
        if !admitted {
            // Restore the prior contribution we tentatively released.
            if let Some(p) = prior {
                for community_id in &p.communities {
                    self.custody_ledger.record(community_id, &p.owner, p.bytes);
                }
                self.custody_deadlines.insert(recording_id.clone(), p);
            }
            warn!(
                recording = %recording_id,
                owner = %owner,
                "custody admission refused (per-owner/community/global cap)"
            );
            return ArchiveAdmit::QuotaExceeded;
        }

        // Persist + record. Each community holds an independent copy.
        for community_id in communities {
            for artifact in artifacts {
                if let Err(e) = self
                    .evidence_store
                    .append_envelope(community_id, recording_id, artifact)
                    .await
                {
                    warn!(
                        community = ?community_id,
                        recording = %recording_id,
                        error = %e,
                        "AggregationActor: failed to store envelope"
                    );
                }
            }
            self.custody_ledger.record(community_id, owner, bytes);
        }

        // Deadline. Archive pushes are transient export-staging (now + TTL).
        // Gossipsub passive collection is retained indefinitely (held_until =
        // never), preserving the prior cumulative-archive semantics — only the
        // per-owner fairness cap is newly applied to that path, not eviction.
        let now = Self::now_millis();
        let stored_at = PhalanxTimestamp::from_millis(now);
        let held_until = if custody {
            let ttl_ms = self.config.storage.custody_ttl_secs.saturating_mul(1000);
            PhalanxTimestamp::from_millis(now.saturating_add(ttl_ms))
        } else {
            PhalanxTimestamp::from_millis(u64::MAX) // never swept
        };
        self.custody_deadlines.insert(
            recording_id.clone(),
            CustodyEntry {
                held_until,
                owner: owner.clone(),
                communities: communities.to_vec(),
                bytes,
            },
        );

        // Storage pressure: the disk actually written THIS call (one copy per
        // community) against the config cap — NOT the cumulative ledger total,
        // which sums per-community fair-share bytes and would over-report.
        let disk_written = bytes.saturating_mul(u64::try_from(communities.len()).unwrap_or(1));
        self.governor
            .record_storage_pressure(disk_written, self.config.storage.max_storage_bytes);

        // Proximity evidence collection.
        for artifact in artifacts {
            if let Evidence::Proximity(pw) = &artifact.evidence {
                self.proximity_log.push(pw.clone());
            }
        }

        let envelope_count = u32::try_from(artifacts.len()).unwrap_or(u32::MAX);
        ArchiveAdmit::Stored {
            envelope_count,
            stored_at,
            held_until,
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
