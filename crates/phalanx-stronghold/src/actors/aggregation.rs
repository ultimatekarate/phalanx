// crates/phalanx-stronghold/src/actors/aggregation.rs
//
// AggregationActor: receives ShardChunks from the mesh, reassembles via
// dual Crucible pipeline, stores encrypted recordings by community.
// Never decrypts — grants are provided at corroboration time.
//
// Hands layer. Owns Crucible<ShardMold> and Crucible<RecordingAmalgam>.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use phalanx_forensics::archive::build_export_receipt;
use phalanx_forensics::bloom::RotatingBloomFilter;
use phalanx_forensics::crucible::{Crucible, RecordingAmalgam};
use phalanx_forensics::cryptography::grant::GrantAuthority;
use phalanx_forensics::export_recording_to_signed_mp4;
use phalanx_forensics::gate::PromotionGate;
use phalanx_forensics::reassembler::ShardMold;
use phalanx_forensics::unit::ForensicUnit;
use phalanx_proto::community::CommunityId;
use phalanx_proto::corroboration::ProximityWitness;
use phalanx_proto::crypto::{SealedLocator, SymmetricKey};
use phalanx_proto::evidence::{Evidence, Recording, WitnessEnvelope};
use phalanx_proto::identity::{Did, PhalanxIdentity, RecordingId};
use phalanx_proto::prelude::ShardChunk;
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_proto::types::Fps;
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
    /// the sentinel can sign a custody receipt. An optional export `grant`
    /// (sealed to this Stronghold) authorizes later autonomous export.
    PersistEnvelopes {
        recording_id: RecordingId,
        envelopes: Vec<WitnessEnvelope>,
        owner_did: Did,
        grant: Option<SealedLocator>,
        reply_to: oneshot::Sender<ArchiveAdmit>,
    },
    /// Custody TTL sweep: reclaim recordings whose `held_until` has passed.
    SweepExpired,
    /// Autonomous-export quiescence scan: spawn export tasks for settled,
    /// grant-bearing recordings. Driven by the sentinel's maintenance tick
    /// (alongside `SweepExpired`); also the test trigger.
    ScanExports,
    /// An autonomous export task finished (sent by the task back to the actor).
    /// `success` marks the recording exported (so it is not re-exported) and, if
    /// configured, releases its custody copy early; a failure just clears the
    /// in-flight guard so the next quiescence tick can retry.
    ExportCompleted {
        recording_id: RecordingId,
        success: bool,
    },
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

/// Custody bookkeeping for the TTL sweep. Persisted to a per-recording sidecar
/// (carries its own `recording_id`) so the sweep + fairness ledger survive a
/// Stronghold restart — without it, a restart orphans held recordings and they
/// are never reclaimed. Carries everything needed to release ledger bytes.
///
/// NOTE: the sidecar is postcard (non-self-describing); the M2.3 fields below
/// extend the layout, so sidecars written by an earlier build are unreadable
/// and dropped by `reconcile_one_sidecar` (their shards survive). Acceptable
/// pre-release; a real format version belongs with the first shipped release.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CustodyEntry {
    recording_id: RecordingId,
    held_until: PhalanxTimestamp,
    owner: Did,
    communities: Vec<CommunityId>,
    bytes: u64,
    /// Export grant sealed to THIS Stronghold's DID (escrow-for-export). Sealed
    /// ciphertext — safe to persist; unlockable only with the Stronghold's
    /// in-memory private key. `None` ⇒ custody-only, never auto-exported.
    grant: Option<SealedLocator>,
    /// Wall-clock of the most recent (re-)push for this recording. The export
    /// trigger fires only once `now - last_activity ≥ export_quiescence`, so a
    /// still-arriving recording is never exported mid-flight.
    last_activity: PhalanxTimestamp,
    /// Set once the recording has been autonomously exported, so the trigger
    /// does not re-export it. Reset to false on any new push (new content).
    exported: bool,
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
    /// Cryptographically-forgotten recordings. Refuses re-admission (push or
    /// gossipsub) and is persisted so the forgetting survives a restart.
    revoked: HashSet<RecordingId>,
    /// This Stronghold's identity — unlocks export grants (ECDH) and signs the
    /// `ExportReceipt`. Shared (Arc) so spawned export tasks can hold it.
    identity: Arc<PhalanxIdentity>,
    /// Weak handle to the actor's own mailbox, for spawned export tasks to post
    /// `ExportCompleted` back. WEAK on purpose: it must not keep the channel
    /// alive, or the actor would never observe shutdown (rx never closes).
    self_tx: mpsc::WeakSender<AggregationCommand>,
    /// Recordings with an export task currently in flight — prevents the
    /// quiescence trigger from spawning a duplicate export each tick.
    exporting: HashSet<RecordingId>,
    rx: mpsc::Receiver<AggregationCommand>,
}

impl AggregationActor {
    pub fn new(
        evidence_store: EvidenceStore,
        governor: Arc<StrongholdGovernor>,
        config: Arc<StrongholdConfig>,
        identity: Arc<PhalanxIdentity>,
        self_tx: mpsc::WeakSender<AggregationCommand>,
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
            revoked: HashSet::new(),
            identity,
            self_tx,
            exporting: HashSet::new(),
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

        // Rebuild custody deadlines + fairness ledger + revoked set from disk
        // before serving, so a restart neither orphans held recordings nor
        // resurrects forgotten ones.
        self.reconcile_custody().await;

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
                // Record + PERSIST the forgetting BEFORE deleting shards. Order
                // matters for crash-consistency: if a crash struck after the
                // shards were deleted but before the revocation was persisted, a
                // restart would find an orphan custody sidecar and could
                // resurrect (and re-admit) the forgotten recording. Persisting
                // first closes that window.
                if self.revoked.insert(recording_id.clone()) {
                    self.persist_revoked().await;
                }
                // Remove from in-memory recording crucible + delete shards.
                self.recording_crucible.contexts.remove(&recording_id);
                if let Err(e) = self.evidence_store.revoke_recording(&recording_id).await {
                    warn!(recording = %recording_id, error = %e, "Failed to revoke from evidence store");
                } else {
                    info!(recording = %recording_id, "Recording revoked from Stronghold");
                }
                // Release any in-flight custody bytes so a revoked recording
                // never leaks the owner's fairness quota; drop its sidecar too.
                if let Some(entry) = self.clear_custody(&recording_id).await {
                    for community_id in &entry.communities {
                        self.custody_ledger
                            .release(community_id, &entry.owner, entry.bytes);
                    }
                }
            }
            AggregationCommand::PersistEnvelopes {
                recording_id,
                envelopes,
                owner_did,
                grant,
                reply_to,
            } => {
                let outcome = self
                    .handle_persist_envelopes(recording_id, envelopes, owner_did, grant)
                    .await;
                let _ = reply_to.send(outcome);
            }
            AggregationCommand::SweepExpired => {
                self.handle_sweep_expired().await;
            }
            AggregationCommand::ScanExports => {
                self.spawn_due_exports();
            }
            AggregationCommand::ExportCompleted {
                recording_id,
                success,
            } => {
                self.handle_export_completed(&recording_id, success).await;
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
        grant: Option<SealedLocator>,
    ) -> ArchiveAdmit {
        // An empty push cannot be attributed to any custody/quota — refuse it.
        if envelopes.is_empty() {
            debug!(recording = %recording_id, "archive push with no envelopes, rejecting");
            return ArchiveAdmit::Rejected;
        }

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

        self.persist_and_account(
            &recording_id,
            &owner_did,
            &envelopes,
            &communities,
            true,
            grant,
        )
        .await
    }

    // ── Custody persistence helpers (memory + disk kept in sync) ─────────

    /// Insert/replace a custody deadline in memory AND persist its sidecar, so
    /// the TTL sweep + fairness ledger can be rebuilt after a restart.
    async fn set_custody(&mut self, entry: CustodyEntry) {
        let recording_id = entry.recording_id.clone();
        match postcard::to_allocvec(&entry) {
            Ok(bytes) => {
                if let Err(e) = self
                    .evidence_store
                    .write_custody_sidecar(&recording_id, &bytes)
                    .await
                {
                    warn!(recording = %recording_id, error = %e, "failed to persist custody sidecar");
                }
            }
            Err(e) => {
                warn!(recording = %recording_id, error = %e, "failed to serialize custody sidecar");
            }
        }
        self.custody_deadlines.insert(recording_id, entry);
    }

    /// Remove a custody deadline from memory AND disk, returning the prior entry.
    /// Does NOT touch the ledger — the caller decides whether to release bytes
    /// (sweep/revoke release; the idempotency path may re-record).
    async fn clear_custody(&mut self, recording_id: &RecordingId) -> Option<CustodyEntry> {
        let entry = self.custody_deadlines.remove(recording_id);
        if entry.is_some() {
            if let Err(e) = self
                .evidence_store
                .delete_custody_sidecar(recording_id)
                .await
            {
                warn!(recording = %recording_id, error = %e, "failed to delete custody sidecar");
            }
        }
        entry
    }

    /// Delete a recording's custody sidecar, logging (never swallowing) any
    /// failure. `reason` gives the log context (e.g. "revoked", "orphan").
    async fn delete_sidecar_logged(&self, recording_id: &RecordingId, reason: &str) {
        if let Err(e) = self
            .evidence_store
            .delete_custody_sidecar(recording_id)
            .await
        {
            warn!(
                recording = %recording_id,
                reason,
                error = %e,
                "reconcile: failed to delete custody sidecar"
            );
        }
    }

    /// Persist the full revoked set (small, whole-set rewrite).
    async fn persist_revoked(&self) {
        match postcard::to_allocvec(&self.revoked) {
            Ok(bytes) => {
                if let Err(e) = self.evidence_store.write_revoked(&bytes).await {
                    warn!(error = %e, "failed to persist revoked set");
                }
            }
            Err(e) => warn!(error = %e, "failed to serialize revoked set"),
        }
    }

    /// Startup reconciliation: rebuild the revoked set, then custody deadlines +
    /// fairness ledger, from disk; finally sweep anything already past its
    /// deadline so a long downtime does not retain expired recordings.
    async fn reconcile_custody(&mut self) {
        // Revoked set first, so a reconciled custody entry for an
        // already-forgotten recording is never resurrected below.
        match self.evidence_store.load_revoked().await {
            Ok(bytes) if !bytes.is_empty() => {
                match postcard::from_bytes::<HashSet<RecordingId>>(&bytes) {
                    Ok(ids) => self.revoked = ids,
                    Err(e) => warn!(error = %e, "failed to deserialize revoked set"),
                }
            }
            Ok(_) => {}
            Err(e) => warn!(error = %e, "failed to load revoked set"),
        }

        match self.evidence_store.load_custody_sidecars().await {
            Ok(sidecars) => {
                let mut restored = 0usize;
                for bytes in sidecars {
                    if self.reconcile_one_sidecar(&bytes).await {
                        restored = restored.saturating_add(1);
                    }
                }
                if restored > 0 {
                    info!(restored, "custody reconcile: restored deadlines from disk");
                }
            }
            Err(e) => warn!(error = %e, "failed to load custody sidecars"),
        }

        // Reclaim anything whose window already closed during downtime.
        self.handle_sweep_expired().await;
    }

    /// Reconcile one custody sidecar: drop it if the recording was revoked or its
    /// shards are gone (orphan), otherwise restore the deadline + fairness ledger
    /// for the communities whose shards still exist. Returns true if a deadline
    /// was restored.
    async fn reconcile_one_sidecar(&mut self, bytes: &[u8]) -> bool {
        let entry: CustodyEntry = match postcard::from_bytes(bytes) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "skipping unreadable custody sidecar");
                return false;
            }
        };
        // Drop a stale sidecar for a recording that was revoked.
        if self.revoked.contains(&entry.recording_id) {
            self.delete_sidecar_logged(&entry.recording_id, "revoked")
                .await;
            return false;
        }
        // Self-heal: keep only communities whose shards still exist on disk. A
        // crash between the sidecar write and the shard write (or a partial
        // reclaim) can leave a sidecar whose shards are gone — recording its
        // bytes would inflate the fairness ledger forever. If none remain, the
        // sidecar is an orphan and is dropped.
        let mut live = Vec::with_capacity(entry.communities.len());
        for community_id in &entry.communities {
            if self
                .evidence_store
                .recording_exists(community_id, &entry.recording_id)
                .await
            {
                live.push(*community_id);
            }
        }
        if live.is_empty() {
            self.delete_sidecar_logged(&entry.recording_id, "orphan")
                .await;
            return false;
        }
        let pruned = live.len() != entry.communities.len();
        for community_id in &live {
            self.custody_ledger
                .record(community_id, &entry.owner, entry.bytes);
        }
        let healed = CustodyEntry {
            communities: live,
            ..entry
        };
        if pruned {
            // Rewrite the sidecar so its community list matches disk.
            self.set_custody(healed).await;
        } else {
            self.custody_deadlines
                .insert(healed.recording_id.clone(), healed);
        }
        true
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
            let Some(entry) = self.clear_custody(&rid).await else {
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
                None,
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
    /// Serialized byte size of a recording's envelopes (one copy).
    fn recording_bytes(artifacts: &[WitnessEnvelope]) -> u64 {
        artifacts
            .iter()
            .map(|e| {
                postcard::to_allocvec(e)
                    .map(|v| u64::try_from(v.len()).unwrap_or(u64::MAX))
                    .unwrap_or(0)
            })
            .sum()
    }

    /// Collect any proximity witnesses carried by a recording's envelopes.
    fn collect_proximity(&mut self, artifacts: &[WitnessEnvelope]) {
        for artifact in artifacts {
            if let Evidence::Proximity(pw) = &artifact.evidence {
                self.proximity_log.push(pw.clone());
            }
        }
    }

    async fn persist_and_account(
        &mut self,
        recording_id: &RecordingId,
        owner: &Did,
        artifacts: &[WitnessEnvelope],
        communities: &[CommunityId],
        custody: bool,
        grant: Option<SealedLocator>,
    ) -> ArchiveAdmit {
        // Revocation strictly precedes persistence: never re-admit a
        // cryptographically-forgotten recording. This single chokepoint covers
        // both the directed push and gossipsub ingest (both funnel through here).
        if self.revoked.contains(recording_id) {
            warn!(recording = %recording_id, "persist refused: recording is revoked");
            return ArchiveAdmit::Rejected;
        }

        // Serialized byte size of this recording (per copy).
        let bytes: u64 = Self::recording_bytes(artifacts);

        // Idempotency: a re-push / re-assembly overwrites the same shard files,
        // so release the prior ledger contribution before re-admitting (else the
        // ledger double-counts and never fully releases). This is IN-MEMORY only:
        // on success the on-disk sidecar is rewritten (same key) by set_custody;
        // on refusal the prior sidecar is left untouched and still matches the
        // restored entry — so memory and disk never desync, and a rejected
        // re-push does no disk IO at all.
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
            // Restore the prior contribution we tentatively released — purely in
            // memory; the prior sidecar on disk was never touched, so memory and
            // disk are consistent again without any new write.
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

        // Carry forward an existing export grant when this push supplies none,
        // so a gossipsub re-delivery (grant=None) of an archive-pushed recording
        // never strips its escrow-for-export authority.
        let grant = grant.or_else(|| prior.as_ref().and_then(|p| p.grant.clone()));

        // Deadline. Archive pushes are transient export-staging (now + TTL).
        // Gossipsub passive collection is retained indefinitely (held_until =
        // never), preserving the prior cumulative-archive semantics — only the
        // per-owner fairness cap is newly applied to that path, not eviction.
        // A gossipsub re-delivery must NOT shorten an existing finite custody
        // window (it would let passive traffic cancel an archive push's TTL).
        let now = Self::now_millis();
        let stored_at = PhalanxTimestamp::from_millis(now);
        let held_until = if custody {
            let ttl_ms = self.config.storage.custody_ttl_secs.saturating_mul(1000);
            PhalanxTimestamp::from_millis(now.saturating_add(ttl_ms))
        } else {
            // Never swept (or inherit an existing finite custody window). NOTE:
            // never-expiring gossipsub recordings keep a custody sidecar for the
            // lifetime of the recording (needed so the fairness ledger survives
            // restart). On a long-running, gossipsub-heavy Stronghold these
            // accumulate; a periodic sidecar GC for never-expiring entries is a
            // deliberate follow-up, not done here.
            match prior.as_ref() {
                Some(p) if p.held_until.as_u64() != u64::MAX => p.held_until,
                _ => PhalanxTimestamp::from_millis(u64::MAX),
            }
        };

        // Persist the custody sidecar BEFORE the shards. Ordering matters for
        // crash-consistency: a crash can then only ever leave a
        // sidecar-without-shards (which reconcile self-heals by dropping) —
        // never orphan shards with no deadline and no ledger entry. `exported`
        // resets to false on every push: new content must be re-exported.
        self.set_custody(CustodyEntry {
            recording_id: recording_id.clone(),
            held_until,
            owner: owner.clone(),
            communities: communities.to_vec(),
            bytes,
            grant,
            last_activity: stored_at,
            exported: false,
        })
        .await;

        // Persist shards + record the ledger. Each community holds one copy.
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

        // Storage pressure: the disk actually written THIS call (one copy per
        // community) against the config cap — NOT the cumulative ledger total,
        // which sums per-community fair-share bytes and would over-report.
        let disk_written = bytes.saturating_mul(u64::try_from(communities.len()).unwrap_or(1));
        self.governor
            .record_storage_pressure(disk_written, self.config.storage.max_storage_bytes);

        // Proximity evidence collection.
        self.collect_proximity(artifacts);

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

    // ── Autonomous export ────────────────────────────────────────────────

    /// Quiescence scan (runs on the maintenance tick): for every held recording
    /// that carries an export grant with `export` permission, has not been
    /// exported, has no export already in flight, and has been settled (no new
    /// push) for at least `export_quiescence_secs`, spawn an off-loop export
    /// task. A `export_quiescence_secs` of `0` disables the feature entirely.
    fn spawn_due_exports(&mut self) {
        let window_secs = self.config.storage.export_quiescence_secs;
        if window_secs == 0 {
            return;
        }
        let now = Self::now_millis();
        let window_ms = window_secs.saturating_mul(1000);

        // Collect candidates first (shared borrow of custody state), then spawn
        // (which mutates `exporting`).
        let mut due: Vec<(RecordingId, CommunityId, SealedLocator)> = Vec::new();
        for e in self.custody_deadlines.values() {
            if e.exported || self.exporting.contains(&e.recording_id) {
                continue;
            }
            let Some(grant) = e.grant.as_ref() else {
                continue;
            };
            if !grant.permissions.export {
                continue;
            }
            // Settled: no (re-)push for at least the quiescence window.
            if now.saturating_sub(e.last_activity.as_u64()) < window_ms {
                continue;
            }
            // Every community holds the same copy; read from the first.
            let Some(community) = e.communities.first().copied() else {
                continue;
            };
            due.push((e.recording_id.clone(), community, grant.clone()));
        }

        for (recording_id, community, grant) in due {
            self.exporting.insert(recording_id.clone());
            let override_dir = self.config.storage.export_path.as_ref().map(PathBuf::from);
            tokio::spawn(run_export(
                self.evidence_store.clone(),
                self.identity.clone(),
                override_dir,
                grant,
                recording_id,
                community,
                self.self_tx.clone(),
            ));
        }
    }

    /// React to a finished export task. On success: mark the recording exported
    /// (persisted, so a restart does not re-export) and — if configured —
    /// reclaim its custody copy early (the signed artifact is the deliverable).
    /// On failure: just clear the in-flight guard so a later tick can retry.
    async fn handle_export_completed(&mut self, recording_id: &RecordingId, success: bool) {
        self.exporting.remove(recording_id);
        if !success {
            return;
        }
        // Mark exported + persist. If the entry is gone (swept/revoked) or
        // already marked, there is nothing to do.
        let entry = match self.custody_deadlines.get(recording_id) {
            Some(e) if !e.exported => CustodyEntry {
                exported: true,
                ..e.clone()
            },
            _ => return,
        };
        self.set_custody(entry).await;
        info!(recording = %recording_id, "autonomous export: recording marked exported");

        if self.config.storage.release_custody_after_export {
            if let Some(entry) = self.clear_custody(recording_id).await {
                for community_id in &entry.communities {
                    if let Err(e) = self
                        .evidence_store
                        .reclaim_recording(community_id, recording_id)
                        .await
                    {
                        warn!(
                            recording = %recording_id,
                            community = ?community_id,
                            error = %e,
                            "autonomous export: early-release reclaim failed"
                        );
                    }
                }
                for community_id in &entry.communities {
                    self.custody_ledger
                        .release(community_id, &entry.owner, entry.bytes);
                }
                info!(recording = %recording_id, "autonomous export: custody released early");
            }
        }
    }
}

/// Off-loop export task: unlock the grant → decode/transcode/C2PA-sign the
/// recording → write the signed MP4 + a signed `ExportReceipt` to the durable
/// sink → post `ExportCompleted` back to the actor. Spawned per recording so a
/// slow encode never blocks the actor mailbox.
async fn run_export(
    evidence_store: EvidenceStore,
    identity: Arc<PhalanxIdentity>,
    override_dir: Option<PathBuf>,
    grant: SealedLocator,
    recording_id: RecordingId,
    community: CommunityId,
    self_tx: mpsc::WeakSender<AggregationCommand>,
) {
    let success = run_export_inner(
        &evidence_store,
        &identity,
        override_dir.as_deref(),
        &grant,
        &recording_id,
        &community,
    )
    .await;

    // Report back so the actor marks it exported (or clears the in-flight guard
    // to retry). WEAK upgrade: if the actor is gone (shutdown), drop silently.
    if let Some(tx) = self_tx.upgrade() {
        let _ = tx
            .send(AggregationCommand::ExportCompleted {
                recording_id,
                success,
            })
            .await;
    }
}

/// The fallible body of [`run_export`]. Returns `true` iff a signed artifact +
/// receipt were written to the sink.
async fn run_export_inner(
    evidence_store: &EvidenceStore,
    identity: &Arc<PhalanxIdentity>,
    override_dir: Option<&std::path::Path>,
    grant: &SealedLocator,
    recording_id: &RecordingId,
    community: &CommunityId,
) -> bool {
    // 1. Unlock the grant → per-recording DEK. `unlock` enforces the grant was
    //    sealed to THIS Stronghold (recipient == our DID) and authenticates the
    //    permissions via AAD, so a tampered or misdirected grant fails here.
    let dek = match grant.unlock(identity) {
        Ok(k) => SymmetricKey::from_bytes(k),
        Err(e) => {
            warn!(recording = %recording_id, error = ?e, "autonomous export: grant unlock failed");
            return false;
        }
    };

    // 2. Load the recording's envelopes from custody.
    let recording = match evidence_store.read_recording(community, recording_id).await {
        Ok(r) => r,
        Err(e) => {
            warn!(recording = %recording_id, error = %e, "autonomous export: read failed");
            return false;
        }
    };

    // 3. Decrypt → re-verify provenance → transcode → C2PA-sign. CPU-bound, so
    //    run it on a blocking thread to keep the async runtime responsive.
    let id_for_blocking = identity.clone();
    let artifacts = recording.artifacts;
    let exported = match tokio::task::spawn_blocking(move || {
        export_recording_to_signed_mp4(artifacts, &dek, &id_for_blocking, Fps::default())
    })
    .await
    {
        Ok(Ok(a)) => a,
        Ok(Err(e)) => {
            warn!(recording = %recording_id, error = %e, "autonomous export: transcode/sign failed");
            return false;
        }
        Err(e) => {
            warn!(recording = %recording_id, error = %e, "autonomous export: blocking join failed");
            return false;
        }
    };

    // 4. Sign an ExportReceipt bound to exactly the bytes that landed.
    let artifact_hash = *blake3::hash(&exported.mp4_bytes).as_bytes();
    let receipt = build_export_receipt(
        identity,
        recording_id.clone(),
        artifact_hash,
        PhalanxTimestamp::from_millis(AggregationActor::now_millis()),
    );
    let receipt_bytes = match postcard::to_allocvec(&receipt) {
        Ok(b) => b,
        Err(e) => {
            warn!(recording = %recording_id, error = %e, "autonomous export: receipt serialize failed");
            return false;
        }
    };

    // 5. Write artifact + receipt to the durable sink (atomic temp+rename).
    match evidence_store
        .write_export(
            override_dir,
            recording_id,
            &exported.mp4_bytes,
            &receipt_bytes,
        )
        .await
    {
        Ok(path) => {
            info!(
                recording = %recording_id,
                path = %path.display(),
                frames = exported.frame_count,
                "autonomous export: wrote signed C2PA artifact"
            );
            true
        }
        Err(e) => {
            warn!(recording = %recording_id, error = %e, "autonomous export: write failed");
            false
        }
    }
}
