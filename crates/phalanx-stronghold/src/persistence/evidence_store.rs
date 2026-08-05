// crates/phalanx-stronghold/src/persistence/evidence_store.rs
//
// Filesystem-backed evidence vault. Stores WitnessEnvelopes as shards
// keyed by (CommunityId, RecordingId). Atomic writes via temp+rename.
//
// Hands layer — owns IO. Imports Dictionary nouns unchanged.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use phalanx_proto::community::CommunityId;
use phalanx_proto::evidence::{Evidence, ForensicGap, Recording, StorageSequence, WitnessEnvelope};
use phalanx_proto::identity::RecordingId;
use phalanx_proto::time::PhalanxTimestamp;
use tracing::warn;

use crate::error::StrongholdError;

// ── Path Helpers ────────────────────────────────────────────────────────

/// RT-2: Hash a RecordingId with blake3 to produce a safe directory name.
fn recording_dir_name(recording_id: &RecordingId) -> String {
    let hash = blake3::hash(recording_id.as_str().as_bytes());
    hash.to_hex().to_string()
}

/// Hex-encode a CommunityId (already [u8; 32]).
fn community_dir_name(community_id: &CommunityId) -> String {
    hex::encode(community_id.0)
}

// ── EvidenceStore ───────────────────────────────────────────────────────

#[derive(Clone)]
pub struct EvidenceStore {
    root: PathBuf,
}

impl EvidenceStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Default durable export sink: `{vault}/exports`. The autonomous export
    /// task writes the signed C2PA MP4 + `ExportReceipt` here unless the config
    /// overrides the path. A sibling of `evidence/`, never under it, so a
    /// custody reclaim of `evidence/` never deletes a delivered artifact.
    pub fn export_dir(&self) -> PathBuf {
        self.root.join("exports")
    }

    /// Base path for a community's evidence.
    fn community_path(&self, community_id: &CommunityId) -> PathBuf {
        self.root
            .join("evidence")
            .join(community_dir_name(community_id))
    }

    /// Base path for a specific recording within a community.
    fn recording_path(&self, community_id: &CommunityId, recording_id: &RecordingId) -> PathBuf {
        self.community_path(community_id)
            .join(recording_dir_name(recording_id))
    }

    /// Shards directory for a recording.
    fn shards_path(&self, community_id: &CommunityId, recording_id: &RecordingId) -> PathBuf {
        self.recording_path(community_id, recording_id)
            .join("shards")
    }

    /// Extract the StorageSequence from a WitnessEnvelope's inner Evidence.
    fn envelope_sequence(envelope: &WitnessEnvelope) -> StorageSequence {
        match &envelope.evidence {
            Evidence::Video(v) => v.sequence_id,
            Evidence::Audio(a) => a.sequence_id,
            Evidence::Gap(g) => g.start_seq,
            Evidence::Handover(_) => StorageSequence(0),
            Evidence::ManifestEntry(m) => m.sequence_id,
        }
    }

    /// Extract the RecordingId from a WitnessEnvelope's inner Evidence.
    fn envelope_recording_id(envelope: &WitnessEnvelope) -> Option<RecordingId> {
        match &envelope.evidence {
            Evidence::Video(v) => Some(v.recording_id.clone()),
            Evidence::Audio(a) => Some(a.recording_id.clone()),
            Evidence::Gap(g) => Some(g.recording_id.clone()),
            Evidence::Handover(_) => None,
            Evidence::ManifestEntry(m) => Some(m.recording_id.clone()),
        }
    }

    // ── Operations ──────────────────────────────────────────────────────

    /// Append a WitnessEnvelope as a shard file. Atomic: write to .tmp, then rename.
    pub async fn append_envelope(
        &self,
        community_id: &CommunityId,
        recording_id: &RecordingId,
        envelope: &WitnessEnvelope,
    ) -> Result<(), StrongholdError> {
        let seq = Self::envelope_sequence(envelope);
        let shards_dir = self.shards_path(community_id, recording_id);
        tokio::fs::create_dir_all(&shards_dir).await?;

        let final_path = shards_dir.join(format!("{}.bin", seq.0));

        let bytes = postcard::to_allocvec(envelope).map_err(|e| {
            StrongholdError::Serialization(format!("Failed to serialize envelope: {e}"))
        })?;

        // RT-6: atomic write
        super::atomic::atomic_write(&final_path, &bytes).await?;

        Ok(())
    }

    /// Read all shards for a recording, detect gaps, and build a Recording.
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Sequence arithmetic for gap detection and epoch millis.
    pub async fn read_recording(
        &self,
        community_id: &CommunityId,
        recording_id: &RecordingId,
    ) -> Result<Recording, StrongholdError> {
        let shards_dir = self.shards_path(community_id, recording_id);

        if !shards_dir.exists() {
            return Err(StrongholdError::RecordingNotFound(recording_id.clone()));
        }

        // Snapshot: list directory first, then load only those files.
        let mut entries = tokio::fs::read_dir(&shards_dir).await?;
        let mut shard_files: Vec<(u32, PathBuf)> = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                // Skip .tmp files
                if path.extension().and_then(|e| e.to_str()) == Some("tmp") {
                    continue;
                }
                if let Ok(seq_num) = stem.parse::<u32>() {
                    shard_files.push((seq_num, path));
                }
            }
        }

        // Sort by sequence number
        shard_files.sort_by_key(|(seq, _)| *seq);

        let mut envelopes: Vec<WitnessEnvelope> = Vec::with_capacity(shard_files.len());
        let mut gaps: Vec<ForensicGap> = Vec::new();
        let now = PhalanxTimestamp::from_millis(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        );
        let mut expected_seq: Option<StorageSequence> = None;
        let mut owner_did = phalanx_proto::identity::Did::default();

        for (seq_num, path) in &shard_files {
            let bytes = tokio::fs::read(path).await?;
            let envelope: WitnessEnvelope = postcard::from_bytes(&bytes).map_err(|e| {
                StrongholdError::Serialization(format!(
                    "Failed to deserialize shard {}: {e}",
                    seq_num
                ))
            })?;

            let current_seq = StorageSequence(*seq_num);

            // Gap detection: if we expected a sequence and there's a jump
            if let Some(exp) = expected_seq {
                if current_seq.0 > exp.0 {
                    gaps.push(ForensicGap {
                        recording_id: recording_id.clone(),
                        start_seq: exp,
                        end_seq: StorageSequence(current_seq.0 - 1),
                        detected_at: now,
                    });
                }
            }

            // Track owner from the envelope DID
            owner_did = envelope.did.clone();

            expected_seq = Some(StorageSequence(current_seq.0 + 1));
            envelopes.push(envelope);
        }

        let complete = gaps.is_empty();
        Ok(Recording {
            id: recording_id.clone(),
            owner_did,
            artifacts: envelopes,
            gaps,
            is_complete: complete,
        })
    }

    /// List all recording IDs stored for a community.
    pub async fn list_recordings(
        &self,
        community_id: &CommunityId,
    ) -> Result<Vec<RecordingId>, StrongholdError> {
        let community_dir = self.community_path(community_id);

        if !community_dir.exists() {
            return Ok(Vec::new());
        }

        let mut recordings = Vec::new();
        let mut entries = tokio::fs::read_dir(&community_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                // The directory name is a blake3 hash of the recording ID.
                // We can't reverse the hash, so we need to peek inside
                // to find the actual recording ID from a stored shard.
                let shards_dir = entry.path().join("shards");
                if shards_dir.exists() {
                    if let Some(rid) = self.peek_recording_id(&shards_dir).await {
                        recordings.push(rid);
                    }
                }
            }
        }

        Ok(recordings)
    }

    /// Peek into the first shard to extract the RecordingId.
    async fn peek_recording_id(&self, shards_dir: &std::path::Path) -> Option<RecordingId> {
        let mut entries = tokio::fs::read_dir(shards_dir).await.ok()?;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("bin") {
                let bytes = tokio::fs::read(&path).await.ok()?;
                let envelope: WitnessEnvelope = postcard::from_bytes(&bytes).ok()?;
                return Self::envelope_recording_id(&envelope);
            }
        }
        None
    }

    /// Total bytes consumed by a community's evidence directory.
    #[allow(clippy::arithmetic_side_effects)] // Byte total accumulation.
    pub async fn community_bytes(
        &self,
        community_id: &CommunityId,
    ) -> Result<u64, StrongholdError> {
        let community_dir = self.community_path(community_id);

        if !community_dir.exists() {
            return Ok(0);
        }

        let mut total: u64 = 0;
        let mut stack = vec![community_dir];

        while let Some(dir) = stack.pop() {
            let mut entries = tokio::fs::read_dir(&dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let ft = entry.file_type().await?;
                if ft.is_file() {
                    total += entry.metadata().await?.len();
                } else if ft.is_dir() {
                    stack.push(entry.path());
                }
            }
        }

        Ok(total)
    }

    /// Cryptographic Forgetting: remove all shards for a recording across all communities.
    /// Searches all community directories for the recording's hash directory.
    pub async fn revoke_recording(
        &self,
        recording_id: &RecordingId,
    ) -> Result<(), StrongholdError> {
        let target_dir = recording_dir_name(recording_id);
        let evidence_root = self.root.join("evidence");

        if !evidence_root.exists() {
            return Ok(());
        }

        let mut community_dirs = tokio::fs::read_dir(&evidence_root).await?;
        while let Some(community_entry) = community_dirs.next_entry().await? {
            if !community_entry.file_type().await?.is_dir() {
                continue;
            }
            let recording_path = community_entry.path().join(&target_dir);
            if recording_path.exists() {
                tokio::fs::remove_dir_all(&recording_path).await?;
                tracing::info!(
                    recording = %recording_id,
                    path = %recording_path.display(),
                    "Stronghold: recording directory deleted"
                );
            }
        }

        Ok(())
    }

    /// Write an autonomously-exported artifact (the signed C2PA MP4) and its
    /// signed `ExportReceipt` to the durable sink (atomic temp+rename for both).
    /// `dir` overrides [`EvidenceStore::export_dir`] when the config names an
    /// external sink. Filenames derive from a blake3 hash of the recording id,
    /// so an owner-controlled id can never escape the sink directory. Returns
    /// the artifact path.
    pub async fn write_export(
        &self,
        dir: Option<&Path>,
        recording_id: &RecordingId,
        mp4: &[u8],
        receipt_bytes: &[u8],
    ) -> Result<PathBuf, StrongholdError> {
        let base = dir.map_or_else(|| self.export_dir(), Path::to_path_buf);
        tokio::fs::create_dir_all(&base).await?;
        let stem = recording_dir_name(recording_id);
        let mp4_path = base.join(format!("{stem}.mp4"));
        let receipt_path = base.join(format!("{stem}.receipt.bin"));
        super::atomic::atomic_write(&mp4_path, mp4).await?;
        super::atomic::atomic_write(&receipt_path, receipt_bytes).await?;
        Ok(mp4_path)
    }

    /// Whether any shard directory exists for a (community, recording) pair.
    /// Used by startup reconciliation to self-heal custody sidecars whose shards
    /// were deleted (so their bytes are not re-counted into the fairness ledger).
    pub async fn recording_exists(
        &self,
        community_id: &CommunityId,
        recording_id: &RecordingId,
    ) -> bool {
        self.recording_path(community_id, recording_id).exists()
    }

    /// Custody reclamation: remove a SINGLE recording's shards within ONE
    /// community. Unlike `revoke_recording` (cryptographic forgetting across
    /// ALL communities), this is scoped to exactly the (community, recording)
    /// the custody ledger tracked — so an identically-named recording in a
    /// different community is never touched. Idempotent: a missing directory is
    /// a no-op.
    pub async fn reclaim_recording(
        &self,
        community_id: &CommunityId,
        recording_id: &RecordingId,
    ) -> Result<(), StrongholdError> {
        let recording_path = self.recording_path(community_id, recording_id);
        if recording_path.exists() {
            tokio::fs::remove_dir_all(&recording_path).await?;
            tracing::info!(
                recording = %recording_id,
                community = ?community_id,
                "Stronghold: custody recording reclaimed"
            );
        }
        Ok(())
    }

    // ── Custody / revocation persistence (restart durability) ────────────
    //
    // The actor owns the CustodyEntry / revoked-set types and their
    // (de)serialization; this layer only does atomic IO on opaque bytes,
    // keeping the Hands layer free of Dictionary logic.

    /// Directory holding per-recording custody sidecars.
    fn custody_dir(&self) -> PathBuf {
        self.root.join("custody")
    }

    fn custody_sidecar_path(&self, recording_id: &RecordingId) -> PathBuf {
        self.custody_dir()
            .join(format!("{}.bin", recording_dir_name(recording_id)))
    }

    /// Persist a recording's custody sidecar (atomic). `bytes` is the caller's
    /// serialized custody record (which carries its own recording_id, owner,
    /// communities, held_until, and byte count), so the TTL sweep + fairness
    /// ledger can be rebuilt after a restart.
    pub async fn write_custody_sidecar(
        &self,
        recording_id: &RecordingId,
        bytes: &[u8],
    ) -> Result<(), StrongholdError> {
        tokio::fs::create_dir_all(self.custody_dir()).await?;
        super::atomic::atomic_write(&self.custody_sidecar_path(recording_id), bytes).await?;
        Ok(())
    }

    /// Delete a recording's custody sidecar. A missing file is a no-op.
    pub async fn delete_custody_sidecar(
        &self,
        recording_id: &RecordingId,
    ) -> Result<(), StrongholdError> {
        match tokio::fs::remove_file(self.custody_sidecar_path(recording_id)).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Load every custody sidecar's raw bytes for startup reconciliation.
    pub async fn load_custody_sidecars(&self) -> Result<Vec<Vec<u8>>, StrongholdError> {
        let dir = self.custody_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut entries = tokio::fs::read_dir(&dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_file() {
                match tokio::fs::read(entry.path()).await {
                    Ok(bytes) => out.push(bytes),
                    Err(e) => warn!(
                        error = %e,
                        path = %entry.path().display(),
                        "custody reconcile: failed to read sidecar"
                    ),
                }
            }
        }
        Ok(out)
    }

    /// Persist the revoked-recording set (atomic, whole-set rewrite). The set is
    /// small — one entry per cryptographically-forgotten recording — so a full
    /// rewrite is simpler and safe. Caller serializes the `RecordingId` set.
    pub async fn write_revoked(&self, bytes: &[u8]) -> Result<(), StrongholdError> {
        super::atomic::atomic_write(&self.root.join("revoked.bin"), bytes).await?;
        Ok(())
    }

    /// Load the persisted revoked-set bytes (empty if none yet).
    pub async fn load_revoked(&self) -> Result<Vec<u8>, StrongholdError> {
        match tokio::fs::read(self.root.join("revoked.bin")).await {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }
}

// hex encoding helper — using the blake3 hex output directly for recording IDs,
// but we need hex for CommunityId ([u8; 32]).
mod hex {
    #[allow(clippy::arithmetic_side_effects)] // Hex string capacity — bytes * 2.
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let bytes = bytes.as_ref();
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}
