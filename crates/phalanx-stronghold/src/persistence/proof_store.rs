// crates/phalanx-stronghold/src/persistence/proof_store.rs
//
// Filesystem store for CorroborationProofs, keyed by (CommunityId, proof_hash).
//
// Hands layer — owns IO. Uses postcard serialization, atomic writes.

use std::path::PathBuf;

use phalanx_proto::community::CommunityId;
use phalanx_proto::corroboration::CorroborationProof;

use crate::error::StrongholdError;

// ── Path Helpers ────────────────────────────────────────────────────────

fn community_hex(community_id: &CommunityId) -> String {
    let mut s = String::with_capacity(64);
    for b in &community_id.0 {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hash_hex(hash: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in hash {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ── ProofStore ──────────────────────────────────────────────────────────

pub struct ProofStore {
    root: PathBuf,
}

impl ProofStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Directory for a community's proofs.
    fn community_path(&self, community_id: &CommunityId) -> PathBuf {
        self.root.join("proofs").join(community_hex(community_id))
    }

    /// Store a CorroborationProof. Atomic: write to .tmp, then rename.
    pub async fn store_proof(
        &self,
        community_id: &CommunityId,
        proof: &CorroborationProof,
    ) -> Result<(), StrongholdError> {
        let dir = self.community_path(community_id);
        tokio::fs::create_dir_all(&dir).await?;

        let filename = format!("{}.bin", hash_hex(&proof.proof_hash));
        let final_path = dir.join(&filename);
        let tmp_path = dir.join(format!("{}.bin.tmp", hash_hex(&proof.proof_hash)));

        let bytes = postcard::to_allocvec(proof).map_err(|e| {
            StrongholdError::Serialization(format!("Failed to serialize proof: {e}"))
        })?;

        tokio::fs::write(&tmp_path, &bytes).await?;
        tokio::fs::rename(&tmp_path, &final_path).await?;

        Ok(())
    }

    /// Load a specific proof by its hash.
    pub async fn load_proof(
        &self,
        community_id: &CommunityId,
        proof_hash: &[u8; 32],
    ) -> Result<CorroborationProof, StrongholdError> {
        let dir = self.community_path(community_id);
        let path = dir.join(format!("{}.bin", hash_hex(proof_hash)));

        let bytes = tokio::fs::read(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StrongholdError::Storage(format!("Proof not found: {}", hash_hex(proof_hash)))
            } else {
                StrongholdError::Io(e)
            }
        })?;

        postcard::from_bytes(&bytes).map_err(|e| {
            StrongholdError::Serialization(format!("Failed to deserialize proof: {e}"))
        })
    }

    /// List all proof hashes stored for a community.
    pub async fn list_proofs(
        &self,
        community_id: &CommunityId,
    ) -> Result<Vec<[u8; 32]>, StrongholdError> {
        let dir = self.community_path(community_id);

        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut hashes = Vec::new();
        let mut entries = tokio::fs::read_dir(&dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            // Only .bin files, skip .tmp
            if path.extension().and_then(|e| e.to_str()) != Some("bin") {
                continue;
            }

            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if let Some(hash) = parse_hex_hash(stem) {
                    hashes.push(hash);
                }
            }
        }

        Ok(hashes)
    }
}

/// Parse a 64-char hex string into [u8; 32].
#[allow(clippy::arithmetic_side_effects)] // Hex index arithmetic — i*2 bounded by array length.
fn parse_hex_hash(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let idx = i * 2;
        *byte = u8::from_str_radix(s.get(idx..idx + 2)?, 16).ok()?;
    }
    Some(out)
}
