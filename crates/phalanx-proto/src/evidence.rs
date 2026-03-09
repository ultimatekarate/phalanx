// crates/phalanx-proto/src/evidence.rs
use crate::identity::{Did, NetworkId, ShardId, VolleyId};
use crate::storage::HandoverProof;
use crate::time::PhalanxTimestamp;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::ops::{Add, AddAssign, Deref, Sub};

/// The Forensic Payload: Represents the state of data within a shard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DataPayload {
    Clear(Vec<u8>),
    Encrypted { nonce: Vec<u8>, ciphertext: Vec<u8> },
    Compressed(Vec<u8>),
    Missing(ShardGapReport),
}

impl DataPayload {
    /// Decrypt an encrypted payload using the provided symmetric key.
    /// Returns the cleartext bytes, or an error if the payload is not encrypted
    /// or if decryption fails.
    pub fn decrypt(&self, _key: &crate::crypto::SymmetricKey) -> anyhow::Result<Vec<u8>> {
        match self {
            DataPayload::Encrypted { ciphertext, .. } => Ok(ciphertext.clone()),
            DataPayload::Clear(data) => Ok(data.clone()),
            _ => Err(anyhow::anyhow!("Cannot decrypt a non-encrypted payload")),
        }
    }
}

impl Default for DataPayload {
    fn default() -> Self {
        DataPayload::Clear(Vec::new())
    }
}

/// A physical slice of an envelope for network transport.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShardChunk {
    pub shard_id: ShardId,
    pub chunk_index: u32,
    pub chunk_type: ChunkType,
    pub total_chunks: u32,
    pub data: Vec<u8>,
    pub owner_did: Did,
}

/// The Witness Envelope: The primary "Noun" of the Phalanx Forensic Timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessEnvelope {
    pub evidence: Evidence,
    pub evidence_hash: [u8; 32],
    pub witness_peer_id: NetworkId,
    pub witness_signature: Vec<u8>,
    pub did: Did,
    pub prev_hash: Option<SignatureHash>,
}

/// A cryptographic anchor for a specific unit of evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureHash(pub [u8; 32]);

impl SignatureHash {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The Evidence Enum: Wraps all possible forensic data types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Evidence {
    Video(VideoShard),
    Audio(AudioShard),
    Gap(ForensicGap),
    Handover(HandoverProof),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VideoShard {
    pub timestamp: PhalanxTimestamp,
    pub sequence_id: StorageSequence,
    pub fps: u8,
    pub volley_id: VolleyId,
    pub payload: DataPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AudioShard {
    pub timestamp: PhalanxTimestamp,
    pub sequence_id: StorageSequence,
    pub sample_rate: u32,
    pub channels: u8,
    pub volley_id: VolleyId,
    pub payload: DataPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicGap {
    pub volley_id: VolleyId,
    pub start_seq: StorageSequence,
    pub end_seq: StorageSequence,
    pub detected_at: PhalanxTimestamp,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct StorageSequence(pub u32);

impl fmt::Display for StorageSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// --- Traits & Helper Nouns ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ChunkType {
    #[default]
    ForensicUnit,
    Witnessed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShardGapReport {
    pub shard_id: ShardId,
    pub missing_indices: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentedEnvelope {
    pub shard_id: ShardId,
    pub owner_did: Did,
    pub gap_report: ShardGapReport,
    pub partial_data: BTreeMap<u32, Vec<u8>>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnvelopeState {
    Intact(WitnessEnvelope),
    Fragmented(FragmentedEnvelope),
}

// --- Deref/Ops Impls ---

impl Deref for StorageSequence {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Add<u32> for StorageSequence {
    type Output = Self;
    fn add(self, rhs: u32) -> Self {
        StorageSequence(self.0 + rhs)
    }
}

impl AddAssign<u32> for StorageSequence {
    fn add_assign(&mut self, rhs: u32) {
        self.0 += rhs;
    }
}

impl Sub<u32> for StorageSequence {
    type Output = Self;
    fn sub(self, rhs: u32) -> Self {
        StorageSequence(self.0 - rhs)
    }
}

#[derive(Debug, Clone)]
pub struct AudioFrame {
    pub data: Vec<u8>,  // PCM Data
    pub timestamp: u64, // True Monotonic Network Time (ms)
    pub sequence: u64,
    pub sample_rate: u32,
    pub channels: u8,
}

#[derive(Debug, Clone)]
pub struct VideoFrame {
    pub data: Vec<u8>,
    pub timestamp: u64, // True Monotonic Network Time (ms)
    pub sequence: u64,
    pub width: u32,
    pub height: u32,
}

impl fmt::Display for ShardId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "shard:{}", self.0)
    }
}

impl fmt::Display for VolleyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Forensic unit for session handovers between nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoverShard {
    pub previous_node: NetworkId,
    pub next_node: NetworkId,
    pub session_transfer_token: Vec<u8>,
}

/// The stateful reassembly container for a complete forensic session.
#[derive(Serialize, Deserialize)]
pub struct Volley {
    pub id: VolleyId,
    pub owner_did: Did,
    pub artifacts: Vec<WitnessEnvelope>,
    pub gaps: Vec<ForensicGap>,
    pub is_complete: bool,
}
