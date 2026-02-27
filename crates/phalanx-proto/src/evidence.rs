use serde::{Deserialize, Serialize};
use crate::identity::{Did, ShardId, VolleyId};
use crate::time::PhalanxTimestamp;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DataPayload {
    Clear(Vec<u8>),
    Encrypted {
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
    },
    Compressed(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShardChunk {
    pub shard_id: ShardId,
    pub chunk_index: u32,
    pub chunk_type: ChunkType,
    pub total_chunks: u32,
    pub data: Vec<u8>,
    pub owner_did: Did,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessEnvelope {
    pub evidence: Evidence,
    pub witness_peer_id: NetworkId,
    pub witness_signature: Vec<u8>,
    pub did: Did,
    pub prev_hash: Option<SignatureHash>,
}

impl WitnessEnvelope {
    /// Verifies the envelope signature without panicking.
    #[must_use]
    pub fn verify(&self) -> bool {
        let clean_did = self.did.0.replace("did:key:", "");

        // Fail-safe: if decoding fails, signature is invalid
        let Ok(pubkey_bytes) = bs58::decode(clean_did).into_vec() else {
            return false;
        };

        let Ok(data_bytes) = postcard::to_stdvec(&self.evidence) else {
            return false;
        };

        PhalanxIdentity::verify(&pubkey_bytes, &data_bytes, &self.witness_signature)
    }

    /// Creates a new signed envelope.
    ///
    /// # Sentinel Safety
    /// Returns `Result` to propagate serialization errors instead of panicking.
    pub fn new(
        evidence: Evidence,
        identity: &PhalanxIdentity,
        peer_id: NetworkId,
        prev_hash: Option<SignatureHash>,
    ) -> Result<Self, ShardError> {
        let data_to_sign = postcard::to_stdvec(&evidence)
            .map_err(|e| ShardError::SerializationError(e.to_string()))?;

        let signature = identity.sign(&data_to_sign);

        Ok(Self {
            evidence,
            witness_peer_id: peer_id,
            witness_signature: signature.to_vec(),
            did: identity.did.clone(),
            prev_hash,
        })
    }

    pub fn signature_hash(&self) -> SignatureHash {
        let mut hasher = Sha256::new();
        hasher.update(&self.witness_signature);
        let result = hasher.finalize();

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        SignatureHash(hash)
    }

    pub fn chunkify(self, shard_id: ShardId) -> Result<Vec<ShardChunk>, ShardError> {
        // 1. Capture the owner's DID for the chunks
        let owner_did = self.did.clone();

        // 2. Serialize the FULL envelope (Header + Signature + Data)
        let data = postcard::to_stdvec(&self)
            .map_err(|e| ShardError::SerializationError(e.to_string()))?;

        // 3. Split into chunks using the standalone helper
        chunkify(
            shard_id,
            data,
            4096, // Standard Phalanx MTU
            owner_did,
            ChunkType::Witnessed,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardGapReport {
    pub shard_id: ShardId,
    pub missing_indices: Vec<u32>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub enum ChunkType {
    #[default]
    ForensicUnit,
    Witnessed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRequest {
    /// The gap report identifying exactly what is missing
    pub report: ShardGapReport,
    /// The DID of the node asking for help (for routing/trust)
    pub requester: Did,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicGap {
    pub volley_id: VolleyId,
    pub start_seq: StorageSequence,
    pub end_seq: StorageSequence,
    pub detected_at: PhalanxTimestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VideoShard {
    pub timestamp: PhalanxTimestamp,
    pub sequence_id: StorageSequence,
    pub fps: u8,
    pub volley_id: VolleyId,
    pub payload: DataPayload,
}

impl VideoShard {
    pub fn encrypt(&mut self, key: &SymmetricKey) -> Result<(), CryptoError> {
        self.payload.encrypt(key)
    }
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

impl AudioShard {
    pub fn encrypt(&mut self, key: &SymmetricKey) -> Result<(), CryptoError> {
        self.payload.encrypt(key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Evidence {
    Video(VideoShard),
    Audio(AudioShard),
    Gap(ForensicGap),
    Handover(HandoverProof),
}

impl Evidence {
    #[must_use]
    pub fn sequence_id(&self) -> StorageSequence {
        match self {
            Evidence::Video(s) => s.sequence_id,
            Evidence::Audio(s) => s.sequence_id,
            Evidence::Gap(g) => g.start_seq,
            Evidence::Handover(h) => h.sequence_id,
        }
    }

    #[must_use]
    pub fn volley_id(&self) -> &VolleyId {
        match self {
            Evidence::Video(s) => &s.volley_id,
            Evidence::Audio(s) => &s.volley_id,
            Evidence::Gap(g) => &g.volley_id,
            Evidence::Handover(h) => &h.volley_id,
        }
    }

    #[must_use]
    pub fn timestamp(&self) -> PhalanxTimestamp {
        match self {
            Evidence::Video(s) => s.timestamp,
            Evidence::Audio(s) => s.timestamp,
            Evidence::Gap(g) => g.detected_at,
            Evidence::Handover(_) => PhalanxTimestamp::now(),
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct StorageSequence(pub u32);

impl From<u32> for StorageSequence {
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl Deref for StorageSequence {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Add<u32> for StorageSequence {
    type Output = Self;
    fn add(self, rhs: u32) -> Self::Output {
        StorageSequence(self.0 + rhs)
    }
}

impl Sub<u32> for StorageSequence {
    type Output = Self;
    fn sub(self, rhs: u32) -> Self::Output {
        StorageSequence(self.0 - rhs)
    }
}

impl std::fmt::Display for StorageSequence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::AddAssign<u32> for StorageSequence {
    fn add_assign(&mut self, rhs: u32) {
        self.0 += rhs;
    }
}

/// Cryptographic proof of a witness rotation.
/// Witness A signs the identity of Witness B + the hash of the last unit to
/// permit the ChronosGate to accept the new identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HandoverProof {
    pub volley_id: VolleyId,
    pub sequence_id: StorageSequence,
    pub old_did: Did,
    pub new_did: Did,
    /// The hash of the final envelope generated by the old identity
    pub anchor_hash: SignatureHash,
    /// Signature from the OLD identity approving the handoff
    pub old_signature: Signature,
    /// Signature from the NEW identity accepting the handoff
    pub new_signature: Signature,
}

impl HandoverProof {
    pub fn generate(
        old_identity: &PhalanxIdentity,
        new_identity: &PhalanxIdentity,
        volley_id: VolleyId,
        sequence_id: StorageSequence,
        anchor_hash: SignatureHash,
    ) -> Result<Self, ShardError> {
        // 1. Create a deterministic payload of the transfer details
        // We use a tuple to ensure the serialization is strictly ordered
        let transfer_manifest = (
            &volley_id,
            &sequence_id,
            &old_identity.did,
            &new_identity.did,
            &anchor_hash,
        );

        // 2. Serialize the manifest into bytes
        let manifest_bytes = postcard::to_stdvec(&transfer_manifest)
            .map_err(|e| ShardError::SerializationError(e.to_string()))?;

        // 3. Hash the manifest to create a standard SignatureHash
        let mut hasher = blake3::Hasher::new();
        hasher.update(&manifest_bytes);
        let shared_hash = SignatureHash(hasher.finalize().into());

        // 4. Both identities sign the exact same hash
        // (Assuming your PhalanxIdentity has a sign() or sign_hash() method)
        let old_signature = old_identity.sign(shared_hash.as_bytes());
        let new_signature = new_identity.sign(shared_hash.as_bytes());

        Ok(Self {
            volley_id,
            sequence_id,
            old_did: old_identity.did.clone(),
            new_did: new_identity.did.clone(),
            anchor_hash,
            old_signature,
            new_signature,
        })
    }

}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataPayload {
    Clear(Vec<u8>),
    Encrypted { nonce: Vec<u8>, ciphertext: Vec<u8> },
    Missing(ShardGapReport),
}

impl Default for DataPayload {
    fn default() -> Self {
        DataPayload::Clear(Vec::new())
    }
}

impl DataPayload {
    pub fn encrypt(&mut self, key: &SymmetricKey) -> Result<(), CryptoError> {
        match self {
            DataPayload::Clear(data) => {
                let (nonce, ciphertext) = encrypt_bytes(key.as_bytes(), data)?;
                *self = DataPayload::Encrypted { nonce, ciphertext };
                Ok(())
            }
            DataPayload::Encrypted { .. } => Ok(()),
            DataPayload::Missing(_) => Ok(()), // Deterministic No-Op: Cannot encrypt gaps
        }
    }

    pub fn decrypt(&self, key: &SymmetricKey) -> Result<Vec<u8>, CryptoError> {
        match self {
            DataPayload::Clear(data) => Ok(data.clone()),
            DataPayload::Encrypted { nonce, ciphertext } => {
                decrypt_bytes(key.as_bytes(), nonce, ciphertext)
            }
            DataPayload::Missing(_) => {
                // Compile-time enforcement against reading gaps
                Err(CryptoError::EncryptionFailure)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureHash(pub [u8; 32]);

impl SignatureHash {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}


/// Represents a shard that failed complete reassembly but possesses
/// sufficient metadata to remain in the forensic timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentedEnvelope {
    pub shard_id: ShardId,
    pub owner_did: Did,
    pub gap_report: ShardGapReport,
    pub partial_data: BTreeMap<u32, Vec<u8>>,
}

/// The monadic output state of the Reassembler.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnvelopeState {
    Intact(WitnessEnvelope),
    Fragmented(FragmentedEnvelope),
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardDiscoveryRequest {
    pub volley_id: VolleyId,
    pub sequence_id: StorageSequence,
}

/// Represents a forensic response awaiting redelivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingEgress {
    pub channel_id: String,
    pub response: VolleyResponse,
    pub attempt_count: u32,
    pub next_attempt: PhalanxTimestamp,
}

impl PendingEgress {
    /// Instantiates a resilient egress record with type-safe timestamp arithmetic.
    pub fn new(channel_id: String, response: VolleyResponse, delay: Duration) -> Self {
        let now_ms = PhalanxTimestamp::now().as_millis();
        let delay_ms = delay.as_millis() as u64;

        Self {
            channel_id,
            response,
            attempt_count: 0,
            next_attempt: PhalanxTimestamp::from_millis(now_ms + delay_ms),
        }
    }
}


pub enum StorageCommand {
    Ingest(ShardChunk, MeshTopic, NetworkId),
    Retrieval(RetrievalQuery),
    EmergencySalvage(Vec<PendingEgress>),
    GetShard {
        volley_id: VolleyId,
        sequence_id: StorageSequence,
        reply_to: tokio::sync::oneshot::Sender<Option<WitnessEnvelope>>,
    },
    IngestEnvelope(EnvelopeState),
}

pub struct RetrievalQuery {
    pub volley_id: VolleyId,
    pub reply_to: oneshot::Sender<Result<Vec<WitnessEnvelope>, GuardianError>>,
}

#[derive(Debug, Clone)]
pub struct AudioFrame {
    pub data: Vec<u8>,  // PCM Data
    pub timestamp: u64, // True Monotonic Network Time (ms)
    pub sequence: u64,
    pub sample_rate: u32,
    pub channels: u8,
}

// crates/phalanx-proto/src/evidence.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoFrame {
    pub data: Vec<u8>,
    pub timestamp: u64, 
    pub sequence: u64,
    pub width: u32,
    pub height: u32,
}

#[async_trait::async_trait]
pub trait PlaybackSink: Send + Sync {
    async fn handle_chunk(&mut self, seq: StorageSequence, data: Vec<u8>) -> Result<(), String>;
}
#[async_trait]
pub trait PlaybackSink: Send + Sync {
    /// Handles a decrypted chunk of forensic data.
    /// The implementation is responsible for the "Dual Exodus" logic.
    async fn handle_chunk(&mut self, sequence_id: StorageSequence, mut data: Vec<u8>)
        -> Result<()>;

    /// Called when the playback sequence is complete or terminated.
    async fn finalize(&mut self) -> Result<()>;
}