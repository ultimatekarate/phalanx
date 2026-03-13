// crates/phalanx-forensics/src/reassembler.rs

use crate::crucible::{Crucible, Mold};
use crate::prelude::TransientJournal;
use image::DynamicImage;
use phalanx_proto::evidence::{
    AudioShard, ChunkType, EnvelopeState, ForensicMetrics, StorageSequence, VideoShard,
    WitnessEnvelope,
};
use phalanx_proto::identity::{Did, ShardId};
use phalanx_proto::prelude::{
    DataPayload, EncodingSymbolId, PhalanxTimestamp, RepairRatio, ShardChunk, ShardError,
    SymbolSize, VolleyId,
};
use phalanx_proto::types::{ChannelCount, Fps, PowerState, SampleRate};
use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation, PayloadId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// OTI (ObjectTransmissionInformation) prefix length in bytes.
/// Every fountain symbol's data field starts with 12 bytes of OTI,
/// making each symbol self-describing — the receiver can initialize
/// the decoder from ANY received symbol.
const OTI_PREFIX_LEN: usize = 12;

// BRIDGE API (Restored for Hardware Drivers) ---
pub fn compress_frame(raw_data: Vec<u8>, width: u32, height: u32) -> Result<Vec<u8>, String> {
    let img = DynamicImage::ImageRgb8(
        image::ImageBuffer::from_raw(width, height, raw_data)
            .ok_or("Failed to create image buffer")?,
    );

    let mut output = Vec::new();
    let encoder = image::codecs::jpeg::JpegEncoder::new(&mut output);
    img.write_with_encoder(encoder)
        .map_err(|e| format!("JPEG Compression error: {}", e))?;

    Ok(output)
}

/// `lens_metrics` carries the sensor fingerprint computed by the ForensicLens pipeline.
/// Every VideoShard MUST carry real metrics — `ForensicMetrics::default()` (all zeros)
/// is itself a forensic signal that the LensGate can flag as a bypass attempt.
pub fn create_video_shard(
    frames: Vec<Vec<u8>>,
    sequence: StorageSequence,
    fps: Fps,
    volley: VolleyId,
    lens_metrics: ForensicMetrics,
) -> Result<VideoShard, ShardError> {
    let raw_bytes = postcard::to_allocvec(&frames)
        .map_err(|e| ShardError::InvalidSize(format!("Serialization fail: {}", e)))?;

    Ok(VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: sequence,
        // Automatically applies the new LZ4 block compression
        payload: DataPayload::Compressed(compress_payload(&raw_bytes)),
        fps,
        volley_id: volley,
        lens_metrics,
    })
}

/// RESTORED: Factory for creating a network-ready AudioShard.
pub fn create_audio_shard(
    data: Vec<u8>,
    sequence: StorageSequence,
    rate: SampleRate,
    channels: ChannelCount,
    volley: VolleyId,
) -> Result<AudioShard, ShardError> {
    Ok(AudioShard {
        payload: DataPayload::Compressed(compress_payload(&data)),
        sequence_id: sequence,
        sample_rate: rate,
        channels,
        volley_id: volley,
        timestamp: PhalanxTimestamp::now(),
    })
}

// --- BLOCK-LEVEL UTILITIES ---

/// S1 FIX: Decompression bomb guard.
/// Reads the claimed decompressed size from the LZ4 prepended header and rejects
/// payloads that would expand beyond MAX_DECOMPRESSED_BYTES, preventing OOM attacks.
const MAX_DECOMPRESSED_BYTES: usize = 128 * 1024 * 1024; // 128 MiB hard ceiling

pub fn decompress_payload(data: &[u8]) -> Result<Vec<u8>, String> {
    // S1 FIX: Check the claimed decompressed size before allocating.
    // lz4_flex prepends a 4-byte little-endian uncompressed size.
    if data.len() < 4 {
        return Err("LZ4 Decompression error: input too short for size header".into());
    }
    let claimed_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if claimed_size > MAX_DECOMPRESSED_BYTES {
        return Err(format!(
            "LZ4 Decompression bomb: claimed size {} exceeds {} byte limit",
            claimed_size, MAX_DECOMPRESSED_BYTES
        ));
    }

    lz4_flex::decompress_size_prepended(data).map_err(|e| format!("LZ4 Decompression error: {}", e))
}

pub fn compress_payload(data: &[u8]) -> Vec<u8> {
    lz4_flex::compress_prepend_size(data)
}

// --- THE REASSEMBLER ---

/// P1 FIX: Maximum number of concurrent shard reassembly contexts per peer.
/// Prevents a single attacker from monopolizing the Crucible's capacity
/// by opening thousands of unique shard IDs from the same DID.
const MAX_CONTEXTS_PER_PEER: usize = 50;

pub struct Reassembler {
    pub active_shards: Crucible<ShardMold>,
    pub power_state: PowerState,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    pub fn new() -> Self {
        Self {
            active_shards: Crucible::new(ShardMold, std::time::Duration::from_secs(1), 1000),
            power_state: PowerState::Normal,
        }
    }

    /// P1 FIX: Count how many active contexts belong to a specific peer.
    fn peer_context_count(&self, owner_did: &Did) -> usize {
        self.active_shards
            .contexts
            .values()
            .filter(|ctx| ctx.accumulator.owner_did == *owner_did)
            .count()
    }

    pub async fn ingest_chunk<J: TransientJournal>(
        &mut self,
        chunk: ShardChunk,
        journal: &mut J,
    ) -> Result<Option<EnvelopeState>, ShardError> {
        // P1 FIX: Per-peer quota enforcement.
        // Check if this peer already has too many active reassembly contexts.
        // Only enforce for NEW shard IDs (existing ones are already tracked).
        if !self.active_shards.contexts.contains_key(&chunk.shard_id)
            && self.peer_context_count(&chunk.owner_did) >= MAX_CONTEXTS_PER_PEER
        {
            tracing::warn!(
                peer = %chunk.owner_did,
                active_contexts = self.peer_context_count(&chunk.owner_did),
                limit = MAX_CONTEXTS_PER_PEER,
                "P1: Per-peer crucible quota exceeded"
            );
            return Err(ShardError::CapacityExceeded(MAX_CONTEXTS_PER_PEER as u64));
        }

        journal.record_chunk(&chunk).await?;
        journal.sync().await?;

        match self.active_shards.process(chunk) {
            Ok(Some(envelope)) => Ok(Some(EnvelopeState::Intact(envelope))),
            Ok(None) => Ok(None),
            // THE FIX: Map the Crucible's generic GuardianError back to a ShardError
            Err(guardian_error) => Err(ShardError::SerializationError(format!(
                "Reassembly rejected by Crucible: {:?}",
                guardian_error
            ))),
        }
    }

    pub async fn recover_from_journal<J: TransientJournal>(
        &mut self,
        journal: &mut J,
    ) -> Result<(), ShardError> {
        let chunks = journal.read_all_chunks().await?;
        for chunk in chunks {
            // Replay the WAL chunks through the Crucible engine
            let _ = self.active_shards.process(chunk);
        }
        Ok(())
    }
}

// --- THE SHARD BUFFER (Fountain-mode RaptorQ decoder state) ---

/// M1 FIX: Maximum bytes a single shard reassembly may accumulate.
/// Prevents memory amplification from attackers sending oversized chunks.
const MAX_SHARD_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Resource guard: hard cap of 2,000 symbols per context.
/// Domain grounding: 1MB frame at 1,200-byte MTU = 834 chunks. 2,000 gives 2.4× headroom.
const MAX_SYMBOLS_PER_CONTEXT: u32 = 2_000;

#[derive(Debug, Serialize, Deserialize)]
pub struct ShardBuffer {
    pub received_count: u32,
    /// Set when a symbol with `is_terminal == true` arrives.
    pub terminal_received: bool,
    /// Raw symbol data keyed by ESI. Stored for:
    /// Duplicate detection (skip already-received ESIs)
    /// WAL recovery (decoder reconstructed by replaying stored symbols)
    /// accumulated_bytes() resource accounting
    pub parts: BTreeMap<u32, Vec<u8>>,
    pub owner_did: Did,
    /// RaptorQ fountain decoder. Not serializable — reconstructed from
    /// stored symbols during WAL recovery (journal replay through Crucible).
    #[serde(skip)]
    fountain_decoder: Option<Decoder>,
    /// Set when the decoder reports successful decode.
    #[serde(skip)]
    decoded_data: Option<Vec<u8>>,
}

impl ShardBuffer {
    /// Total bytes currently held across all received parts.
    pub fn accumulated_bytes(&self) -> usize {
        self.parts.values().map(|v| v.len()).sum()
    }
}

// --- THE SHARD MOLD (Fountain-only) ---

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ShardMold;

impl Mold for ShardMold {
    type Input = ShardChunk;
    type Output = WitnessEnvelope;
    type Key = ShardId;
    type Accumulator = ShardBuffer;
    type Error = ShardError;

    fn get_key(item: &Self::Input) -> Self::Key {
        item.shard_id
    }

    fn init_accumulator(item: &Self::Input) -> Self::Accumulator {
        ShardBuffer {
            received_count: 0,
            terminal_received: item.is_terminal,
            parts: BTreeMap::new(),
            owner_did: item.owner_did.clone(),
            fountain_decoder: None,
            decoded_data: None,
        }
    }

    // Byte-level buffers inherently lack cryptographic proof
    // thus this must be false.
    fn is_authoritative(_acc: &Self::Accumulator) -> bool {
        false
    }

    fn ingest(acc: &mut Self::Accumulator, item: Self::Input) -> Result<(), Self::Error> {
        // M1 FIX: Enforce per-shard byte budget before accepting the chunk.
        let incoming_bytes = item.data.len();
        let current_bytes = acc.accumulated_bytes();
        if current_bytes + incoming_bytes > MAX_SHARD_BYTES {
            return Err(ShardError::CapacityExceeded(
                (current_bytes + incoming_bytes) as u64,
            ));
        }

        // Resource guard: hard cap of 2,000 symbols per context.
        if acc.received_count >= MAX_SYMBOLS_PER_CONTEXT {
            return Err(ShardError::CapacityExceeded(MAX_SYMBOLS_PER_CONTEXT as u64));
        }

        let esi = item.encoding_symbol_id.0;
        if item.is_terminal {
            acc.terminal_received = true;
        }

        // Skip duplicate symbols
        if acc.parts.contains_key(&esi) {
            return Ok(());
        }

        let raw_data = item.data;

        // Validate OTI prefix
        if raw_data.len() < OTI_PREFIX_LEN {
            return Err(ShardError::InvalidSize(
                "Symbol data too short for OTI prefix".into(),
            ));
        }

        // Extract OTI and symbol payload (copy symbol data before moving raw_data)
        let oti_bytes: [u8; 12] = raw_data[..OTI_PREFIX_LEN]
            .try_into()
            .expect("OTI slice is exactly 12 bytes");
        let symbol_data = raw_data[OTI_PREFIX_LEN..].to_vec();

        // Initialize decoder on first symbol (lazy — any symbol carries the OTI)
        if acc.fountain_decoder.is_none() {
            let config = ObjectTransmissionInformation::deserialize(&oti_bytes);
            acc.fountain_decoder = Some(Decoder::new(config));
        }

        // Store raw data (OTI + symbol) for WAL recovery and dedup tracking
        acc.parts.insert(esi, raw_data);
        acc.received_count += 1;

        // Feed to fountain decoder (only if not already decoded)
        if acc.decoded_data.is_none() {
            let payload_id = PayloadId::new(0, esi); // source_block_number = 0 (per-envelope encoding)
            let packet = EncodingPacket::new(payload_id, symbol_data);
            if let Some(decoder) = acc.fountain_decoder.as_mut() {
                if let Some(decoded) = decoder.decode(packet) {
                    acc.decoded_data = Some(decoded);
                }
            }
        }

        Ok(())
    }

    fn is_ready(acc: &Self::Accumulator, _elapsed: std::time::Duration) -> bool {
        // Fountain completeness: the decoder has successfully reconstructed the original data.
        acc.decoded_data.is_some()
    }

    fn assemble(&self, _key: Self::Key, acc: Self::Accumulator) -> Option<Self::Output> {
        let decoded = acc.decoded_data?;

        // S3 FIX: Assembly size bound.
        if decoded.len() > MAX_SHARD_BYTES {
            tracing::warn!(
                total_size = decoded.len(),
                limit = MAX_SHARD_BYTES,
                "S3: Assembly rejected — decoded size exceeds safe limit"
            );
            return None;
        }

        // Deserialization Gate: unmarshal the decoded bytes into a WitnessEnvelope.
        crate::gate::unmarshal(&decoded, "ShardMold::assemble").ok()
    }
}

// --- WEAVER TRAITS ---

pub trait AudioWeaver {
    fn weave_audio(
        &self,
        sequence: StorageSequence,
        rate: SampleRate,
        channels: ChannelCount,
        volley: VolleyId,
    ) -> AudioShard;
}

impl AudioWeaver for Vec<u8> {
    fn weave_audio(
        &self,
        sequence: StorageSequence,
        rate: SampleRate,
        channels: ChannelCount,
        volley: VolleyId,
    ) -> AudioShard {
        AudioShard {
            payload: DataPayload::Compressed(compress_payload(self)),
            sequence_id: sequence,
            sample_rate: rate,
            channels,
            volley_id: volley,
            timestamp: PhalanxTimestamp::now(),
        }
    }
}

pub trait VideoWeaver {
    fn weave_video(
        &self,
        frames: Vec<Vec<u8>>,
        sequence: StorageSequence,
        fps: Fps,
        volley: VolleyId,
    ) -> VideoShard;
}

impl VideoWeaver for Vec<u8> {
    fn weave_video(
        &self,
        frames: Vec<Vec<u8>>,
        sequence: StorageSequence,
        fps: Fps,
        volley: VolleyId,
    ) -> VideoShard {
        let raw_bytes = postcard::to_allocvec(&frames).unwrap_or_default();
        VideoShard {
            timestamp: PhalanxTimestamp::now(),
            sequence_id: sequence,
            payload: DataPayload::Compressed(compress_payload(&raw_bytes)),
            fps,
            volley_id: volley,
            lens_metrics: ForensicMetrics::default(),
        }
    }
}

// --- FOUNTAIN CHUNKIFIER ---

/// The formal trait for slicing forensic evidence into RaptorQ fountain-coded
/// network symbols. Each symbol is self-describing: prefixed with 12 bytes of
/// ObjectTransmissionInformation so the receiver can initialize the decoder
/// from ANY received symbol.
pub trait FountainChunkifier {
    fn fountain_chunkify(
        &self,
        shard_id: ShardId,
        owner_did: Did,
        symbol_size: SymbolSize,
        chunk_type: ChunkType,
        repair_ratio: RepairRatio,
    ) -> Result<Vec<ShardChunk>, ShardError>;
}

impl FountainChunkifier for Vec<u8> {
    fn fountain_chunkify(
        &self,
        shard_id: ShardId,
        owner_did: Did,
        symbol_size: SymbolSize,
        chunk_type: ChunkType,
        repair_ratio: RepairRatio,
    ) -> Result<Vec<ShardChunk>, ShardError> {
        if self.is_empty() {
            return Ok(Vec::new());
        }
        if symbol_size.0 == 0 {
            return Err(ShardError::InvalidSize("Symbol size cannot be zero".into()));
        }

        // Create RaptorQ encoder
        let encoder = Encoder::with_defaults(self, symbol_size.0 as u16);
        let config = encoder.get_config();
        let oti_bytes = config.serialize(); // [u8; 12]

        // Calculate repair symbol count from ratio
        // source_symbols ≈ ceil(data_len / symbol_size)
        let source_symbol_count = (self.len() as f32 / symbol_size.0 as f32).ceil() as u32;
        let repair_count =
            ((source_symbol_count as f32) * (repair_ratio.get() - 1.0)).ceil() as u32;

        // Generate source + repair packets
        let packets = encoder.get_encoded_packets(repair_count);
        let total = packets.len();
        let last_index = total.saturating_sub(1);
        let timestamp = PhalanxTimestamp::now();

        // Build ShardChunks with OTI prefix on each symbol
        let chunks = packets
            .into_iter()
            .enumerate()
            .map(|(i, packet)| {
                let esi = packet.payload_id().encoding_symbol_id();
                let symbol_data = packet.data().to_vec();

                // Prefix with OTI (12 bytes) — 1% overhead at 1,200-byte symbols
                let mut data = Vec::with_capacity(OTI_PREFIX_LEN + symbol_data.len());
                data.extend_from_slice(&oti_bytes);
                data.extend_from_slice(&symbol_data);

                ShardChunk {
                    shard_id,
                    encoding_symbol_id: EncodingSymbolId(esi),
                    is_terminal: i == last_index,
                    data,
                    owner_did: owner_did.clone(),
                    chunk_type,
                    timestamp,
                }
            })
            .collect();

        Ok(chunks)
    }
}

// --- TEST UTILITIES ---

/// Test helper: creates fountain-coded ShardChunks from raw data.
/// Uses the actual production encode path — no dead code under test.
#[cfg(test)]
pub fn make_test_fountain_chunks(
    data: &[u8],
    shard_id: ShardId,
    owner: Did,
    symbol_size: SymbolSize,
) -> Vec<ShardChunk> {
    data.to_vec()
        .fountain_chunkify(
            shard_id,
            owner,
            symbol_size,
            ChunkType::Witnessed,
            RepairRatio::default(), // 1.5× repair
        )
        .expect("Test fountain encoding should not fail")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::judge::PayloadCipher;
    use crate::witness::WitnessAuthority;
    use phalanx_proto::crypto::SymmetricKey;
    use phalanx_proto::evidence::{Evidence, SignatureHash};
    use phalanx_proto::identity::PhalanxIdentity;
    use phalanx_proto::prelude::PendingEgress;
    use phalanx_proto::storage::HandoverProof;

    fn get_test_key() -> SymmetricKey {
        SymmetricKey([0x42; 32])
    }

    struct MockJournal;

    #[async_trait::async_trait]
    impl TransientJournal for MockJournal {
        async fn record_chunk(&mut self, _chunk: &ShardChunk) -> Result<(), ShardError> {
            Ok(())
        }
        async fn sync(&mut self) -> Result<(), ShardError> {
            Ok(())
        }
        async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError> {
            Ok(vec![])
        }
        async fn clear(&mut self) -> Result<(), ShardError> {
            Ok(())
        }
        async fn record_pending_egress(
            &mut self,
            _pending: &[PendingEgress],
        ) -> Result<(), ShardError> {
            Ok(())
        }
        async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_video_shard_encryption_cycle() -> Result<(), Box<dyn std::error::Error>> {
        let frames = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let seq = StorageSequence(100);

        let mut shard = create_video_shard(
            frames.clone(),
            seq,
            Fps::new(30),
            "volley_1".into(),
            ForensicMetrics::default(),
        )?;

        // create_video_shard produces Compressed payload
        if let DataPayload::Compressed(data) = &shard.payload {
            let decompressed = decompress_payload(data).expect("Decompression failed");
            let deserialized_frames: Vec<Vec<u8>> = postcard::from_bytes(&decompressed)?;
            assert_eq!(deserialized_frames, frames);
        } else {
            panic!("Newly created shard should be DataPayload::Compressed");
        }

        let key = get_test_key();
        shard.payload.apply_encryption(&key)?;

        match &shard.payload {
            DataPayload::Encrypted { nonce, ciphertext } => {
                assert_eq!(nonce.len(), 24, "XChaCha20Poly1305 requires 24-byte nonce");
                assert!(!ciphertext.is_empty(), "Ciphertext should not be empty");
            }
            _ => panic!("Shard payload should be Encrypted"),
        }

        // reveal() returns the compressed bytes; decompress to recover frames
        let decrypted_bytes = shard.payload.reveal(&key)?;
        let decompressed = decompress_payload(&decrypted_bytes).expect("Decompression failed");
        let recovered_frames: Vec<Vec<u8>> = postcard::from_bytes(&decompressed)?;
        assert_eq!(recovered_frames, frames);

        Ok(())
    }

    #[test]
    fn test_audio_shard_encryption_cycle() -> Result<(), Box<dyn std::error::Error>> {
        let audio_data = vec![10, 20, 30, 40];
        let seq = StorageSequence(200);
        let mut shard = create_audio_shard(
            audio_data.clone(),
            seq,
            SampleRate::new(44100),
            ChannelCount::new(2),
            "volley_2".into(),
        )?;

        let key = get_test_key();
        shard.payload.apply_encryption(&key)?;

        // reveal() returns compressed bytes; decompress to recover audio
        let decrypted_bytes = shard.payload.reveal(&key)?;
        let decompressed = decompress_payload(&decrypted_bytes).expect("Decompression failed");
        assert_eq!(decompressed, audio_data);

        Ok(())
    }

    #[test]
    fn test_double_encryption_idempotency() -> Result<(), Box<dyn std::error::Error>> {
        let frames = vec![vec![1]];
        let mut shard = create_video_shard(
            frames,
            StorageSequence(1),
            Fps::new(30),
            "v1".into(),
            ForensicMetrics::default(),
        )?;
        let key = get_test_key();

        shard.payload.apply_encryption(&key)?;

        let (nonce1, cipher1) = match &shard.payload {
            DataPayload::Encrypted { nonce, ciphertext } => (nonce.clone(), ciphertext.clone()),
            _ => panic!("Should be encrypted"),
        };

        // Second call should be idempotent (already encrypted)
        shard.payload.apply_encryption(&key)?;

        match &shard.payload {
            DataPayload::Encrypted { nonce, ciphertext } => {
                assert_eq!(nonce, &nonce1, "Nonce changed on second encrypt call");
                assert_eq!(
                    ciphertext, &cipher1,
                    "Ciphertext changed on second encrypt call"
                );
            }
            _ => panic!("Should remain encrypted"),
        }

        Ok(())
    }

    #[test]
    fn test_serialization_roundtrip_encrypted() -> Result<(), Box<dyn std::error::Error>> {
        let frames = vec![vec![255, 0, 255]];
        let mut shard = create_video_shard(
            frames,
            StorageSequence(50),
            Fps::new(60),
            "v_net".into(),
            ForensicMetrics::default(),
        )?;
        let key = get_test_key();

        shard.payload.apply_encryption(&key)?;

        let wire_data = postcard::to_allocvec(&shard)?;
        let received_shard: VideoShard = postcard::from_bytes(&wire_data)?;

        let decrypted_payload = received_shard.payload.reveal(&key)?;
        let decompressed = decompress_payload(&decrypted_payload).expect("Decompression failed");
        let recovered_frames: Vec<Vec<u8>> = postcard::from_bytes(&decompressed)?;

        assert_eq!(recovered_frames[0], vec![255, 0, 255]);
        assert_eq!(received_shard.sequence_id.0, 50);
        assert_eq!(received_shard.volley_id, "v_net".into());

        Ok(())
    }

    // --- FOUNTAIN CODE TESTS ---

    #[test]
    fn test_fountain_roundtrip_encode_decode() {
        // Create a real WitnessEnvelope
        let identity = PhalanxIdentity::new_ephemeral();
        let evidence = Evidence::Video(VideoShard {
            timestamp: PhalanxTimestamp::now(),
            sequence_id: StorageSequence(1),
            fps: Fps::new(30),
            volley_id: VolleyId::new("fountain_test"),
            payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            lens_metrics: ForensicMetrics::default(),
        });
        let original_envelope =
            WitnessEnvelope::sign_envelope(evidence, &identity, identity.network_id.clone(), None)
                .expect("Failed to sign envelope");

        let serialized = postcard::to_allocvec(&original_envelope).expect("serialize");

        // Fountain-encode into symbols
        let shard_id = ShardId(42);
        let chunks =
            make_test_fountain_chunks(&serialized, shard_id, identity.did.clone(), SymbolSize(256));
        assert!(!chunks.is_empty(), "Should produce at least one symbol");
        assert!(
            chunks.last().unwrap().is_terminal,
            "Last symbol must be terminal"
        );

        // Decode by feeding ALL symbols through ShardMold
        let mold = ShardMold;
        let mut acc = ShardMold::init_accumulator(&chunks[0]);
        for chunk in &chunks {
            let _ = ShardMold::ingest(&mut acc, chunk.clone());
        }

        assert!(
            ShardMold::is_ready(&acc, std::time::Duration::ZERO),
            "Decoder should complete with all symbols"
        );

        let recovered = mold
            .assemble(shard_id, acc)
            .expect("Assembly should succeed");
        assert_eq!(
            recovered.witness_signature, original_envelope.witness_signature,
            "Cryptographic integrity must survive fountain encode/decode"
        );
    }

    #[test]
    fn test_fountain_survives_30_percent_loss() {
        // Create and serialize envelope
        let identity = PhalanxIdentity::new_ephemeral();
        let evidence = Evidence::Video(VideoShard {
            timestamp: PhalanxTimestamp::now(),
            sequence_id: StorageSequence(1),
            fps: Fps::new(30),
            volley_id: VolleyId::new("loss_test"),
            payload: DataPayload::Clear(vec![0xCA; 2048]), // Large enough to produce multiple symbols
            lens_metrics: ForensicMetrics::default(),
        });
        let original_envelope =
            WitnessEnvelope::sign_envelope(evidence, &identity, identity.network_id.clone(), None)
                .expect("sign");

        let serialized = postcard::to_allocvec(&original_envelope).expect("serialize");

        // Fountain-encode with 1.5x repair ratio (50% redundancy)
        let shard_id = ShardId(99);
        let all_chunks = make_test_fountain_chunks(
            &serialized,
            shard_id,
            identity.did.clone(),
            SymbolSize(128), // Small symbols → more symbols → better loss test
        );

        // Verify we have enough symbols to lose 30%
        assert!(
            all_chunks.len() >= 4,
            "Need enough symbols for meaningful loss test, got {}",
            all_chunks.len()
        );

        // Drop 30% of symbols (simulating network loss)
        let keep_count = (all_chunks.len() as f64 * 0.7).ceil() as usize;
        let surviving_chunks: Vec<_> = all_chunks.into_iter().take(keep_count).collect();

        // Attempt decode with only surviving symbols
        let mold = ShardMold;
        let mut acc = ShardMold::init_accumulator(&surviving_chunks[0]);
        for chunk in &surviving_chunks {
            let _ = ShardMold::ingest(&mut acc, chunk.clone());
        }

        assert!(
            ShardMold::is_ready(&acc, std::time::Duration::ZERO),
            "Decoder should recover from 30% symbol loss (had {}/{} symbols)",
            surviving_chunks.len(),
            keep_count
        );

        let recovered = mold
            .assemble(shard_id, acc)
            .expect("Assembly should succeed despite packet loss");
        assert_eq!(
            recovered.witness_signature, original_envelope.witness_signature,
            "Integrity preserved after loss recovery"
        );
    }

    #[tokio::test]
    async fn test_reassembler_fountain_roundtrip() {
        let identity = PhalanxIdentity::new_ephemeral();
        let mut reassembler = Reassembler::new();
        let mut journal = MockJournal;

        // Create and serialize a real WitnessEnvelope
        let evidence = Evidence::Video(VideoShard {
            timestamp: PhalanxTimestamp::now(),
            sequence_id: StorageSequence(1),
            fps: Fps::new(30),
            volley_id: VolleyId::new("reassembler_test"),
            payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            lens_metrics: ForensicMetrics::default(),
        });
        let original_envelope =
            WitnessEnvelope::sign_envelope(evidence, &identity, identity.network_id.clone(), None)
                .expect("sign");

        let serialized = postcard::to_allocvec(&original_envelope).expect("serialize");

        // Fountain-encode
        let chunks = make_test_fountain_chunks(
            &serialized,
            ShardId(77),
            identity.did.clone(),
            SymbolSize(256),
        );

        // Feed chunks through the Reassembler
        let mut final_result = None;
        for chunk in chunks {
            let result = reassembler
                .ingest_chunk(chunk, &mut journal)
                .await
                .expect("ingest should not fail");

            if let Some(state) = result {
                final_result = Some(state);
                break; // Decoder completed
            }
        }

        // Verify
        let recovered = match final_result.expect("Should have decoded") {
            EnvelopeState::Intact(env) => env,
        };
        assert_eq!(
            recovered.witness_signature, original_envelope.witness_signature,
            "Full pipeline: camera → encode → reassemble → envelope"
        );
        assert_eq!(
            reassembler.active_shards.active_count(),
            0,
            "Memory leak: Buffer not cleared after successful assembly"
        );
    }

    #[test]
    fn test_fountain_chunkifier_empty_data() {
        let result = Vec::<u8>::new().fountain_chunkify(
            ShardId(1),
            Did("test".into()),
            SymbolSize(256),
            ChunkType::Witnessed,
            RepairRatio::default(),
        );
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_fountain_chunkifier_zero_symbol_size() {
        let result = vec![1, 2, 3].fountain_chunkify(
            ShardId(1),
            Did("test".into()),
            SymbolSize(0),
            ChunkType::Witnessed,
            RepairRatio::default(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_fountain_symbols_carry_oti_prefix() {
        let data = vec![0xAB; 500];
        let chunks = data
            .fountain_chunkify(
                ShardId(1),
                Did("test".into()),
                SymbolSize(256),
                ChunkType::Witnessed,
                RepairRatio::new(1.0), // source only, minimum symbols
            )
            .unwrap();

        for chunk in &chunks {
            assert!(
                chunk.data.len() >= OTI_PREFIX_LEN,
                "Every symbol must carry the 12-byte OTI prefix"
            );
            // All symbols should carry the same OTI
            let oti = &chunk.data[..OTI_PREFIX_LEN];
            let first_oti = &chunks[0].data[..OTI_PREFIX_LEN];
            assert_eq!(oti, first_oti, "All symbols in a shard share the same OTI");
        }
    }

    #[test]
    fn test_shard_mold_full_reassembly() {
        let identity = PhalanxIdentity::new_ephemeral();
        let shard_id = ShardId(707);

        // Create a REAL envelope
        use ed25519_dalek::Signer;
        let envelope = WitnessEnvelope::sign_envelope(
            Evidence::Handover(HandoverProof {
                volley_id: VolleyId::new("test"),
                sequence_id: StorageSequence(0),
                old_did: identity.did.clone(),
                new_did: identity.did.clone(),
                anchor_hash: SignatureHash([0; 32]),
                old_signature: identity.keypair.sign(b"test"),
                new_signature: identity.keypair.sign(b"test"),
            }),
            &identity,
            identity.network_id.clone(),
            None,
        )
        .unwrap();

        let serialized = postcard::to_allocvec(&envelope).unwrap();

        // Fountain-encode and decode
        let chunks =
            make_test_fountain_chunks(&serialized, shard_id, identity.did.clone(), SymbolSize(256));

        let mold = ShardMold;
        let mut acc = ShardMold::init_accumulator(&chunks[0]);
        for chunk in &chunks {
            let _ = ShardMold::ingest(&mut acc, chunk.clone());
        }

        let result = mold
            .assemble(shard_id, acc)
            .expect("Should assemble successfully");
        assert_eq!(result.witness_signature, envelope.witness_signature);
    }
}
