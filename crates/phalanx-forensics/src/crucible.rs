use phalanx_proto::evidence::Evidence;
use phalanx_proto::evidence::ForensicGap;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::evidence::Volley;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::prelude::*;
use phalanx_proto::types::{ForensicUnit, Verified};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::time::Duration;
use std::time::Instant;
use tracing::{debug, error, info, instrument, warn};

// Placeholder constants for threshold limits
const VOLLEY_SIZE_THRESHOLD: usize = 100;
const VOLLEY_TIME_THRESHOLD: Duration = Duration::from_secs(60);

fn default_cleanup_interval() -> Duration {
    Duration::from_secs(1)
}

fn default_capacity() -> usize {
    1000
}

pub trait EnvelopeHashExt {
    fn signature_hash(&self) -> SignatureHash;
}

impl EnvelopeHashExt for WitnessEnvelope {
    fn signature_hash(&self) -> SignatureHash {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.witness_signature);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        SignatureHash(hash)
    }
}

pub trait EvidenceExt {
    fn volley_id(&self) -> &VolleyId;
    fn sequence_id(&self) -> StorageSequence;
    fn timestamp(&self) -> PhalanxTimestamp;
}

impl EvidenceExt for Evidence {
    fn volley_id(&self) -> &VolleyId {
        match self {
            Evidence::Video(s) => &s.volley_id,
            Evidence::Audio(s) => &s.volley_id,
            Evidence::Handover(h) => &h.volley_id,
            _ => unimplemented!("Add other variants here"),
        }
    }
    fn sequence_id(&self) -> StorageSequence {
        match self {
            Evidence::Video(s) => s.sequence_id,
            Evidence::Audio(s) => s.sequence_id,
            Evidence::Handover(h) => h.sequence_id,
            _ => unimplemented!("Add other variants here"),
        }
    }
    fn timestamp(&self) -> PhalanxTimestamp {
        match self {
            Evidence::Video(s) => s.timestamp,
            Evidence::Audio(s) => s.timestamp,
            // Handover doesn't have a time in the struct, so we default to now or add it to proto later
            _ => PhalanxTimestamp::now(),
        }
    }
}

/// A stateful aggregation strategy for transforming stream-based inputs into unified outputs.
///
/// The `Mold` trait defines the "logic of completion" for a specific data type. It utilizes
/// an **Accumulator** pattern, where incoming data is held in a temporary stateful buffer
/// (the `Accumulator`) until it satisfies specific readiness criteria.
pub trait Mold: Send + Sync + Serialize + for<'de> Deserialize<'de> {
    type Input;
    type Output;
    // ENFORCEMENT: Keys must be serializable to reconstruct the BTreeMap
    type Key: Ord
        + Clone
        + std::fmt::Debug
        + Serialize
        + DeserializeOwned
        + std::hash::Hash
        + Eq
        + std::fmt::Display;
    // ENFORCEMENT: Accumulators must serialize their internal byte states
    type Accumulator: Serialize + DeserializeOwned;
    // ENFORCEMENT: Strategies must define a failure state for active backpressure
    type Error: std::fmt::Debug + std::error::Error + Send + Sync + 'static;

    fn get_key(item: &Self::Input) -> Self::Key;
    fn init_accumulator(item: &Self::Input) -> Self::Accumulator;

    // GUARDIAN GATE: Ingest now returns a Result to reject adversarial data
    fn ingest(acc: &mut Self::Accumulator, item: Self::Input) -> Result<(), Self::Error>;
    fn is_ready(acc: &Self::Accumulator, elapsed: Duration) -> bool;
    fn assemble(&self, key: Self::Key, acc: Self::Accumulator) -> Option<Self::Output>;
}

/// A generic execution engine and container for stateful data aggregation.
#[derive(Debug, Serialize, Deserialize)]
#[serde(
    bound = "S::Key: Serialize + DeserializeOwned, S::Accumulator: Serialize + DeserializeOwned"
)]
pub struct Crucible<S: Mold> {
    strategy: S,
    pub contexts: BTreeMap<S::Key, WorkContext<S::Accumulator>>,
    #[serde(skip, default = "std::time::Instant::now")]
    pub last_cleanup: std::time::Instant,

    #[serde(skip, default = "default_cleanup_interval")]
    pub cleanup_interval: Duration,

    #[serde(skip, default = "default_capacity")]
    pub max_capacity: usize,
}

// --- THE WRAPPER (The Work Unit) ---
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkContext<A> {
    pub accumulator: A,
    #[serde(skip, default = "std::time::Instant::now")]
    pub created_at: std::time::Instant,
}

impl<S: Mold> Crucible<S> {
    #[must_use]
    pub fn new(strategy: S, cleanup_interval: Duration, max_capacity: usize) -> Self {
        Self {
            strategy,
            contexts: std::collections::BTreeMap::new(),
            last_cleanup: std::time::Instant::now(),
            cleanup_interval,
            max_capacity,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.contexts.len()
    }

    #[instrument(skip(self, item), level = "info")]
    pub fn process(&mut self, item: S::Input) -> Result<Option<S::Output>, S::Error> {
        self.perform_cleanup();
        let key = S::get_key(&item);
        let active_contexts = self.contexts.len();

        let (is_ready_now, elapsed) = match self.contexts.entry(key.clone()) {
            Entry::Occupied(mut entry) => {
                let ctx = entry.get_mut();

                // If ingestion fails (e.g., policy breach), the error is propagated
                S::ingest(&mut ctx.accumulator, item)?;
                let el = ctx.created_at.elapsed();

                (S::is_ready(&ctx.accumulator, el), el)
            }
            Entry::Vacant(entry) => {
                if active_contexts >= self.max_capacity {
                    warn!("Crucible capacity exceeded. Dropping item.");
                    return Ok(None);
                }

                let mut acc = S::init_accumulator(&item);

                // First item is also subject to validation
                S::ingest(&mut acc, item)?;

                let ctx = entry.insert(WorkContext {
                    accumulator: acc,
                    created_at: Instant::now(),
                });

                (
                    S::is_ready(&ctx.accumulator, Duration::ZERO),
                    Duration::ZERO,
                )
            }
        };

        if !is_ready_now {
            debug!(
                ?key,
                ?elapsed,
                "Crucible: Item ingested but NOT ready to seal."
            );
            return Ok(None);
        }

        info!(?key, ?elapsed, "Crucible: Item READY. Sealing...");
        if let Some(ctx) = self.contexts.remove(&key) {
            return Ok(self.strategy.assemble(key, ctx.accumulator));
        }

        Ok(None)
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.contexts.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.contexts.is_empty()
    }

    pub fn get(&self, key: &S::Key) -> Option<&S::Accumulator> {
        self.contexts.get(key).map(|ctx| &ctx.accumulator)
    }

    fn perform_cleanup(&mut self) {
        if self.last_cleanup.elapsed() > self.cleanup_interval {
            self.last_cleanup = Instant::now();
        }
    }

    pub fn flush_stale(&mut self, ttl: Duration) -> Vec<S::Output> {
        let mut ready_keys = Vec::new();
        let active_count = self.contexts.len();
        let now = Instant::now();

        if active_count > 0 {
            info!(
                target: "phalanx::forensics",
                count = active_count,
                ttl_ms = ttl.as_millis(),
                "CRUCIBLE_FLUSH_START"
            );
        }

        for (key, ctx) in &self.contexts {
            let age = now.duration_since(ctx.created_at);
            let is_stale = age >= ttl;

            info!(
                target: "phalanx::forensics",
                ?key,
                age_ms = age.as_millis(),
                ttl_ms = ttl.as_millis(),
                stale = is_stale,
                "CRUCIBLE_STALE_CHECK"
            );

            if is_stale {
                ready_keys.push(key.clone());
            }
        }

        let mut results = Vec::new();
        for key in ready_keys {
            if let Some(ctx) = self.contexts.remove(&key) {
                info!(target: "phalanx::forensics", ?key, "CRUCIBLE_EJECTING_STALE_KEY");
                if let Some(out) = self.strategy.assemble(key, ctx.accumulator) {
                    results.push(out);
                }
            }
        }
        results
    }

    pub fn flush_all(&mut self) -> Vec<S::Output> {
        let keys: Vec<S::Key> = self.contexts.keys().cloned().collect();
        let mut results = Vec::new();

        for key in keys {
            if let Some(ctx) = self.contexts.remove(&key) {
                if let Some(out) = self.strategy.assemble(key, ctx.accumulator) {
                    results.push(out);
                }
            }
        }
        results
    }

    pub fn freeze(&self) -> Result<Vec<u8>, ShardError> {
        postcard::to_allocvec(self).map_err(|e| ShardError::SerializationError(e.to_string()))
    }

    pub fn thaw(bytes: &[u8]) -> Result<Self, ShardError> {
        postcard::from_bytes(bytes).map_err(|e| ShardError::SerializationError(e.to_string()))
    }
}

impl<S: Mold + Default> Default for Crucible<S> {
    fn default() -> Self {
        Self::new(S::default(), Duration::from_secs(1), default_capacity())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolleyBuffer {
    pub artifacts: BTreeMap<StorageSequence, WitnessEnvelope>,
    pub volley_id: VolleyId,
    pub owner_did: Did,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VolleyAmalgam;

// Define a concrete error type for VolleyAmalgam rejections
#[derive(Debug, thiserror::Error)]
pub enum AmalgamError {
    #[error("Unauthorized Handover: Origin DID mismatch")]
    UnauthorizedHandover,
    #[error("Identity Mismatch: Frame DID does not match Volley owner")]
    IdentityMismatch,
}

impl Mold for VolleyAmalgam {
    type Input = ForensicUnit<WitnessEnvelope, Verified>;
    type Output = Volley;
    type Key = VolleyId;
    type Accumulator = VolleyBuffer;
    type Error = AmalgamError;

    fn get_key(item: &Self::Input) -> Self::Key {
        item.data.evidence.volley_id().clone()
    }

    fn init_accumulator(item: &Self::Input) -> Self::Accumulator {
        let mut artifacts = BTreeMap::new();
        artifacts.insert(item.data.evidence.sequence_id(), item.data.clone());

        VolleyBuffer {
            artifacts,
            volley_id: item.data.evidence.volley_id().clone(),
            owner_did: item.data.did.clone(),
        }
    }

    fn ingest(acc: &mut Self::Accumulator, item: Self::Input) -> Result<(), Self::Error> {
        let seq = item.data.evidence.sequence_id();

        match &item.data.evidence {
            Evidence::Handover(proof) => {
                if proof.old_did == acc.owner_did {
                    tracing::info!(
                        volley = %acc.volley_id,
                        "Crucible: Advancing stream ownership via HandoverProof"
                    );
                    acc.owner_did = proof.new_did.clone();
                    acc.artifacts.insert(seq, item.data);
                    Ok(())
                } else {
                    tracing::warn!(
                        volley = %acc.volley_id,
                        "Crucible rejected HandoverProof: Unauthorized origin"
                    );
                    // ACTIVE REJECTION: Signals the Sentinel to drop connection/penalize peer
                    Err(AmalgamError::UnauthorizedHandover)
                }
            }
            _ => {
                if item.data.did == acc.owner_did {
                    acc.artifacts.insert(seq, item.data);
                    Ok(())
                } else {
                    tracing::warn!(
                        volley = %acc.volley_id,
                        seq = %seq.0,
                        "Crucible dropped illegal frame: Causality Breach (Identity Mismatch)"
                    );
                    Err(AmalgamError::IdentityMismatch)
                }
            }
        }
    }

    fn is_ready(acc: &Self::Accumulator, elapsed: Duration) -> bool {
        acc.artifacts.len() >= VOLLEY_SIZE_THRESHOLD || elapsed > VOLLEY_TIME_THRESHOLD
    }

    fn assemble(&self, key: VolleyId, acc: Self::Accumulator) -> Option<Self::Output> {
        if acc.artifacts.is_empty() {
            return None;
        }

        let mut sorted_envelopes: Vec<WitnessEnvelope> = Vec::with_capacity(acc.artifacts.len());
        let mut gaps = Vec::new();
        let now = PhalanxTimestamp::now();

        let mut expected_seq: Option<StorageSequence> = None;
        let mut last_signature_hash: Option<SignatureHash> = None;

        for (seq, env) in acc.artifacts {
            let current_seq: StorageSequence = seq;

            if let Some(expected) = expected_seq {
                if current_seq > expected {
                    gaps.push(ForensicGap {
                        volley_id: key.clone(),
                        start_seq: expected,
                        end_seq: current_seq - 1,
                        detected_at: now,
                    });
                    last_signature_hash = None;
                }
            }

            if let (Some(expected_hash), Some(actual_link)) = (last_signature_hash, env.prev_hash) {
                if expected_hash != actual_link {
                    error!(
                        volley_id = %key,
                        seq = %current_seq.0,
                        "VolleyAmalgam: CAUSALITY BREACH - Hash link mismatch detected"
                    );
                    return None;
                }
            }

            expected_seq = Some(current_seq + 1);
            last_signature_hash = Some(env.signature_hash());
            sorted_envelopes.push(env);
        }

        info!(
            volley_id = %key,
            artifacts = %sorted_envelopes.len(),
            gaps = %gaps.len(),
            "VolleyAmalgam: Finalized chain with verified causality"
        );

        let gaps_2 = gaps.clone();

        Some(Volley {
            id: key.clone(),
            owner_did: acc.owner_did,
            artifacts: sorted_envelopes,
            gaps,
            is_complete: gaps_2.is_empty(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[derive(Debug, Serialize, Deserialize, Default)]
    struct SumMold;

    // Define a dummy error for the test mold
    #[derive(Debug, thiserror::Error)]
    #[error("SumMoldError")]
    struct SumError;

    impl Mold for SumMold {
        type Input = i32;
        type Output = String;
        type Key = String;
        type Accumulator = Vec<i32>;
        type Error = SumError;

        fn get_key(_item: &i32) -> String {
            "fixed".to_string()
        }

        fn init_accumulator(_item: &i32) -> Vec<i32> {
            vec![]
        }

        fn ingest(acc: &mut Vec<i32>, item: i32) -> Result<(), Self::Error> {
            acc.push(item);
            Ok(())
        }

        fn is_ready(acc: &Vec<i32>, _elapsed: Duration) -> bool {
            acc.len() >= 3
        }

        fn assemble(&self, _key: String, acc: Vec<i32>) -> Option<String> {
            let sum: i32 = acc.iter().sum();
            Some(format!("Sum: {}", sum))
        }
    }

    #[test]
    fn test_crucible_auto_seal() {
        let mut crucible = Crucible::new(SumMold, Duration::from_secs(5), 100);

        // Process returns a Result now, so we unwrap the Ok
        assert!(crucible.process(10).unwrap().is_none());
        assert!(crucible.process(20).unwrap().is_none());

        let result = crucible.process(30).unwrap();
        assert_eq!(result, Some("Sum: 60".to_string()));

        assert!(crucible.contexts.is_empty());
    }

    #[test]
    fn test_crucible_flush_stale() {
        let ttl = Duration::from_millis(50);
        let mut crucible = Crucible::new(SumMold, ttl, 100);

        crucible.process(5).unwrap();

        std::thread::sleep(Duration::from_millis(100));

        let results = crucible.flush_stale(ttl);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "Sum: 5");
    }

    #[test]
    fn test_crucible_flush_all() {
        let mut crucible = Crucible::new(SumMold, Duration::from_secs(5), 100);
        crucible.process(1).unwrap();
        crucible.process(2).unwrap();

        let results = crucible.flush_all();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "Sum: 3");
    }
}
