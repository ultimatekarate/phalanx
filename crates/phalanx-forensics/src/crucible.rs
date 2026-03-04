use phalanx_proto::evidence::Evidence;
use phalanx_proto::evidence::ForensicGap;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::identity::Volley;
use phalanx_proto::prelude::*;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::time::Duration;
use std::time::Instant;
use tracing::{debug, info, instrument};
use tracing::{error, warn};

fn default_cleanup_interval() -> Duration {
    Duration::from_secs(1)
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
///
/// This pattern is essential for reconstructing high-level objects from fragmented network
/// data, such as reassembling shards into envelopes or grouping envelopes into volleys.
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

    fn get_key(item: &Self::Input) -> Self::Key;
    fn init_accumulator(item: &Self::Input) -> Self::Accumulator;

    fn ingest(acc: &mut Self::Accumulator, item: Self::Input);
    fn is_ready(acc: &Self::Accumulator, elapsed: Duration) -> bool;
    fn assemble(&self, key: Self::Key, acc: Self::Accumulator) -> Option<Self::Output>;
}
/// A generic execution engine and container for stateful data aggregation.
///
/// `Crucible` acts as a "workbench" that manages multiple active **WorkContexts**.
/// It routes incoming inputs to their respective **Accumulators** based on keys derived
/// via the associated [`Mold`] strategy.
///
/// ### The Salvage Protocol: Handling Stale Data
/// In distributed mesh networks, there is no guarantee that every fragment of a data set
/// will arrive. To prevent memory exhaustion and "zombie" sessions, `Crucible` implements
/// a **Salvage Protocol** through methods like [`flush_stale`].
///
/// By tracking the `created_at` timestamp for every Accumulator, the system can identify
/// items that have exceeded a Time-To-Live (TTL) threshold. These stale items
/// are force-sealed and assembled, allowing the system to recover partial data (such as
/// a Volley with detected gaps) rather than losing the information entirely.
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
}
// --- THE WRAPPER (The Work Unit) ---
// Wraps the raw data (Accumulator) with metadata (Time)

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkContext<A> {
    pub accumulator: A,
    #[serde(skip, default = "std::time::Instant::now")]
    pub created_at: std::time::Instant,
}

impl<S: Mold> Crucible<S> {
    #[must_use]
    pub fn new(strategy: S, _cleanup_interval: Duration) -> Self {
        Self {
            strategy,
            contexts: std::collections::BTreeMap::new(),
            last_cleanup: std::time::Instant::now(),
            cleanup_interval: Duration::from_secs(1),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.contexts.len()
    }

    #[instrument(skip(self, item), level = "info")]
    pub fn process(&mut self, item: S::Input) -> Option<S::Output> {
        self.perform_cleanup();
        let key = S::get_key(&item);

        let (is_ready_now, elapsed) = match self.contexts.entry(key.clone()) {
            Entry::Occupied(mut entry) => {
                let ctx = entry.get_mut();
                S::ingest(&mut ctx.accumulator, item);
                let el = ctx.created_at.elapsed();

                (S::is_ready(&ctx.accumulator, el), el)
            }
            Entry::Vacant(entry) => {
                // Initialize the empty accumulator
                let mut acc = S::init_accumulator(&item);

                // FIX: Actually ingest the first item!
                S::ingest(&mut acc, item);

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
            return None; // Ensure we exit if not ready
        }

        info!(?key, ?elapsed, "Crucible: Item READY. Sealing...");
        if let Some(ctx) = self.contexts.remove(&key) {
            // FIX: Call assemble on the instance
            return self.strategy.assemble(key, ctx.accumulator);
        }

        None
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

    /// Orchestrates the "Salvage Protocol" for the workbench.
    ///
    /// Iterates through all active WorkContexts and force-seals any Accumulators
    /// that have exceeded the defined Duration. This ensures partial data is
    /// archived rather than leaked during peer disconnection.
    pub fn flush_stale(&mut self, ttl: Duration) -> Vec<S::Output> {
        let mut ready_keys = Vec::new();
        let active_count = self.contexts.len();
        let now = Instant::now(); // FORENSIC: Capture reference time

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
                // Assemble immediately regardless of state
                if let Some(out) = self.strategy.assemble(key, ctx.accumulator) {
                    results.push(out);
                }
            }
        }
        results
    }
}

impl<S: Mold + Default> Default for Crucible<S> {
    /// Initializes a default Crucible workbench with a standard 1-second cleanup interval.
    fn default() -> Self {
        // Use the strategy's default and our standard 1s interval
        Self::new(S::default(), Duration::from_secs(1))
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

impl Mold for VolleyAmalgam {
    type Input = WitnessEnvelope;
    type Output = Volley;
    type Key = VolleyId;
    type Accumulator = VolleyBuffer;

    fn get_key(item: &Self::Input) -> Self::Key {
        item.evidence.volley_id().clone()
    }

    fn init_accumulator(item: &Self::Input) -> Self::Accumulator {
        let mut artifacts = BTreeMap::new();
        artifacts.insert(item.evidence.sequence_id(), item.clone());

        VolleyBuffer {
            artifacts,
            volley_id: item.evidence.volley_id().clone(),
            owner_did: item.did.clone(),
        }
    }

    fn ingest(acc: &mut Self::Accumulator, item: Self::Input) {
        let seq = item.evidence.sequence_id();

        match &item.evidence {
            Evidence::Handover(proof) => {
                // 1. Verify the bridge connects to the CURRENT legal owner
                if proof.old_did == acc.owner_did {
                    tracing::info!(
                        volley = %acc.volley_id,
                        "Crucible: Advancing stream ownership via HandoverProof"
                    );

                    // Transfer legal ownership of the active buffer
                    acc.owner_did = proof.new_did.clone();
                    acc.artifacts.insert(seq, item);
                } else {
                    tracing::warn!(
                        volley = %acc.volley_id,
                        "Crucible rejected HandoverProof: Unauthorized origin"
                    );
                }
            }
            _ => {
                // 2. Standard Frame Verification
                if item.did == acc.owner_did {
                    acc.artifacts.insert(seq, item);
                } else {
                    // ZERO-TRUST DROP: Prevent buffer bloat from malicious peers
                    tracing::warn!(
                        volley = %acc.volley_id,
                        seq = %seq.0,
                        "Crucible dropped illegal frame: Causality Breach (Identity Mismatch)"
                    );
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

        // BTreeMap guarantees we iterate by StorageSequence order
        for (seq, env) in acc.artifacts {
            let current_seq: StorageSequence = seq;

            // 1. SEQUENCE CONTINUITY CHECK
            if let Some(expected) = expected_seq {
                if current_seq > expected {
                    // Detected a sequence gap - create an attributed ForensicGap
                    gaps.push(ForensicGap {
                        volley_id: key.clone(), // FIX: Every gap belongs to the Volley
                        start_seq: expected,
                        end_seq: current_seq - 1,
                        detected_at: now,
                    });

                    // Note: A gap breaks the hash-link by definition.
                    // In a 'Healable' timeline, we reset the link anchor here.
                    last_signature_hash = None;
                }
            }

            // 2. CAUSALITY (HASH-LINK) VERIFICATION
            // Only verify link if there wasn't just a gap or if it's not the first unit
            if let (Some(expected_hash), Some(actual_link)) = (last_signature_hash, env.prev_hash) {
                if expected_hash != actual_link {
                    error!(
                        volley_id = %key,
                        seq = %current_seq.0,
                        "VolleyAmalgam: CAUSALITY BREACH - Hash link mismatch detected"
                    );
                    // In Zero-Trust, a breach means we discard the assembly to prevent corruption
                    return None;
                }
            }

            // Update state for next iteration
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

    // 1. MOCK STRATEGY
    // 1. MOCK STRATEGY - Now with Derives
    #[derive(Debug, Serialize, Deserialize, Default)]
    struct SumMold;

    impl Mold for SumMold {
        type Input = i32;
        type Output = String;
        type Key = String;
        type Accumulator = Vec<i32>;

        fn get_key(_item: &i32) -> String {
            "fixed".to_string()
        }

        fn init_accumulator(_item: &i32) -> Vec<i32> {
            vec![]
        }

        fn ingest(acc: &mut Vec<i32>, item: i32) {
            acc.push(item);
        }

        fn is_ready(acc: &Vec<i32>, _elapsed: Duration) -> bool {
            acc.len() >= 3
        }

        fn assemble(&self, _key: String, acc: Vec<i32>) -> Option<String> {
            let sum: i32 = acc.iter().sum();
            Some(format!("Sum: {}", sum))
        }
    }

    // FIXED: The Lab uses std::time::Instant, not tokio. No tokio dependency needed.
    #[test]
    fn test_crucible_auto_seal() {
        let mut crucible = Crucible::new(SumMold, Duration::from_secs(5));

        // 1. Ingest 2 items (Not ready)
        assert!(crucible.process(10).is_none());
        assert!(crucible.process(20).is_none());

        // 2. Ingest 3rd item (Trigger Seal)
        let result = crucible.process(30);
        assert_eq!(result, Some("Sum: 60".to_string()));

        // 3. Verify Workbench is empty
        assert!(crucible.contexts.is_empty());
    }

    #[test]
    fn test_crucible_flush_stale() {
        // Use a very short TTL to avoid slow tests while staying tokio-free
        let ttl = Duration::from_millis(50);
        let mut crucible = Crucible::new(SumMold, ttl);

        // 1. Ingest 1 item (Stale)
        crucible.process(5);

        // 2. Wait beyond threshold using std::thread::sleep (no tokio needed)
        std::thread::sleep(Duration::from_millis(100));

        // 3. Flush (TTL is 50ms, we waited 100ms)
        let results = crucible.flush_stale(ttl);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "Sum: 5");
    }

    #[test]
    fn test_crucible_flush_all() {
        let mut crucible = Crucible::new(SumMold, Duration::from_secs(5));
        crucible.process(1);
        crucible.process(2); // 2 items waiting

        let results = crucible.flush_all();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "Sum: 3"); // 1+2
    }
}
