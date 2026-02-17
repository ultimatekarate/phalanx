use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::time::Instant;
use tracing::{debug, info, instrument, warn};

/// A stateful aggregation strategy for transforming stream-based inputs into unified outputs.
///
/// The `Mold` trait defines the "logic of completion" for a specific data type. It utilizes
/// an **Accumulator** pattern, where incoming data is held in a temporary stateful buffer
/// (the `Accumulator`) until it satisfies specific readiness criteria.
///
/// This pattern is essential for reconstructing high-level objects from fragmented network
/// data, such as reassembling shards into envelopes or grouping envelopes into volleys.
pub trait Mold {
    type Input;
    type Output;
    type Key: Ord + Clone + std::fmt::Debug;
    type Accumulator;

    /// Identity derivation: Determines which bucket (Accumulator) an item belongs to.
    fn get_key(item: &Self::Input) -> Self::Key;

    /// Initialize a new buffer (accumulator) when a new key is encountered.
    fn init_accumulator(item: &Self::Input) -> Self::Accumulator;

    /// Ingests data into the existing buffer, updating the internal state of the Accumulator.
    fn ingest(acc: &mut Self::Accumulator, item: Self::Input);

    /// Evaluates whether the Accumulator has met the threshold for finalization.
    /// This can be based on the number of received items, total byte size, or elapsed time.
    fn is_ready(acc: &Self::Accumulator, elapsed: Duration) -> bool;

    /// The final transformation step: Consumes the Accumulator and produces the final Output.
    fn assemble(key: Self::Key, acc: Self::Accumulator) -> Option<Self::Output>;
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
pub struct Crucible<S: Mold> {
    /// Active work units currently being aggregated.
    contexts: BTreeMap<S::Key, WorkContext<S>>,
    /// Frequency at which internal house-cleaning is performed.
    cleanup_interval: Duration,
    /// The last time the workbench was pruned.
    last_cleanup: Instant,
}

// --- THE WRAPPER (The Work Unit) ---
// Wraps the raw data (Accumulator) with metadata (Time)
pub struct WorkContext<S: Mold> {
    pub accumulator: S::Accumulator,
    pub created_at: Instant,
}

impl<S: Mold> Crucible<S> {
    pub fn new() -> Self {
        Self {
            contexts: BTreeMap::new(),
            cleanup_interval: Duration::from_secs(1),
            last_cleanup: Instant::now(),
        }
    }

    pub fn len(&self) -> usize {
        self.contexts.len()
    }

    #[instrument(skip(self, item), level = "info")]
    pub fn process(&mut self, item: S::Input) -> Option<S::Output> {
        self.perform_cleanup();
        let key = S::get_key(&item);

        // 1. INGEST (Unified Logic)
        let (is_ready_now, elapsed) = match self.contexts.entry(key.clone()) {
            Entry::Occupied(mut entry) => {
                let ctx = entry.get_mut();
                S::ingest(&mut ctx.accumulator, item);
                // Check readiness against elapsed time
                let el = ctx.created_at.elapsed();

                (S::is_ready(&ctx.accumulator, el), el)
            }
            Entry::Vacant(entry) => {
                let ctx = entry.insert(WorkContext {
                    accumulator: S::init_accumulator(&item),
                    created_at: Instant::now(),
                });
                // Check readiness IMMEDIATELY (Elapsed = 0)
                // Critical for 0-latency configs
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
        }

        // 2. EJECT (If ready)
        if is_ready_now {
            info!(?key, ?elapsed, "Crucible: Item READY. Sealing...");
            if let Some(ctx) = self.contexts.remove(&key) {
                return S::assemble(key, ctx.accumulator);
            }
        }

        None
    }

    pub fn active_count(&self) -> usize {
        self.contexts.len()
    }

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
        if active_count > 0 {
            info!(
                count = active_count,
                ttl_ms = ttl.as_millis(),
                "Crucible checking for stale sessions..."
            );
        }

        for (key, ctx) in &self.contexts {
            let age = ctx.created_at.elapsed();
            if age >= ttl {
                warn!(
                    ?key,
                    age_ms = age.as_millis(),
                    "Crucible: FOUND STALE SESSION. Flushing."
                );
                ready_keys.push(key.clone());
            } else {
                debug!(
                    ?key,
                    age_ms = age.as_millis(),
                    "Crucible: Session active (not stale yet)."
                );
            }
        }
        let mut results = Vec::new();
        for key in ready_keys {
            if let Some(ctx) = self.contexts.remove(&key) {
                if let Some(out) = S::assemble(key, ctx.accumulator) {
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
                if let Some(out) = S::assemble(key, ctx.accumulator) {
                    results.push(out);
                }
            }
        }
        results
    }
}

impl<S: Mold> Default for Crucible<S> {
    /// Initializes a default Crucible workbench with a standard 1-second cleanup interval.
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // 1. MOCK STRATEGY
    struct SumMold;
    impl Mold for SumMold {
        type Input = i32;
        type Output = String;
        type Key = String;
        type Accumulator = Vec<i32>;

        fn get_key(_item: &i32) -> String {
            "fixed_key".to_string()
        }
        fn init_accumulator(item: &i32) -> Vec<i32> {
            vec![*item]
        }
        fn ingest(acc: &mut Vec<i32>, item: i32) {
            acc.push(item);
        }

        fn is_ready(acc: &Vec<i32>, _elapsed: Duration) -> bool {
            acc.len() >= 3 // Ready when we have 3 items
        }

        fn assemble(_key: String, acc: Vec<i32>) -> Option<String> {
            let sum: i32 = acc.iter().sum();
            Some(format!("Sum: {}", sum))
        }
    }

    // FIX: Must use tokio::test because Crucible::new() calls tokio::time::Instant::now()
    #[tokio::test]
    async fn test_crucible_auto_seal() {
        let mut crucible = Crucible::<SumMold>::new();

        // 1. Ingest 2 items (Not ready)
        assert!(crucible.process(10).is_none());
        assert!(crucible.process(20).is_none());

        // 2. Ingest 3rd item (Trigger Seal)
        let result = crucible.process(30);
        assert_eq!(result, Some("Sum: 60".to_string()));

        // 3. Verify Workbench is empty
        assert!(crucible.contexts.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn test_crucible_flush_stale() {
        let mut crucible = Crucible::<SumMold>::new();

        // 1. Ingest 1 item (Stale)
        crucible.process(5);

        // 2. Advance time beyond threshold
        // Since we are paused, this explicitly moves the clock forward
        tokio::time::advance(Duration::from_secs(10)).await;

        // 3. Flush (Threshold is 5s, we waited 10s)
        let results = crucible.flush_stale(Duration::from_secs(5));

        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "Sum: 5");
    }

    #[tokio::test]
    async fn test_crucible_flush_all() {
        let mut crucible = Crucible::<SumMold>::new();
        crucible.process(1);
        crucible.process(2); // 2 items waiting

        let results = crucible.flush_all();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "Sum: 3"); // 1+2
    }
}
