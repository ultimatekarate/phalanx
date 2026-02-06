use std::collections::BTreeMap;
use std::time::{Duration};
use tokio::time::Instant;

// --- THE GENERIC TRAIT (The Strategy) ---
pub trait Mold {
    type Input;
    type Output;
    type Key: Ord + Clone;      
    type Accumulator;           

    /// Identity derivation: Who does this item belong to?
    fn get_key(item: &Self::Input) -> Self::Key;

    /// Initialize a new buffer (accumulator)
    fn init_accumulator(item: &Self::Input) -> Self::Accumulator;

    /// Add data to the buffer
    fn ingest(acc: &mut Self::Accumulator, item: Self::Input);

    /// Check if the buffer is ready to be sealed (Size or Time)
    fn is_ready(acc: &Self::Accumulator, elapsed: Duration) -> bool;

    /// Transform the buffer into the final Output
    fn assemble(key: Self::Key, acc: Self::Accumulator) -> Option<Self::Output>;
}

// --- THE CONTAINER (The Workbench) ---
pub struct Crucible<S: Mold> {
    // PUBLIC: Allows Stronghold to inspect active work (e.g., for tests or status API)
    pub contexts: BTreeMap<S::Key, WorkContext<S>>,
    cleanup_interval: Duration,
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

    pub fn process(&mut self, item: S::Input) -> Option<S::Output> {
        self.perform_cleanup();

        let key = S::get_key(&item);
        
        let ctx = self.contexts
            .entry(key.clone())
            .or_insert_with(|| WorkContext {
                accumulator: S::init_accumulator(&item),
                created_at: Instant::now(),
            });

        S::ingest(&mut ctx.accumulator, item);

        if S::is_ready(&ctx.accumulator, ctx.created_at.elapsed()) {
            // "Seal" the work: Remove from workbench and assemble
            if let Some(removed_ctx) = self.contexts.remove(&key) {
                return S::assemble(key, removed_ctx.accumulator);
            }
        }

        None
    }

    fn perform_cleanup(&mut self) {
        if self.last_cleanup.elapsed() > self.cleanup_interval {
            self.last_cleanup = Instant::now();
        }
    }
    
    /// Salvage Protocol: Force-finish items that have been on the workbench too long
    pub fn flush_stale(&mut self, ttl: Duration) -> Vec<S::Output> {
        let mut ready_keys = Vec::new();
        
        for (key, ctx) in &self.contexts {
            if ctx.created_at.elapsed() >= ttl {
                ready_keys.push(key.clone());
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

// ... (existing code in src/crucible.rs)

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // 1. MOCK STRATEGY
    // A simple integer summer: Sums 3 integers, then returns the total string.
    struct SumMold;
    impl Mold for SumMold {
        type Input = i32;
        type Output = String;
        type Key = String;
        type Accumulator = Vec<i32>;

        fn get_key(_item: &i32) -> String { "fixed_key".to_string() }
        
        fn init_accumulator(item: &i32) -> Vec<i32> { vec![*item] }
        
        fn ingest(acc: &mut Vec<i32>, item: i32) { acc.push(item); }
        
        fn is_ready(acc: &Vec<i32>, _elapsed: Duration) -> bool {
            acc.len() >= 3 // Ready when we have 3 items
        }
        
        fn assemble(_key: String, acc: Vec<i32>) -> Option<String> {
            let sum: i32 = acc.iter().sum();
            Some(format!("Sum: {}", sum))
        }
    }

    #[test]
    fn test_crucible_auto_seal() {
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

    #[tokio::test(start_paused = true)] // Requires "tokio" feature for time manipulation
    async fn test_crucible_flush_stale() {
        let mut crucible = Crucible::<SumMold>::new();

        // 1. Ingest 1 item (Stale)
        crucible.process(5);
        
        // 2. Advance time beyond threshold
        tokio::time::advance(Duration::from_secs(10)).await;
        
        // 3. Flush
        let results = crucible.flush_stale(Duration::from_secs(5));
        
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "Sum: 5");
    }

    #[test]
    fn test_crucible_flush_all() {
        let mut crucible = Crucible::<SumMold>::new();
        crucible.process(1);
        crucible.process(2); // 2 items waiting

        let results = crucible.flush_all();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "Sum: 3"); // 1+2
    }
}