use std::collections::BTreeMap;
use std::time::{Duration, Instant};

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