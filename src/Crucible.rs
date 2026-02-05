// THE SECRET SAUCE - MY FINEST INNOVATION


use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};

// --- THE GENERIC TRAIT (The "Brain") ---
pub trait Mold {
    type Input;
    type Output;
    type Key: Ord + Clone;      // e.g., EnvelopeId (String) or PeerDid (String)
    type Accumulator;           // The temporary buffer state

    /// How do we identify which bucket this item belongs to?
    fn get_key(item: &Self::Input) -> Self::Key;

    /// Initialize a new buffer when a new key is seen
    fn init_accumulator(item: &Self::Input) -> Self::Accumulator;

    /// Add item to the buffer. Returns true if the item was accepted.
    fn ingest(acc: &mut Self::Accumulator, item: Self::Input);

    /// Ask the brain: Is this buffer ready to be sealed?
    fn is_ready(acc: &Self::Accumulator, elapsed: Duration) -> bool;

    /// Transform the buffer into the final output
    fn assemble(key: Self::Key, acc: Self::Accumulator) -> Option<Self::Output>;
}

// --- THE GENERIC ENGINE (The "Body") ---
pub struct Crucible<S: Mold> {
    sessions: BTreeMap<S::Key, Session<S>>,
    cleanup_interval: Duration,
    last_cleanup: Instant,
}

struct Session<S: Mold> {
    accumulator: S::Accumulator,
    created_at: Instant,
}

impl<S: Mold> Crucible<S> {
    pub fn new() -> Self {
        Self {
            sessions: BTreeMap::new(),
            cleanup_interval: Duration::from_secs(1),
            last_cleanup: Instant::now(),
        }
    }

    /// The Universal Ingest Function
    pub fn process(&mut self, item: S::Input) -> Option<S::Output> {
        self.perform_cleanup();

        let key = S::get_key(&item);
        
        // 1. Get or Init Session
        let session = self.sessions
            .entry(key.clone())
            .or_insert_with(|| Session {
                accumulator: S::init_accumulator(&item),
                created_at: Instant::now(),
            });

        // 2. Feed the Strategy
        S::ingest(&mut session.accumulator, item);

        // 3. Check for Completion (Size or Time)
        if S::is_ready(&session.accumulator, session.created_at.elapsed()) {
            // Pop the session
            if let Some(sess) = self.sessions.remove(&key) {
                // Assemble the result
                return S::assemble(key, sess.accumulator);
            }
        }

        None
    }

    /// Remove stale sessions
    fn perform_cleanup(&mut self) {
        if self.last_cleanup.elapsed() > self.cleanup_interval {
            // We can't easily check "is_ready" for staleness inside retain without specialized logic,
            // so we'll rely on the next process() call or force a manual flush if needed.
            // For this implementation, we'll keep it simple:
            // In a real system, we'd iterate and check TTLs here.
            self.last_cleanup = Instant::now();
        }
    }
    
    /// Force flush all stale sessions (useful for Volleys)
    pub fn flush_stale(&mut self, ttl: Duration) -> Vec<S::Output> {
        let mut ready_keys = Vec::new();
        
        for (key, session) in &self.sessions {
            if session.created_at.elapsed() > ttl {
                ready_keys.push(key.clone());
            }
        }

        let mut results = Vec::new();
        for key in ready_keys {
            if let Some(session) = self.sessions.remove(&key) {
                if let Some(out) = S::assemble(key, session.accumulator) {
                    results.push(out);
                }
            }
        }
        results
    }
}