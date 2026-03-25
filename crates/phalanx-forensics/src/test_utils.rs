// --- crates/phalanx-forensics/src/test_utils.rs ---
use phalanx_proto::trust::MonotonicClock;

pub struct MockClock {
    current: u64,
}

impl MockClock {
    pub fn new(start_seconds: u64) -> Self {
        Self {
            current: start_seconds,
        }
    }

    /// Simulate the passage of time
    pub fn tick(&mut self, seconds: u64) {
        // Counter increment — overflow not reachable in practice.
        #[allow(clippy::arithmetic_side_effects)]
        {
            self.current += seconds;
        }
    }

    pub fn now(&self) -> MonotonicClock {
        MonotonicClock(self.current)
    }
}
