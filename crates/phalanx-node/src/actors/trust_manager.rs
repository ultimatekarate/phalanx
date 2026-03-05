// --- crates/phalanx-node/src/actors/trust_manager.rs ---
use crate::trust::{ClockProvider, SystemClock};
use phalanx_forensics::policy::TrustArbiter;
use phalanx_proto::trust::TrustRegistry;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};

pub struct TrustManager {
    registry: Arc<RwLock<TrustRegistry>>,
    clock: SystemClock,
}

impl TrustManager {
    pub fn new(registry: Arc<RwLock<TrustRegistry>>) -> Self {
        Self {
            registry,
            clock: SystemClock,
        }
    }

    /// Primary background loop for reputation management
    pub async fn run_maintenance_loop(self) {
        let mut tick_rate = interval(Duration::from_secs(60));

        loop {
            tick_rate.tick().await;

            let clock = SystemClock;
            let now = clock.current_monotonic();
            let mut registry = self.registry.write().await;

            // Invoke the Lab's pure logic
            TrustArbiter::apply_decay(
                &mut registry,
                now,
                60, // 1 minute interval
                5,  // Recover 5 points per interval
            );
        }
    }
}
