// --- crates/phalanx-node/src/actors/trust_manager.rs ---
use crate::actors::retrieval::TrustCommand;
use crate::trust::{ClockProvider, SystemClock};
use phalanx_forensics::policy::TrustArbiter;
use phalanx_proto::trust::TrustRegistry;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, Duration};

pub struct TrustManager {
    registry: Arc<RwLock<TrustRegistry>>,
    clock: SystemClock,
    rx: mpsc::Receiver<TrustCommand>,
}

impl TrustManager {
    pub fn new(registry: Arc<RwLock<TrustRegistry>>, rx: mpsc::Receiver<TrustCommand>) -> Self {
        Self {
            registry,
            clock: SystemClock,
            rx,
        }
    }

    /// Primary background loop for reputation management
    pub async fn run(mut self) {
        let mut maintenance_tick = interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                _ = maintenance_tick.tick() => {
                    self.run_maintenance().await;
                }
                Some(cmd) = self.rx.recv() => {
                    self.handle_command(cmd).await;
                }
            }
        }
    }

    async fn handle_command(&mut self, cmd: TrustCommand) {
        match cmd {
            TrustCommand::RecordOffense { did, offense } => {
                let mut registry = self.registry.write().await;
                registry.record_offense(&did, offense, &self.clock).await;
            }
        }
    }

    async fn run_maintenance(&self) {
        let now = self.clock.current_monotonic();
        let mut registry = self.registry.write().await;

        // Invoke the Lab's pure logic
        TrustArbiter::accumulate_reputation(
            &mut registry,
            now,
            60, // 1 minute interval
            5,  // Recover 5 points per interval
        );
    }
}
