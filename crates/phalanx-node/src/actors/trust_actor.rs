use crate::trust::{ClockProvider, SystemClock, TrustRegistry};
use phalanx_forensics::policy::TrustArbiter;
use phalanx_proto::prelude::*;
use phalanx_proto::trust::Offense;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{interval, Duration};

#[derive(Debug)]
pub enum TrustCommand {
    RecordOffense {
        did: Did,
        offense: Offense,
    },
    CheckTrust {
        did: Did,
        reply_to: oneshot::Sender<TrustLevel>,
    },
    IsBlacklisted {
        did: Did,
        reply_to: oneshot::Sender<bool>,
    },
}

pub struct TrustActor {
    registry: TrustRegistry,
    clock: SystemClock,
    rx: mpsc::Receiver<TrustCommand>,
}

impl TrustActor {
    pub fn new(registry: TrustRegistry, rx: mpsc::Receiver<TrustCommand>) -> Self {
        Self {
            registry,
            clock: SystemClock,
            rx,
        }
    }

    pub async fn run(mut self) {
        let mut maintenance_tick = interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                _ = maintenance_tick.tick() => {
                    self.run_maintenance().await;
                }
                Some(cmd) = self.rx.recv() => {
                    if !self.handle_command(cmd).await {
                        break;
                    }
                }
                else => break,
            }
        }
    }

    async fn handle_command(&mut self, cmd: TrustCommand) -> bool {
        match cmd {
            TrustCommand::RecordOffense { did, offense } => {
                self.registry
                    .record_offense(&did, offense, &self.clock)
                    .await;
            }
            TrustCommand::CheckTrust { did, reply_to } => {
                let level = self.registry.check_trust(&did);
                let _ = reply_to.send(level);
            }
            TrustCommand::IsBlacklisted { did, reply_to } => {
                let blacklisted = self.registry.is_blacklisted(&did);
                let _ = reply_to.send(blacklisted);
            }
        }
        true
    }

    async fn run_maintenance(&mut self) {
        let now = self.clock.current_monotonic();
        TrustArbiter::accumulate_reputation(&mut self.registry.core, now, 60, 5);
    }
}
