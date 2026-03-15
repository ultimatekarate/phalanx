use crate::clock::TrustedClock;
use crate::trust::{ClockProvider, SystemClock, TrustRegistry};
use phalanx_forensics::policy::TrustArbiter;
use phalanx_proto::prelude::*;
use phalanx_proto::trust::{Offense, PetName, TrustError};
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{interval, Duration};

/// JSON-serializable peer summary for FFI transport.
#[derive(Debug, Serialize)]
pub struct PeerSummary {
    pub did: String,
    pub pet_name: Option<String>,
    pub level: String,
    pub score: i64,
    pub is_blacklisted: bool,
}

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
    // --- FFI extensions for mobile peer management ---
    ListPeers {
        reply_to: oneshot::Sender<Vec<PeerSummary>>,
    },
    SetTrustLevel {
        did: Did,
        level: TrustLevel,
        reply_to: oneshot::Sender<Result<(), TrustError>>,
    },
    AssignPetName {
        did: Did,
        name: PetName,
        reply_to: oneshot::Sender<Result<(), TrustError>>,
    },
    RemovePeer {
        did: Did,
        reply_to: oneshot::Sender<Result<(), TrustError>>,
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
            TrustCommand::ListPeers { reply_to } => {
                let peers: Vec<PeerSummary> = self
                    .registry
                    .peers
                    .iter()
                    .map(|(did, record)| PeerSummary {
                        did: did.as_str().to_string(),
                        pet_name: record.pet_name.as_ref().map(|pn| pn.as_str().to_string()),
                        level: format!("{:?}", record.level),
                        score: record.reputation.score,
                        is_blacklisted: record.reputation.is_blacklisted,
                    })
                    .collect();
                let _ = reply_to.send(peers);
            }
            TrustCommand::SetTrustLevel {
                did,
                level,
                reply_to,
            } => {
                let clock = TrustedClock::new();
                let result = if self.registry.peers.contains_key(&did) {
                    // Preserve existing pet name when updating trust level
                    let existing_name = self
                        .registry
                        .get_alias(&did)
                        .and_then(|s| PetName::new(s).ok())
                        .unwrap_or_else(|| {
                            PetName::new("peer").ok().unwrap_or_else(|| unreachable!())
                        });
                    self.registry
                        .set_peer(&did, &existing_name, level, &clock)
                        .await
                } else {
                    self.registry.register_peer(&did, level, &clock).await
                };
                let _ = reply_to.send(result);
            }
            TrustCommand::AssignPetName {
                did,
                name,
                reply_to,
            } => {
                let result = self.registry.assign_pet_name(&did, name).await;
                let _ = reply_to.send(result);
            }
            TrustCommand::RemovePeer { did, reply_to } => {
                let result = self.registry.remove_peer(&did).await;
                let _ = reply_to.send(result);
            }
        }
        true
    }

    async fn run_maintenance(&mut self) {
        let now = self.clock.current_monotonic();
        TrustArbiter::accumulate_reputation(&mut self.registry.peers, now, 60, 5);
    }
}
