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
    // --- Community management ---
    ImportCommunity {
        community: phalanx_proto::community::Community,
    },
    DissolveCommunity {
        community_id: phalanx_proto::community::CommunityId,
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
            TrustCommand::ImportCommunity { community } => {
                // Defense-in-depth: verify vouch signatures and expiration on import.
                // The creation side validates at assembly time; this catches tampered tokens.
                {
                    use phalanx_proto::time::TrustedClock;
                    let now = phalanx_proto::time::SystemClock.now();
                    if community.is_expired(now) {
                        tracing::warn!(
                            target: "phalanx::trust",
                            community = %community.name,
                            "Rejecting expired community on import"
                        );
                        return true;
                    }
                    let mut vouch_valid = true;
                    for member in &community.members {
                        for vouch in member.vouches() {
                            if phalanx_forensics::identity::verify_vouch(
                                vouch,
                                member.did(),
                                &community.fingerprint,
                                member.joined(),
                            )
                            .is_err()
                            {
                                tracing::warn!(
                                    target: "phalanx::trust",
                                    member = %member.did(),
                                    voucher = %vouch.voucher_did,
                                    "Vouch verification failed on import — rejecting community"
                                );
                                vouch_valid = false;
                                break;
                            }
                        }
                        if !vouch_valid {
                            break;
                        }
                    }
                    if !vouch_valid {
                        return true;
                    }
                }

                tracing::info!(
                    target: "phalanx::trust",
                    community = %community.name,
                    members = community.members.len(),
                    "Importing verified community into TrustRegistry"
                );
                // Sync community data to ReputationProjection for lock-free effective_trust reads
                let community_data: Vec<_> = std::iter::once((
                    community.baseline_trust,
                    community.members.iter().map(|m| m.did().clone()).collect(),
                ))
                .chain(self.registry.communities.values().map(|c| {
                    (
                        c.baseline_trust,
                        c.members.iter().map(|m| m.did().clone()).collect(),
                    )
                }))
                .collect();
                self.registry
                    .communities
                    .insert(community.fingerprint, community);
                self.registry
                    .live_projection
                    .sync_communities(community_data);
            }
            TrustCommand::DissolveCommunity { community_id } => {
                if let Some(community) = self.registry.communities.remove(&community_id) {
                    tracing::info!(
                        target: "phalanx::trust",
                        community = %community.name,
                        "Dissolving community — zeroizing membership data"
                    );
                    community.dissolve(); // Consumes and zeroizes
                                          // Re-sync projection without the dissolved community
                    let community_data: Vec<_> = self
                        .registry
                        .communities
                        .values()
                        .map(|c| {
                            (
                                c.baseline_trust,
                                c.members.iter().map(|m| m.did().clone()).collect(),
                            )
                        })
                        .collect();
                    self.registry
                        .live_projection
                        .sync_communities(community_data);
                }
            }
        }
        true
    }

    async fn run_maintenance(&mut self) {
        let now = self.clock.current_monotonic();
        TrustArbiter::accumulate_reputation(&mut self.registry.peers, now, 60, 5);
    }
}
