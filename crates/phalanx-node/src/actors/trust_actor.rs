use crate::clock::TrustedClock;
use crate::trust::{ClockProvider, SystemClock, TrustRegistry};
use phalanx_forensics::policy::TrustArbiter;
use phalanx_proto::community::{
    Community, CommunityId, CommunityRoster, CommunitySummary, DissolveOutcome, ImportOutcome,
    MemberSummary,
};
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
        community: Community,
        reply_to: oneshot::Sender<ImportOutcome>,
    },
    DissolveCommunity {
        community_id: CommunityId,
        reply_to: oneshot::Sender<DissolveOutcome>,
    },
    ListCommunities {
        reply_to: oneshot::Sender<Vec<CommunitySummary>>,
    },
    GetCommunity {
        community_id: CommunityId,
        reply_to: oneshot::Sender<Option<CommunityRoster>>,
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
            TrustCommand::ImportCommunity {
                community,
                reply_to,
            } => {
                // Defense-in-depth: delegate expiration + vouch checks to the
                // shared forensics verb. Creation side also validates; this
                // catches tampered tokens in transit.
                let outcome = {
                    use phalanx_proto::time::TrustedClock;
                    let now = phalanx_proto::time::SystemClock.now();
                    match phalanx_forensics::identity::verify_community_vouches(&community, now) {
                        Ok(()) => {
                            let fingerprint = community.fingerprint;
                            tracing::info!(
                                target: "phalanx::trust",
                                community = %community.name,
                                members = community.members.len(),
                                "Importing verified community into TrustRegistry"
                            );
                            // Sync community data to ReputationProjection for
                            // lock-free effective_trust reads.
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
                            self.registry.communities.insert(fingerprint, community);
                            self.registry
                                .live_projection
                                .sync_communities(community_data);
                            ImportOutcome::Ok(fingerprint)
                        }
                        Err(e) => {
                            tracing::warn!(
                                target: "phalanx::trust",
                                community = %community.name,
                                error = %e,
                                "Rejecting community on import — verification failed"
                            );
                            ImportOutcome::Err(e)
                        }
                    }
                };
                let _ = reply_to.send(outcome);
            }
            TrustCommand::DissolveCommunity {
                community_id,
                reply_to,
            } => {
                let outcome =
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
                        DissolveOutcome::Ok(community_id)
                    } else {
                        DissolveOutcome::NotFound
                    };
                let _ = reply_to.send(outcome);
            }
            TrustCommand::ListCommunities { reply_to } => {
                let summaries: Vec<CommunitySummary> = self
                    .registry
                    .communities
                    .values()
                    .map(summarize_community)
                    .collect();
                let _ = reply_to.send(summaries);
            }
            TrustCommand::GetCommunity {
                community_id,
                reply_to,
            } => {
                let roster = self
                    .registry
                    .communities
                    .get(&community_id)
                    .map(|c| project_roster(c, &self.registry));
                let _ = reply_to.send(roster);
            }
        }
        true
    }

    async fn run_maintenance(&mut self) {
        let now = self.clock.current_monotonic();
        TrustArbiter::accumulate_reputation(&mut self.registry.peers, now, 60, 5);

        // Mobile maintenance sweep: expire communities past their
        // `expires_at` so a long-running phone across many events does not
        // accumulate stale rosters in RAM. See plan R5.
        use phalanx_proto::time::TrustedClock;
        let wall_now = phalanx_proto::time::SystemClock.now();
        self.registry.dissolve_expired_communities(wall_now);
    }
}

// ── Projection helpers ──────────────────────────────────────────────────

fn summarize_community(community: &Community) -> CommunitySummary {
    // Member counts are bounded by MAX_CEREMONY_MEMBERS (256), so u16
    // truncation is safe; nonetheless cast via `try_from` for robustness.
    let member_count = u16::try_from(community.members.len()).unwrap_or(u16::MAX);
    CommunitySummary {
        id: community.fingerprint,
        name: community.name.clone(),
        member_count,
        expires_at: community.expires_at,
        quorum: community.quorum,
    }
}

fn project_roster(community: &Community, registry: &TrustRegistry) -> CommunityRoster {
    let summary = summarize_community(community);
    let members = community
        .members
        .iter()
        .map(|m| {
            let vouch_count = u16::try_from(m.vouches().len()).unwrap_or(u16::MAX);
            let pet_name = registry
                .get_alias(m.did())
                .and_then(|alias| PetName::new(alias).ok());
            MemberSummary {
                did: m.did().clone(),
                joined_at: m.joined(),
                vouch_count,
                pet_name,
            }
        })
        .collect();
    CommunityRoster {
        summary,
        members,
        grants: community.grants,
        stronghold_did: community.stronghold_did.clone(),
    }
}
