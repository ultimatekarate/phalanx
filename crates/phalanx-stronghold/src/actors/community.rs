// crates/phalanx-stronghold/src/actors/community.rs
//
// CommunityActor: long-running actor managing community rosters.
//
// Hands layer. Owns the community lifecycle: import with vouch verification,
// expiration sweep, dissolution with zeroize, and DID-to-community routing.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use phalanx_forensics::identity::verify_community_vouches;
use phalanx_proto::community::{
    Community, CommunityId, CommunityRoster, CommunitySummary, CommunityVerifyError, MemberSummary,
};
use phalanx_proto::identity::Did;
use phalanx_proto::time::PhalanxTimestamp;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::error::StrongholdError;

// ── Commands ────────────────────────────────────────────────────────────

pub enum CommunityCommand {
    /// Import a community after validating expiration and vouch signatures.
    Import {
        community: Community,
        reply_to: oneshot::Sender<Result<CommunityId, StrongholdError>>,
    },
    /// Dissolve a community: zeroize and remove from all maps.
    Dissolve {
        community_id: CommunityId,
        reply_to: oneshot::Sender<Result<(), StrongholdError>>,
    },
    /// Look up which communities a DID belongs to.
    LookupMember {
        did: Did,
        reply_to: oneshot::Sender<Vec<CommunityId>>,
    },
    /// List all communities as (id, name) pairs.
    ListCommunities {
        reply_to: oneshot::Sender<Vec<(CommunityId, String)>>,
    },
    /// Fetch the full roster for a single community (for the GUI detail
    /// panel). `None` if the id is unknown.
    GetDetail {
        community_id: CommunityId,
        reply_to: oneshot::Sender<Option<CommunityRoster>>,
    },
    /// Snapshot the full DID-to-community routing table.
    SnapshotRouting {
        reply_to: oneshot::Sender<HashMap<Did, Vec<CommunityId>>>,
    },
}

// ── Actor ───────────────────────────────────────────────────────────────

pub struct CommunityActor {
    communities: HashMap<CommunityId, Community>,
    /// Reverse index: DID -> set of communities it belongs to.
    did_index: HashMap<Did, HashSet<CommunityId>>,
    rx: mpsc::Receiver<CommunityCommand>,
}

impl CommunityActor {
    pub fn new(rx: mpsc::Receiver<CommunityCommand>) -> Self {
        Self {
            communities: HashMap::new(),
            did_index: HashMap::new(),
            rx,
        }
    }

    /// Run the actor loop. Returns when the channel is closed.
    pub async fn run(mut self) {
        let mut maintenance = tokio::time::interval(std::time::Duration::from_secs(60));

        loop {
            tokio::select! {
                cmd = self.rx.recv() => {
                    match cmd {
                        Some(command) => self.handle(command),
                        None => {
                            info!("CommunityActor: channel closed, shutting down");
                            break;
                        }
                    }
                }
                _ = maintenance.tick() => {
                    self.sweep_expired();
                }
            }
        }
    }

    fn handle(&mut self, cmd: CommunityCommand) {
        match cmd {
            CommunityCommand::Import {
                community,
                reply_to,
            } => {
                let result = self.import(community);
                let _ = reply_to.send(result);
            }
            CommunityCommand::Dissolve {
                community_id,
                reply_to,
            } => {
                let result = self.dissolve(community_id);
                let _ = reply_to.send(result);
            }
            CommunityCommand::LookupMember { did, reply_to } => {
                let result = self.lookup_member(&did);
                let _ = reply_to.send(result);
            }
            CommunityCommand::ListCommunities { reply_to } => {
                let list = self.list_communities();
                let _ = reply_to.send(list);
            }
            CommunityCommand::GetDetail {
                community_id,
                reply_to,
            } => {
                let detail = self.get_detail(&community_id);
                let _ = reply_to.send(detail);
            }
            CommunityCommand::SnapshotRouting { reply_to } => {
                let snapshot = self.snapshot_routing();
                let _ = reply_to.send(snapshot);
            }
        }
    }

    // ── Command Handlers ────────────────────────────────────────────────

    #[allow(clippy::cast_possible_truncation)] // Epoch millis fit in u64 for centuries.
    fn import(&mut self, community: Community) -> Result<CommunityId, StrongholdError> {
        let now = PhalanxTimestamp::from_millis(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        );

        // Delegate expiration + vouch verification to the shared forensics verb.
        verify_community_vouches(&community, now).map_err(|e| match e {
            CommunityVerifyError::Expired { .. } => StrongholdError::CommunityExpired,
            other => StrongholdError::VouchVerification(other.to_string()),
        })?;

        let community_id = community.fingerprint;

        // Rebuild did_index entries for this community
        for member in &community.members {
            self.did_index
                .entry(member.did().clone())
                .or_default()
                .insert(community_id);
        }

        info!(
            community = %community.name,
            members = community.members.len(),
            "Imported community"
        );

        self.communities.insert(community_id, community);
        Ok(community_id)
    }

    fn dissolve(&mut self, community_id: CommunityId) -> Result<(), StrongholdError> {
        let community = self
            .communities
            .remove(&community_id)
            .ok_or(StrongholdError::CommunityNotFound(community_id))?;

        // Remove DID index entries for this community
        for member in &community.members {
            if let Some(set) = self.did_index.get_mut(member.did()) {
                set.remove(&community_id);
                if set.is_empty() {
                    self.did_index.remove(member.did());
                }
            }
        }

        info!(community_id = ?community_id, "Dissolved community");

        // Zeroize and drop
        community.dissolve();
        Ok(())
    }

    fn lookup_member(&self, did: &Did) -> Vec<CommunityId> {
        self.did_index
            .get(did)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    fn list_communities(&self) -> Vec<(CommunityId, String)> {
        self.communities
            .iter()
            .map(|(id, c)| (*id, c.name.as_str().to_owned()))
            .collect()
    }

    fn get_detail(&self, community_id: &CommunityId) -> Option<CommunityRoster> {
        let community = self.communities.get(community_id)?;
        let member_count = u16::try_from(community.members.len()).unwrap_or(u16::MAX);
        let summary = CommunitySummary {
            id: community.fingerprint,
            name: community.name.clone(),
            member_count,
            expires_at: community.expires_at,
            quorum: community.quorum,
        };
        let members = community
            .members
            .iter()
            .map(|m| {
                let vouch_count = u16::try_from(m.vouches().len()).unwrap_or(u16::MAX);
                MemberSummary {
                    did: m.did().clone(),
                    joined_at: m.joined(),
                    vouch_count,
                    // Stronghold does not maintain peer aliases for community
                    // members; surface None and let the UI render the DID.
                    pet_name: None,
                }
            })
            .collect();
        Some(CommunityRoster {
            summary,
            members,
            grants: community.grants,
            stronghold_did: community.stronghold_did.clone(),
        })
    }

    fn snapshot_routing(&self) -> HashMap<Did, Vec<CommunityId>> {
        self.did_index
            .iter()
            .map(|(did, set)| (did.clone(), set.iter().copied().collect()))
            .collect()
    }

    // ── Maintenance ─────────────────────────────────────────────────────

    #[allow(clippy::cast_possible_truncation)] // Epoch millis fit in u64 for centuries.
    fn sweep_expired(&mut self) {
        let now = PhalanxTimestamp::from_millis(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        );
        let expired: Vec<CommunityId> = self
            .communities
            .iter()
            .filter(|(_, c)| c.is_expired(now))
            .map(|(id, _)| *id)
            .collect();

        for id in expired {
            warn!(community_id = ?id, "Community expired, dissolving");
            // Dissolve ignores the error here since we know the community exists
            let _ = self.dissolve(id);
        }
    }
}
