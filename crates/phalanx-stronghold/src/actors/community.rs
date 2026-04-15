// crates/phalanx-stronghold/src/actors/community.rs
//
// CommunityActor: long-running actor managing community rosters.
//
// Hands layer. Owns the community lifecycle: import with vouch verification,
// expiration sweep, dissolution with zeroize, and DID-to-community routing.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use phalanx_forensics::identity::{
    assemble_community, verify_community_vouches, verify_vouch_response, CommunityAssemblyParams,
};
use phalanx_proto::community::{
    CeremonyError, Community, CommunityId, CommunityRoster, CommunitySummary, CommunityVerifyError,
    MemberSummary, VouchRequest, VouchResponse,
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
    /// Ceremony hook: verify a `VouchResponse` against the `VouchRequest`
    /// the panel issued. Pure delegation to `verify_vouch_response` — the
    /// actor owns no ceremony state, so this is functionally stateless
    /// but goes through the actor so the panel never spawns its own
    /// blocking verification. Ceremony state lives in the panel.
    ///
    /// `request` and `response` are boxed because `VouchRequest` carries
    /// the full ceremony roster (`Vec<Did>`), making the variant
    /// materially larger than the existing `Import { community }` one —
    /// boxing keeps `CommunityCommand` within clippy's
    /// `large_enum_variant` budget.
    VerifyVouchResponse {
        request: Box<VouchRequest>,
        response: Box<VouchResponse>,
        reply_to: oneshot::Sender<Result<(), CeremonyError>>,
    },
    /// Ceremony hook: assemble a community from collected vouches,
    /// then import it into the actor's roster. On success, returns the
    /// fingerprint **and** a cloned copy of the installed community so
    /// the panel can serialize the join payload for QR rendering
    /// without a follow-up round-trip. The actor retains the canonical
    /// copy; the clone travels to the panel for serialization only.
    ///
    /// `params` is boxed for the same reason as the request above —
    /// `CommunityAssemblyParams` owns the full ceremony roster plus
    /// every vouch, and this variant would otherwise bloat the enum.
    /// The reply `Community` is likewise boxed.
    AssembleAndImport {
        params: Box<CommunityAssemblyParams>,
        reply_to: oneshot::Sender<Result<(CommunityId, Box<Community>), CeremonyError>>,
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
            CommunityCommand::VerifyVouchResponse {
                request,
                response,
                reply_to,
            } => {
                let result = self.verify_vouch_response(&request, &response);
                let _ = reply_to.send(result);
            }
            CommunityCommand::AssembleAndImport { params, reply_to } => {
                let result = self.assemble_and_import(*params);
                let _ = reply_to.send(result);
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

    // ── Ceremony Handlers ───────────────────────────────────────────────

    /// Delegate to the Laboratory verb; the actor owns no ceremony
    /// state, it just threads `now` through the system clock. The
    /// panel collects responses directly in its own `CollectingVouches`
    /// state.
    #[allow(clippy::cast_possible_truncation)] // Epoch millis fit in u64 for centuries.
    fn verify_vouch_response(
        &self,
        request: &VouchRequest,
        response: &VouchResponse,
    ) -> Result<(), CeremonyError> {
        let now = PhalanxTimestamp::from_millis(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        );
        verify_vouch_response(request, response, now)
    }

    /// Run the Laboratory assembly verb, then import the resulting
    /// `Community` into this actor's roster. The separate `Import`
    /// command path handles externally-delivered communities (join QR
    /// scanned off another Stronghold); this path handles the freshly
    /// assembled ones. Both funnel through `Self::import` so the
    /// did_index is rebuilt identically in both cases.
    ///
    /// Errors are routed cleanly to their respective `CeremonyError`
    /// variants: `assemble_community` errors become
    /// `CeremonyError::Assembly` via the `#[from]` conversion; any
    /// error surfacing from the import leg (typically unreachable
    /// post-assembly) becomes `CeremonyError::ImportFailed { reason }`,
    /// carrying the underlying `StrongholdError::Display` text. The
    /// variant split keeps the panel's error rendering free of
    /// fabricated `CommunityId` / `Did` placeholders.
    #[allow(clippy::cast_possible_truncation)] // Epoch millis fit in u64 for centuries.
    fn assemble_and_import(
        &mut self,
        params: CommunityAssemblyParams,
    ) -> Result<(CommunityId, Box<Community>), CeremonyError> {
        let now = PhalanxTimestamp::from_millis(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        );
        // assemble_community returns Err(CommunityAssemblyError) → into CeremonyError::Assembly
        let community = assemble_community(params, now)?;
        // Clone once for the reply — the panel needs the full struct to
        // serialize the join payload, and this avoids a second
        // `GetCommunity` round-trip plus the ambiguity of fetching a
        // community that might already have been dissolved in a racing
        // tab. The original moves into `import()`; the clone travels to
        // the panel for serialization only.
        let community_clone = community.clone();
        // Reuse Self::import so the did_index rebuild and zeroize-on-dissolve
        // invariants stay identical to the join path. Any error here is
        // post-assembly and typically unreachable (assembly just produced a
        // Community whose vouches verify by construction) — map to
        // `CeremonyError::ImportFailed` so the panel can surface the real
        // `StrongholdError::Display` message rather than fabricating a
        // zeroed `CommunityId` or a synthetic `Did` built from the error
        // string.
        self.import(community)
            .map_err(|e| CeremonyError::ImportFailed {
                reason: e.to_string(),
            })?;
        Ok((community_clone.fingerprint, Box::new(community_clone)))
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
