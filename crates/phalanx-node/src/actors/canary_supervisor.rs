// crates/phalanx-node/src/actors/canary_supervisor.rs
//
// Silent Canary actor. Owns the CanaryMonitor, the per-peer DID cache, and
// its own clones of the live community-keyset watch receiver and the
// static `extra_community_ids` seeds (the originals stay on MeshSentinel —
// see plan §"Cross-actor shared state").
//
// Cadence: command-driven. No autonomous tick — staleness is detected on
// peer disconnect events arriving via `PeerDisconnected`.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{mpsc, watch};

use phalanx_proto::community::CommunityId;
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::identity::{Did, MeshAddress, RecordingId};
use phalanx_proto::network::topic::MeshTopic;
use phalanx_proto::prelude::PhalanxPhysics;
use phalanx_proto::trust::TrustLevel;

use crate::actors::eclipse_router::EclipseCommand;
use crate::actors::egress::EgressCommand;
use crate::actors::mesh_policy;
use crate::actors::shutdown::ShutdownSignal;
use crate::actors::storage::StorageCommand;
use crate::clock::TrustedClock;
use crate::trust::{ReputationProjection, TrustOracle};
use crate::vitals::HealthTracker;
use crate::vitals::canary::{CanaryMonitor, CanaryState};

/// Commands accepted by the canary supervisor.
#[derive(Debug)]
pub enum CanaryCommand {
    /// A shard envelope has arrived from a peer. Update `peer_did_cache`
    /// and, if a recording is active and the peer is a verified community
    /// member, register a contribution.
    RegisterContribution {
        origin: MeshAddress,
        envelope_did: Did,
        evidence_recording_id: RecordingId,
    },
    /// A peer has reconnected — cancel any pending dark-peer confirmation.
    OnPeerReconnected { peer: MeshAddress },
    /// A peer has disconnected. If recording is active and the canary is
    /// watching, escalate to staleness check (using `Arc<HealthTracker>`)
    /// and dispatch alerts on confirmation.
    PeerDisconnected { peer: MeshAddress },
    /// FFI signalled recording start. Track active state for contribution
    /// gating; clear any prior watched state.
    RecordingStarted { recording_id: RecordingId },
    /// FFI signalled recording stop. Clear watched state.
    RecordingStopped,
}

pub struct CanarySupervisor {
    // Owned state
    canary: CanaryMonitor,
    /// Peer identity cache: MeshAddress → (Did, sequence-number for LRU eviction).
    /// MUST NEVER be persisted — memory-only, dies with the process.
    peer_did_cache: HashMap<MeshAddress, (Did, u64)>,
    peer_did_cache_seq: u64,
    /// Local copy of the recording-active flag, kept in sync via
    /// `RecordingStarted`/`RecordingStopped` commands. Avoids needing to
    /// query MeshSentinel on every shard envelope.
    recording_active: bool,

    // Community keyset (clones of MeshSentinel's originals)
    community_ids_rx: watch::Receiver<Vec<CommunityId>>,
    extra_community_ids: Vec<CommunityId>,

    // Arc-shared dependencies
    clock: Arc<TrustedClock>,
    health_tracker: Arc<HealthTracker>,
    reputation: ReputationProjection,

    // Outbound senders
    egress_tx: mpsc::Sender<EgressCommand>,
    storage_tx: mpsc::Sender<StorageCommand>,
    /// `DidLearned` notifies are sent best-effort to `EclipseRouter` so its
    /// reciprocity sweep can dispatch trust penalties without a query.
    eclipse_tx: mpsc::Sender<EclipseCommand>,

    // Inbound and lifecycle
    rx: mpsc::Receiver<CanaryCommand>,
    shutdown: Arc<ShutdownSignal>,
}

#[allow(clippy::too_many_arguments)] // Spawn-time deps; trimming is plan §"Trim during implementation".
impl CanarySupervisor {
    pub fn new(
        clock: Arc<TrustedClock>,
        health_tracker: Arc<HealthTracker>,
        reputation: ReputationProjection,
        community_ids_rx: watch::Receiver<Vec<CommunityId>>,
        extra_community_ids: Vec<CommunityId>,
        egress_tx: mpsc::Sender<EgressCommand>,
        storage_tx: mpsc::Sender<StorageCommand>,
        eclipse_tx: mpsc::Sender<EclipseCommand>,
        rx: mpsc::Receiver<CanaryCommand>,
        shutdown: Arc<ShutdownSignal>,
    ) -> Self {
        Self {
            canary: CanaryMonitor::new(mesh_policy::CANARY_CONFIRM_TICKS),
            peer_did_cache: HashMap::new(),
            peer_did_cache_seq: 0,
            recording_active: false,
            community_ids_rx,
            extra_community_ids,
            clock,
            health_tracker,
            reputation,
            egress_tx,
            storage_tx,
            eclipse_tx,
            rx,
            shutdown,
        }
    }

    pub async fn run(mut self) {
        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => break,
                Some(cmd) = self.rx.recv() => {
                    self.handle_command(cmd).await;
                }
                else => break,
            }
        }

        // Post-loop drain: process any commands queued before cancellation.
        while let Ok(cmd) = self.rx.try_recv() {
            self.handle_command(cmd).await;
        }
    }

    async fn handle_command(&mut self, cmd: CanaryCommand) {
        match cmd {
            CanaryCommand::RegisterContribution {
                origin,
                envelope_did,
                evidence_recording_id,
            } => {
                self.register_contribution(origin, envelope_did, evidence_recording_id)
                    .await;
            }
            CanaryCommand::OnPeerReconnected { peer } => {
                self.canary.on_peer_reconnected(&peer);
            }
            CanaryCommand::PeerDisconnected { peer } => {
                self.handle_peer_disconnected(peer).await;
            }
            CanaryCommand::RecordingStarted { recording_id: _ } => {
                self.recording_active = true;
                self.canary.clear();
            }
            CanaryCommand::RecordingStopped => {
                self.recording_active = false;
                self.canary.clear();
            }
        }
    }

    async fn register_contribution(
        &mut self,
        origin: MeshAddress,
        envelope_did: Did,
        recording_id: RecordingId,
    ) {
        // Always populate the peer identity cache (memory-only, capped).
        let was_new = !self.peer_did_cache.contains_key(&origin);
        if self.peer_did_cache.len() >= mesh_policy::PEER_DID_CACHE_CAP && was_new {
            // Evict oldest (smallest seq) entry.
            if let Some(oldest) = self
                .peer_did_cache
                .iter()
                .min_by_key(|(_, (_, seq))| *seq)
                .map(|(k, _)| k.clone())
            {
                self.peer_did_cache.remove(&oldest);
            }
        }
        self.peer_did_cache_seq = self.peer_did_cache_seq.saturating_add(1);
        self.peer_did_cache.insert(
            origin.clone(),
            (envelope_did.clone(), self.peer_did_cache_seq),
        );

        // Notify EclipseRouter so its reciprocity sweep can resolve DIDs
        // without cross-actor query latency. Best-effort.
        if was_new {
            let _ = self.eclipse_tx.try_send(EclipseCommand::DidLearned {
                peer: origin.clone(),
                did: envelope_did.clone(),
            });
        }

        // Only register canary contributions during an active recording.
        if !self.recording_active {
            return;
        }

        // Only watch community members (effective_trust >= Verified).
        let trust = self.reputation.effective_trust(&envelope_did);
        if trust < TrustLevel::Verified {
            return;
        }

        self.canary
            .register_contribution(&origin, &envelope_did, &recording_id);
    }

    async fn handle_peer_disconnected(&mut self, peer: MeshAddress) {
        // Mark peer as potentially dark. The canary only fires after
        // heartbeat staleness is confirmed, not on disconnect alone.
        if !(self.recording_active && self.canary.is_active()) {
            return;
        }
        self.canary.on_peer_disconnected(&peer);
        let physics = PhalanxPhysics::default();
        if self.health_tracker.is_peer_stale(&peer, &physics) {
            if let Some(state) = self.canary.on_peer_stale(&peer) {
                self.handle_canary_alert(state).await;
            }
        }
    }

    async fn handle_canary_alert(&mut self, state: CanaryState) {
        let (silent_peers, recordings_at_risk, peers_remaining) = match state {
            CanaryState::Alert {
                silent_peers,
                recordings_at_risk,
                peers_remaining,
            } => (silent_peers, recordings_at_risk, peers_remaining),
            CanaryState::Normal => return,
        };

        tracing::warn!(
            silent = silent_peers.len(),
            at_risk = recordings_at_risk.len(),
            remaining = peers_remaining,
            "Silent Canary: community peer(s) confirmed dark"
        );

        // Re-replicate dark peer's recordings via existing DHT infrastructure.
        for rid in &recordings_at_risk {
            let _ = self
                .egress_tx
                .send(EgressCommand::FindProviders(rid.clone()))
                .await;
        }

        if peers_remaining == 0 {
            // Local salvage — no peers left to distribute to.
            let _ = self
                .storage_tx
                .send(StorageCommand::EmergencySalvage(vec![]))
                .await;
        }

        // Broadcast encrypted canary alert to community members.
        self.broadcast_canary_alert(silent_peers.len()).await;
    }

    async fn broadcast_canary_alert(&mut self, silent_count: usize) {
        let detected_at = self.clock.now().unwrap_or_default();
        // Mesh peer count is structurally bounded well below u32::MAX.
        #[allow(clippy::cast_possible_truncation)]
        let silent_count_u32 = silent_count as u32;
        let alert = phalanx_proto::network::CanaryAlert {
            silent_count: phalanx_proto::network::SilentCount(silent_count_u32),
            detected_at,
        };

        let plaintext = match postcard::to_allocvec(&alert) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(error = %e, "Canary: failed to serialize alert");
                return;
            }
        };

        // Live-snapshot the keyset (registry watch + static extras) so a
        // community dissolved at runtime stops emitting canary alerts.
        let cids =
            mesh_policy::current_community_ids(&self.community_ids_rx, &self.extra_community_ids);
        for cid in &cids {
            let canary_key = SymmetricKey::from_bytes(blake3::derive_key(
                "phalanx.canary.v1.community-alert",
                &cid.0,
            ));

            let (nonce, ciphertext) =
                match phalanx_forensics::cryptography::encrypt_bytes(&canary_key, &plaintext) {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(error = %e, "Canary: encryption failed");
                        continue;
                    }
                };

            let mut payload = nonce;
            payload.extend(ciphertext);

            let _ = self
                .egress_tx
                .send(EgressCommand::PublishMesh {
                    topic: MeshTopic::mesh(),
                    data: payload,
                })
                .await;
        }
    }
}
