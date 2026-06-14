// crates/phalanx-node/src/actors/eclipse_router.rs
//
// Eclipse-remediation actor. Owns topology admission state, eclipse fingerprint
// history, the reciprocity floor's per-peer first-seen ledger, and the local
// DID cache populated via `DidLearned` notifies from CanarySupervisor.
//
// Cadence: 5-minute topology tick (anchor promotion, eclipse evaluation,
// reciprocity sweep, integral pruning) plus per-command processing.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use tokio::time::interval;

use phalanx_forensics::eclipse::{self, EclipseProbe, MeshFingerprint};
use phalanx_forensics::prelude::*;
use phalanx_forensics::trust::{
    PeerContribution, ReciprocityParams, ReciprocityVerdict, evaluate_reciprocity,
};
use phalanx_proto::identity::{Did, MeshAddress};
use phalanx_proto::network::topology::EclipseRisk;
use phalanx_proto::prelude::*;
use phalanx_proto::topology::{SubnetBucket, TransportClass};
use phalanx_proto::trust::Offense;

use crate::actors::egress::EgressCommand;
use crate::actors::mesh_policy;
use crate::actors::shutdown::ShutdownSignal;
use crate::actors::storage::StorageCommand;
use crate::actors::trust_actor::TrustCommand;
use crate::clock::TrustedClock;
use crate::config::NodeConfig;
use crate::trust::ReputationProjection;
use crate::vitals::{HealthTracker, Homeostasis, SystemGovernor};

/// Outcome of a `TryAdmit` request, returned via the oneshot reply channel.
#[derive(Debug, Clone)]
pub struct AdmitOutcome {
    pub admitted: bool,
    pub evicted: Option<MeshAddress>,
    /// `true` iff this admission was the first time we have seen this peer
    /// in the current process lifetime. The orchestrator uses this to
    /// trigger a one-shot revocation replay via `ReplayRevocations`.
    pub was_first_seen: bool,
}

/// Commands accepted by the eclipse router. The 5-minute topology tick is
/// driven by a `tokio::time::interval` arm in the run loop, not by a
/// command variant — same convention as `TrustActor`.
#[derive(Debug)]
pub enum EclipseCommand {
    /// Run topology admission for a newly-discovered peer. The reply
    /// channel returns the outcome (admitted/evicted/was_first_seen) so the
    /// orchestrator on `MeshSentinel` can fan out follow-on work
    /// (proximity witness capture, revocation replay) without depending on
    /// internal Eclipse state.
    TryAdmit {
        peer: MeshAddress,
        source: phalanx_proto::telemetry::DiscoverySource,
        bucket: SubnetBucket,
        transport: TransportClass,
        /// Computed by the orchestrator from `local_mesh` availability and
        /// `system_governor.internet_available()`. Eclipse does not own
        /// the inputs; the orchestrator passes the result through.
        transport_balance: TransportBalance,
        reply_to: oneshot::Sender<AdmitOutcome>,
    },
    /// Tear down per-peer state on disconnect. Demotes anchor, releases
    /// the topology gate slot, and updates the connection gauge.
    PeerDisconnected { peer: MeshAddress },
    /// Notify from `CanarySupervisor` that a peer's DID has been learned
    /// (typically from a shard envelope's signature). Eclipse maintains a
    /// parallel `did_cache` so the reciprocity sweep can dispatch trust
    /// penalties without a cross-actor query at tick time.
    DidLearned { peer: MeshAddress, did: Did },
    /// Replay all persisted revocation tokens to this peer. Triggered by
    /// the orchestrator when `TryAdmit` returns `was_first_seen = true`.
    ReplayRevocations { peer: MeshAddress },
}

/// State and dependencies for the eclipse router.
pub struct EclipseRouter {
    // Owned state
    topology_gate: TopologyGate,
    eclipse_probe: EclipseProbe,
    peer_discovery_count: u32,
    peer_discovery_window: Instant,
    peer_first_seen: HashMap<MeshAddress, u64>,
    revocation_synced_peers: HashSet<MeshAddress>,
    /// Local DID cache. Populated by `DidLearned` notifies from Canary;
    /// capped at `mesh_policy::PEER_DID_CACHE_CAP` with oldest-wins
    /// eviction (entries age out as new DIDs arrive).
    did_cache: HashMap<MeshAddress, (Did, u64)>,
    did_cache_seq: u64,

    // Arc-shared dependencies
    config: Arc<NodeConfig>,
    identity: Arc<PhalanxIdentity>,
    clock: Arc<TrustedClock>,
    system_governor: Arc<SystemGovernor>,
    health_tracker: Arc<HealthTracker>,
    reputation: ReputationProjection,

    // Outbound senders to other actors
    egress_tx: mpsc::Sender<EgressCommand>,
    trust_tx: mpsc::Sender<TrustCommand>,
    storage_tx: mpsc::Sender<StorageCommand>,

    // Inbound and lifecycle
    rx: mpsc::Receiver<EclipseCommand>,
    shutdown: Arc<ShutdownSignal>,
}

#[allow(clippy::too_many_arguments)] // Spawn-time deps; trimming is plan §"Trim during implementation".
impl EclipseRouter {
    pub fn new(
        config: Arc<NodeConfig>,
        identity: Arc<PhalanxIdentity>,
        clock: Arc<TrustedClock>,
        system_governor: Arc<SystemGovernor>,
        health_tracker: Arc<HealthTracker>,
        reputation: ReputationProjection,
        egress_tx: mpsc::Sender<EgressCommand>,
        trust_tx: mpsc::Sender<TrustCommand>,
        storage_tx: mpsc::Sender<StorageCommand>,
        rx: mpsc::Receiver<EclipseCommand>,
        shutdown: Arc<ShutdownSignal>,
    ) -> Self {
        Self {
            topology_gate: TopologyGate::new(
                mesh_policy::TOPOLOGY_TOTAL_CAPACITY,
                SubnetQuota::DEFAULT,
                mesh_policy::TOPOLOGY_MAX_ANCHORS,
            ),
            eclipse_probe: EclipseProbe::new(mesh_policy::ECLIPSE_PROBE_WINDOW),
            peer_discovery_count: 0,
            peer_discovery_window: Instant::now(),
            peer_first_seen: HashMap::new(),
            revocation_synced_peers: HashSet::new(),
            did_cache: HashMap::new(),
            did_cache_seq: 0,
            config,
            identity,
            clock,
            system_governor,
            health_tracker,
            reputation,
            egress_tx,
            trust_tx,
            storage_tx,
            rx,
            shutdown,
        }
    }

    pub async fn run(mut self) {
        let mut topology_tick = interval(Duration::from_secs(mesh_policy::TOPOLOGY_TICK_SECS));
        topology_tick.tick().await; // Consume the immediate first tick.

        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => break,
                Some(cmd) = self.rx.recv() => {
                    self.handle_command(cmd).await;
                }
                _ = topology_tick.tick() => {
                    self.topology_maintenance_tick().await;
                }
                else => break,
            }
        }

        // Post-loop drain: process any commands queued before cancellation
        // fired so in-flight admissions still resolve.
        while let Ok(cmd) = self.rx.try_recv() {
            self.handle_command(cmd).await;
        }
    }

    async fn handle_command(&mut self, cmd: EclipseCommand) {
        match cmd {
            EclipseCommand::TryAdmit {
                peer,
                source,
                bucket,
                transport,
                transport_balance,
                reply_to,
            } => {
                let outcome = self
                    .handle_try_admit(peer, source, bucket, transport, transport_balance)
                    .await;
                let _ = reply_to.send(outcome);
            }
            EclipseCommand::PeerDisconnected { peer } => {
                self.handle_peer_disconnected(peer).await;
            }
            EclipseCommand::DidLearned { peer, did } => {
                self.cache_did(peer, did);
            }
            EclipseCommand::ReplayRevocations { peer: _ } => {
                self.replay_revocation_tokens().await;
            }
        }
    }

    async fn handle_try_admit(
        &mut self,
        peer: MeshAddress,
        source: phalanx_proto::telemetry::DiscoverySource,
        bucket: SubnetBucket,
        transport: TransportClass,
        balance: TransportBalance,
    ) -> AdmitOutcome {
        // E6: Per-second rate limit on peer discovery processing.
        let now = Instant::now();
        if now.duration_since(self.peer_discovery_window) >= Duration::from_secs(1) {
            self.peer_discovery_count = 0;
            self.peer_discovery_window = now;
        }
        self.peer_discovery_count = self.peer_discovery_count.saturating_add(1);
        if self.peer_discovery_count > mesh_policy::PEER_DISCOVERY_RATE_LIMIT_PER_SEC {
            tracing::debug!(
                event = "e6_rate_limit",
                peer = %peer,
                "E6: Peer discovery rate exceeded, dropping"
            );
            return AdmitOutcome {
                admitted: false,
                evicted: None,
                was_first_seen: false,
            };
        }

        match self.topology_gate.try_admit(
            peer.clone(),
            phalanx_proto::trust::TrustLevel::default(),
            bucket,
            transport,
            balance,
        ) {
            Ok((_ticket, evicted)) => {
                self.system_governor.record_peer_discovery(source);
                self.system_governor.record_connection_gauge();

                self.update_peer_first_seen(&peer);

                let was_first_seen = self.revocation_synced_peers.insert(peer.clone());

                if let Some(ref evicted_peer) = evicted {
                    tracing::debug!(
                        event = "topology_eviction",
                        evicted = %evicted_peer,
                        newcomer = %peer,
                        "IWFQ: Evicted lower-trust peer to admit newcomer"
                    );
                    let _ = self
                        .egress_tx
                        .send(EgressCommand::DisconnectPeer(evicted_peer.clone()))
                        .await;
                }

                AdmitOutcome {
                    admitted: true,
                    evicted,
                    was_first_seen,
                }
            }
            Err(reason) => {
                tracing::debug!(
                    event = "topology_rejected",
                    peer = %peer,
                    reason = %reason,
                    "TopologyGate rejected peer"
                );
                let _ = self
                    .egress_tx
                    .send(EgressCommand::DisconnectPeer(peer))
                    .await;
                AdmitOutcome {
                    admitted: false,
                    evicted: None,
                    was_first_seen: false,
                }
            }
        }
    }

    async fn handle_peer_disconnected(&mut self, peer: MeshAddress) {
        // Anchor demotion / gate slot release. The reciprocity sweep relies
        // on `peer_first_seen` retaining its original timestamp on
        // reconnect (prevents grace-period-reset attacks); we do NOT remove
        // from `peer_first_seen` here.
        self.topology_gate.demote_anchor(&peer);
        self.topology_gate.release(&peer);
        self.system_governor.record_peer_departure(false);
        self.system_governor.record_connection_gauge();
    }

    fn cache_did(&mut self, peer: MeshAddress, did: Did) {
        if self.did_cache.len() >= mesh_policy::PEER_DID_CACHE_CAP
            && !self.did_cache.contains_key(&peer)
        {
            // Evict the oldest entry (smallest seq) to bound memory.
            if let Some(oldest_peer) = self
                .did_cache
                .iter()
                .min_by_key(|(_, (_, seq))| *seq)
                .map(|(k, _)| k.clone())
            {
                self.did_cache.remove(&oldest_peer);
            }
        }
        self.did_cache_seq = self.did_cache_seq.saturating_add(1);
        self.did_cache.insert(peer, (did, self.did_cache_seq));
    }

    fn update_peer_first_seen(&mut self, peer: &MeshAddress) {
        if self.peer_first_seen.len() >= mesh_policy::PEER_FIRST_SEEN_CAP
            && !self.peer_first_seen.contains_key(peer)
        {
            if let Some(oldest_peer) = self
                .peer_first_seen
                .iter()
                .min_by_key(|&(_, &ts)| ts)
                .map(|(k, _)| k.clone())
            {
                self.peer_first_seen.remove(&oldest_peer);
            }
        }
        match self.clock.now() {
            Ok(ts) => {
                let now_secs = ts.as_u64() / 1000;
                self.peer_first_seen.entry(peer.clone()).or_insert(now_secs);
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    peer = %peer,
                    "clock unavailable; skipping peer_first_seen insert"
                );
            }
        }
    }

    // ── 5-minute topology tick: anchor promotion, eclipse risk, reciprocity ─

    async fn topology_maintenance_tick(&mut self) {
        self.promote_anchor_candidates();
        self.evaluate_eclipse_risk().await;
        self.sweep_reciprocity_floor().await;
        self.system_governor.prune_stale_integrals();
    }

    fn promote_anchor_candidates(&mut self) {
        use AnchorEligible;
        let peer_ids: Vec<MeshAddress> = self.topology_gate.peer_ids().cloned().collect();
        for peer_id in &peer_ids {
            if self.topology_gate.is_anchored(peer_id) {
                continue;
            }
            let score = self.reputation.evaluate_reputation(peer_id);
            if let Some(proof) = AnchorEligible::try_from_score(score) {
                if self.topology_gate.promote_to_anchor(peer_id, proof) {
                    tracing::debug!(
                        event = "anchor_promoted",
                        peer = %peer_id,
                        score = score,
                        "Promoted peer to anchor status"
                    );
                }
            }
        }
    }

    async fn evaluate_eclipse_risk(&mut self) {
        let peer_id_owned = self.health_tracker.peer_addresses();
        let mut peer_ids: Vec<&MeshAddress> = peer_id_owned.iter().collect();
        let peer_set_hash = eclipse::hash_peer_set(&mut peer_ids);
        let peer_count = peer_ids.len();
        let subnet_distribution = self.topology_gate.subnet_counts().clone();

        let now_secs = match self.clock.now() {
            Ok(ts) => ts.as_u64() / 1000,
            Err(e) => {
                tracing::warn!(error = %e, "clock unavailable; skipping eclipse fingerprint");
                return;
            }
        };

        let fingerprint = MeshFingerprint {
            peer_set_hash,
            peer_count,
            subnet_distribution,
            timestamp: phalanx_proto::time::MonotonicClock(now_secs),
        };

        self.eclipse_probe.record(fingerprint);
        let risk = self.eclipse_probe.evaluate();

        match risk {
            EclipseRisk::Elevated => {
                self.system_governor.record_eclipse_impulse(5.0);
                tracing::warn!(
                    target: "phalanx::shield_wall",
                    event = "eclipse_risk_elevated",
                    peer_count = peer_count,
                    "Eclipse probe: ELEVATED risk — Sybil pressure injected"
                );
            }
            EclipseRisk::Critical => {
                self.system_governor.record_eclipse_impulse(20.0);
                tracing::warn!(
                    target: "phalanx::shield_wall",
                    event = "eclipse_risk_critical",
                    peer_count = peer_count,
                    "Eclipse probe: CRITICAL risk — Sybil pressure injected, triggering re-bootstrap"
                );

                let _ = self
                    .trust_tx
                    .send(TrustCommand::RecordOffense {
                        did: self.identity.did.clone(),
                        offense: Offense::EclipseAttempt,
                    })
                    .await;

                if self.topology_gate.peer_count() < mesh_policy::RE_BOOTSTRAP_TRIGGER_PEER_COUNT {
                    let bootstrap_peers: Vec<String> = self
                        .config
                        .network
                        .bootstrap_peers
                        .iter()
                        .take(3)
                        .cloned()
                        .collect();
                    if !bootstrap_peers.is_empty() {
                        let _ = self
                            .egress_tx
                            .send(EgressCommand::ReBootstrap(bootstrap_peers))
                            .await;
                    }
                }
            }
            _ => {}
        }
    }

    async fn sweep_reciprocity_floor(&mut self) {
        let power_state = self.system_governor.current_power_state();
        if matches!(
            power_state,
            phalanx_proto::types::PowerState::Leaf | phalanx_proto::types::PowerState::Dormant
        ) {
            return;
        }

        let params = ReciprocityParams::default();
        let mesh_peer_count = self.topology_gate.peer_count();
        let now_secs = match self.clock.now() {
            Ok(ts) => ts.as_u64() / 1000,
            Err(e) => {
                tracing::warn!(error = %e, "clock unavailable; skipping reciprocity sweep");
                return;
            }
        };

        let admitted_peers: Vec<MeshAddress> = self.topology_gate.peer_ids().cloned().collect();

        for peer_id in &admitted_peers {
            let first_seen = self
                .peer_first_seen
                .get(peer_id)
                .copied()
                .unwrap_or(now_secs);
            let connected_secs = now_secs.saturating_sub(first_seen);
            let contribution = self.system_governor.peer_contribution_value(&peer_id.0);
            let is_local_mesh = self
                .topology_gate
                .transport_class(peer_id)
                .is_some_and(|tc| tc == TransportClass::LocalMesh);

            let snapshot = PeerContribution {
                connected_secs,
                contribution_integral: contribution,
                is_local_mesh,
            };

            if let ReciprocityVerdict::NonReciprocal { deficit } =
                evaluate_reciprocity(&snapshot, &params, mesh_peer_count)
            {
                self.system_governor
                    .record_spectral_anomaly(&peer_id.0, deficit * 5.0);

                if deficit > 0.8 {
                    if let Some((did, _)) = self.did_cache.get(peer_id) {
                        let _ = self
                            .trust_tx
                            .send(TrustCommand::RecordOffense {
                                did: did.clone(),
                                offense: Offense::NonReciprocal,
                            })
                            .await;
                    }
                }

                tracing::debug!(
                    target: "phalanx::shield_wall",
                    event = "reciprocity_deficit",
                    peer = %peer_id,
                    deficit = deficit,
                    connected_secs = connected_secs,
                    "Black hole detection: peer below reciprocity floor"
                );
            }
        }
    }

    async fn replay_revocation_tokens(&mut self) {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .storage_tx
            .send(StorageCommand::GetRevocationTokens { reply_to: reply_tx })
            .await
            .is_err()
        {
            return;
        }
        match reply_rx.await {
            Ok(tokens) if !tokens.is_empty() => {
                tracing::info!(
                    count = tokens.len(),
                    "Revocation replay: re-broadcasting to mesh"
                );
                for token in tokens {
                    let _ = self
                        .egress_tx
                        .send(EgressCommand::PublishRevocation(token))
                        .await;
                }
            }
            _ => {}
        }
    }
}
