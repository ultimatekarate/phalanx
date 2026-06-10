// crates/phalanx-node/src/actors/fleet.rs
//
// Construction helpers that keep `MeshSentinel::new` an assembly step rather
// than a god-constructor. Currently houses the Shield Wall group — the cohesive
// set of security actors (EclipseRouter, CanarySupervisor, VitalsActor,
// ArchiveCoordinator, RevocationActor) that share most of their inputs and are
// spawned together. The storage/pipeline actors stay inline in `new()` because
// they are interleaved with channel + Guardian setup and do not extract cleanly.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use phalanx_proto::community::CommunityId;
use phalanx_proto::identity::{MeshAddress, PhalanxIdentity};

use crate::actors::archive_coordinator::{ArchiveCommand, ArchiveCoordinator};
use crate::actors::canary_supervisor::{CanaryCommand, CanarySupervisor};
use crate::actors::eclipse_router::{EclipseCommand, EclipseRouter};
use crate::actors::egress::EgressCommand;
use crate::actors::revocation::{RevocationActor, RevocationCommand};
use crate::actors::shutdown::ShutdownSignal;
use crate::actors::storage::StorageCommand;
use crate::actors::trust_actor::TrustCommand;
use crate::actors::vitals_actor::{VitalsActor, VitalsCommand};
use crate::clock::TrustedClock;
use crate::config::NodeConfig;
use crate::trust::ReputationProjection;
use crate::vitals::{HealthTracker, SystemGovernor};

/// Shared singletons threaded into the Shield Wall actors. Plain data carrier —
/// each spawn clones the Arcs it needs.
pub(crate) struct Shared {
    pub config: Arc<NodeConfig>,
    pub identity: Arc<PhalanxIdentity>,
    pub clock: Arc<TrustedClock>,
    pub system_governor: Arc<SystemGovernor>,
    pub health_tracker: Arc<HealthTracker>,
    pub reputation: ReputationProjection,
    pub used_bytes_gauge: Arc<AtomicU64>,
    pub shutdown: Arc<ShutdownSignal>,
}

/// Command channels + task handles for the Shield Wall actor group. `handles`
/// are ordered EclipseRouter-first so they drain before the storage/egress
/// recipients they send to (VitalsActor's drain touches only HealthTracker, so
/// its position among the senders is safe).
pub(crate) struct ShieldWall {
    pub eclipse_tx: mpsc::Sender<EclipseCommand>,
    pub canary_tx: mpsc::Sender<CanaryCommand>,
    pub vitals_tx: mpsc::Sender<VitalsCommand>,
    pub archive_tx: mpsc::Sender<ArchiveCommand>,
    pub revocation_tx: mpsc::Sender<RevocationCommand>,
    pub handles: Vec<JoinHandle<()>>,
}

/// Spawn the Shield Wall actor group and return its command channels + handles.
/// `storage_tx`/`egress_tx`/`trust_tx` are borrowed (the caller keeps the
/// originals); the community keyset is cloned per actor (Canary pattern).
pub(crate) fn spawn_shield_wall(
    sh: &Shared,
    storage_tx: &mpsc::Sender<StorageCommand>,
    egress_tx: &mpsc::Sender<EgressCommand>,
    trust_tx: &mpsc::Sender<TrustCommand>,
    community_ids_rx: &watch::Receiver<Vec<CommunityId>>,
    extra_community_ids: &[CommunityId],
    local_mesh_address: &MeshAddress,
) -> ShieldWall {
    // EclipseRouter — topology / admission / eclipse remediation. Spawned FIRST
    // so it drains before its recipients (egress, trust, storage).
    let (eclipse_tx, eclipse_rx) = mpsc::channel::<EclipseCommand>(64);
    let eclipse_router = EclipseRouter::new(
        sh.config.clone(),
        sh.identity.clone(),
        sh.clock.clone(),
        sh.system_governor.clone(),
        sh.health_tracker.clone(),
        sh.reputation.clone(),
        egress_tx.clone(),
        trust_tx.clone(),
        storage_tx.clone(),
        eclipse_rx,
        sh.shutdown.clone(),
    );
    let eclipse_handle = tokio::spawn(eclipse_router.run());

    // CanarySupervisor — silent-canary monitoring. Takes eclipse_tx for
    // `DidLearned` notifies.
    let (canary_tx, canary_rx) = mpsc::channel::<CanaryCommand>(64);
    let canary_supervisor = CanarySupervisor::new(
        sh.clock.clone(),
        sh.health_tracker.clone(),
        sh.reputation.clone(),
        community_ids_rx.clone(),
        extra_community_ids.to_vec(),
        egress_tx.clone(),
        storage_tx.clone(),
        eclipse_tx.clone(),
        canary_rx,
        sh.shutdown.clone(),
    );
    let canary_handle = tokio::spawn(canary_supervisor.run());

    // VitalsActor — heartbeat publish (vitals cadence) + receive (decrypt,
    // strict-binding, spectral consistency).
    let (vitals_tx, vitals_rx) = mpsc::channel::<VitalsCommand>(64);
    let vitals_actor = VitalsActor::new(
        sh.system_governor.clone(),
        sh.health_tracker.clone(),
        sh.used_bytes_gauge.clone(),
        community_ids_rx.clone(),
        extra_community_ids.to_vec(),
        egress_tx.clone(),
        sh.config.network.control_topic.clone(),
        local_mesh_address.clone(),
        sh.config.storage.max_storage_bytes.as_u64(),
        vitals_rx,
        sh.shutdown.clone(),
    );
    let vitals_handle = tokio::spawn(vitals_actor.run());

    // ArchiveCoordinator — Stronghold custody staging + receipt ledger.
    let (archive_tx, archive_rx) = mpsc::channel::<ArchiveCommand>(64);
    let archive_coordinator = ArchiveCoordinator::new(
        sh.config.clone(),
        sh.identity.clone(),
        storage_tx.clone(),
        egress_tx.clone(),
        archive_rx,
        sh.shutdown.clone(),
    );
    let archive_handle = tokio::spawn(archive_coordinator.run());

    // RevocationActor — inbound revocation token verify/apply/propagate.
    let (revocation_tx, revocation_rx) = mpsc::channel::<RevocationCommand>(64);
    let revocation_actor = RevocationActor::new(
        storage_tx.clone(),
        egress_tx.clone(),
        revocation_rx,
        sh.shutdown.clone(),
    );
    let revocation_handle = tokio::spawn(revocation_actor.run());

    ShieldWall {
        eclipse_tx,
        canary_tx,
        vitals_tx,
        archive_tx,
        revocation_tx,
        handles: vec![
            eclipse_handle,
            canary_handle,
            vitals_handle,
            archive_handle,
            revocation_handle,
        ],
    }
}
