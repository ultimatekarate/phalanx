// --- crates/phalanx-node/src/actors/meshsentinel.rs ---
use crate::actors::archive_coordinator::ArchiveCommand;
use crate::actors::canary_supervisor::CanaryCommand;
use crate::actors::eclipse_router::{AdmitOutcome, EclipseCommand};
use crate::actors::egress::{EgressActor, EgressCommand};
use crate::actors::fleet;
use crate::actors::ingestion::{IngestionActor, IngestionCommand};
use crate::actors::media_egress::{MediaEgressActor, MediaEgressConfig};
use crate::actors::playback::PlaybackCoordinator;
use crate::actors::recording_session::RecordingSessionState;
use crate::actors::recovery::{PROVIDERS_CHANNEL_BUFFER, RecoveryContext, run_recovery};
use crate::actors::retrieval::{RetrievalActor, RetrievalCommand};
use crate::actors::revocation::RevocationCommand;
use crate::actors::shutdown::ShutdownSignal;
use crate::actors::storage::StorageCommand;
use crate::actors::trust_actor::{TrustActor, TrustCommand};
use crate::actors::vitals_actor::VitalsCommand;
use crate::clock::TrustedClock;
use crate::config::NodeConfig;

use crate::Guardian;
use crate::vitals::{HealthTracker, Homeostasis, LifecycleEvent, SystemGovernor};
use crate::{StorageActor, trust::TrustRegistry};

use phalanx_forensics::policy::{IngressGovernor, TrafficGovernor};
use phalanx_forensics::prelude::*;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::network::{EgressPort, IngressPort, LocalMeshPort};
use phalanx_proto::prelude::*;
use phalanx_proto::storage::TransientJournal;
use phalanx_proto::telemetry::DiscoverySource;
use phalanx_proto::topology::{SubnetBucket, TransportClass};
use phalanx_transport::identity_ext::Libp2pExt;
use std::sync::Arc;

use tokio::sync::mpsc;

use phalanx_proto::crypto::{DekMaster, SymmetricKey};
use phalanx_proto::evidence::{AudioShard, PrnuPosterior, StorageSequence, VideoShard};
use std::error::Error;
use std::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};

/// Returned when `spawn_playback` is invoked while a previous playback
/// coordinator is still live. The playback singleton is enforced
/// engine-side via `MeshSentinel::playback_slot`; this error is the
/// type-level signal that the at-most-one invariant was upheld.
///
/// Domain note: playback serves the user's own recordings AND
/// recordings they hold cryptographic grants for. Recovery is a
/// separate domain operation over the user's own manifest only — the
/// two share the `providers_rx` channel but have distinct lifecycles
/// and slots.
#[derive(Debug, thiserror::Error)]
#[error("a playback session is already active")]
pub struct AlreadyPlaying;

/// Commands the FFI (or any external driver) can dispatch to `MeshSentinel`.
///
/// Each variant covers an operation that requires `&mut MeshSentinel` —
/// `start_recording`, `stop_recording`, `spawn_recovery`, `spawn_playback`.
/// The run loop's `tokio::select!` services this mailbox alongside network
/// events, so commands execute inside the engine's own context without
/// external callers needing to acquire any lock on the sentinel.
///
/// This is the linguistically-correct entry point for sentinel-mutating
/// FFI requests: the FFI sends a command (future-tense, enqueued); the
/// engine handles it (present-tense, single-owner); nothing awaits on a
/// present-tense lock. See `linguistic-code-model.md` § Governance Command #5.
pub enum SentinelCommand {
    /// Set the active recording id. `Some(id)` starts a recording;
    /// `None` stops the current one. The session-state side effects
    /// (witness reset, content-key transition, `recording_active`
    /// atomic flip) run inside the engine's context.
    SetRecordingState {
        id: Option<RecordingId>,
        reply_to: tokio::sync::oneshot::Sender<()>,
    },
    /// Spawn a manifest-walk recovery session. The reply carries the
    /// `JoinHandle` for the spawned task so the FFI can store it (and
    /// abort on shutdown if needed). Cancellation flows through the
    /// `cancel_rx` half of a oneshot the caller owns.
    SpawnRecovery {
        status: Arc<Mutex<phalanx_proto::recovery::RecoveryStatus>>,
        cancel_rx: tokio::sync::oneshot::Receiver<()>,
        reply_to: tokio::sync::oneshot::Sender<JoinHandle<()>>,
    },
    /// Spawn a playback coordinator for the given recording. Engine
    /// enforces at-most-one playback via `playback_slot`; the reply
    /// carries `Err(AlreadyPlaying)` if a prior coordinator is still
    /// live. The sentinel owns the resulting `JoinHandle` in its slot —
    /// the FFI doesn't need it because playback lifecycle is
    /// implicit-shutdown-via-receiver-drop (drop the session → sinks
    /// fail on next send → `coordinator.run` exits).
    SpawnPlayback {
        recording_id: RecordingId,
        video_sink: Box<dyn phalanx_proto::playback::PlaybackSink + Send + Sync + 'static>,
        audio_sink: Box<dyn phalanx_proto::playback::PlaybackSink + Send + Sync + 'static>,
        reply_to: tokio::sync::oneshot::Sender<Result<(), AlreadyPlaying>>,
    },
}

pub struct SentinelDependencies<I: IngressPort, E: EgressPort, J: TransientJournal> {
    pub config: NodeConfig,
    pub identity: PhalanxIdentity,
    pub ingress: I,
    pub egress: E,
    pub journal: J,
    pub trust_registry: TrustRegistry,
    pub system_governor: Arc<SystemGovernor>,
    pub vault_key: SymmetricKey,
    /// HKDF master used by Guardian to derive per-recording DEKs. Threaded
    /// from `identity.dek_master` so the construction order (identity →
    /// Guardian) doesn't have to grow a hidden coupling.
    pub dek_master: DekMaster,
    /// Optional local mesh transport (BLE, WiFi Direct).
    /// Default: `None` (desktop/non-BLE platforms).
    /// When `Some`, MeshSentinel polls for local mesh events alongside network ingress.
    pub local_mesh: Option<Box<dyn LocalMeshPort>>,
    /// Bayesian PRNU posterior — shared with the FFI capture path.
    /// MediaEgressActor reads this for luminance-conditioned provenance checks.
    pub prnu_posterior: Arc<Mutex<PrnuPosterior>>,
    /// Additional `CommunityId`s to seed into the sentinel's heartbeat
    /// keyset, on top of those derived from the trust registry. Production
    /// callers pass an empty `Vec`; integration tests use this to wire a
    /// known community key without standing up a full `TrustRegistry`
    /// `Community` object (which has substantial cryptographic invariants).
    pub extra_community_ids: Vec<phalanx_proto::community::CommunityId>,
    /// The MeshAddress form this node will claim as `sender` on outbound
    /// heartbeats. Must match the form used for `origin` on the receive
    /// side, since strict-binding requires `msg.sender == origin`.
    /// - Production (libp2p): `Libp2pExt::to_mesh_address(&identity)` —
    ///   libp2p PeerId base58 (`12D3KooW...`), matching
    ///   `PeerMapper::to_mesh_address(&propagation_source)` on receive.
    /// - Simulation: the harness's `network_id`, typically
    ///   `MeshAddress::new(identity.witness_id.0.clone())` (multibase
    ///   `z6Mk...`), matching what `SimulationWorld` routes with.
    /// The two encodings are different renderings of the same Ed25519
    /// public key; mixing them silently breaks every heartbeat.
    pub local_mesh_address: MeshAddress,
}

pub struct MeshSentinel<I: IngressPort> {
    // Core router dependencies
    pub config: Arc<NodeConfig>,
    pub identity: Arc<PhalanxIdentity>,
    pub ingress: I,

    // For processing inbound control messages.
    // Arc-shared so EclipseRouter and CanarySupervisor can read peer state without
    // duplicating it. See vitals/health.rs for the lock-discipline doc-comment.
    pub health_tracker: Arc<HealthTracker>,

    // For the playback factory method
    pub storage_tx: mpsc::Sender<StorageCommand>,
    pub network_key: Arc<SymmetricKey>,
    pub discovery_tx: mpsc::Sender<(RecordingId, StorageSequence)>,

    // Homeostasis feedback
    pub system_governor: Arc<SystemGovernor>,

    // Actor dispatch channels
    pub ingestion_tx: mpsc::Sender<IngestionCommand>,
    pub retrieval_tx: mpsc::Sender<RetrievalCommand>,
    pub egress_tx: mpsc::Sender<EgressCommand>,

    /// Shared cancellation signal, cloned into every spawned background task.
    /// Fired by `shutdown()` to wake actors' select! loops out of `rx.recv()`.
    shutdown: Arc<ShutdownSignal>,

    /// JoinHandles for all seven spawned background tasks (storage, egress,
    /// trust, retrieval, ingestion, media, vitals). Taken by `shutdown()` and
    /// awaited with a shared 10-second deadline.
    background_tasks: Vec<JoinHandle<()>>,

    // DHT: Receives notifications when StorageActor persists a shard.
    // Triggers `EgressCommand::AnnounceRecording` to announce the recording on the DHT.
    commit_notify_rx: mpsc::Receiver<RecordingId>,

    // DHT: Receives (recording_id, sequence_id) from PlaybackCoordinator when it
    // discovers missing shards. Triggers `EgressCommand::FindProviders`.
    discovery_rx: mpsc::Receiver<(RecordingId, StorageSequence)>,

    // Optional local mesh transport (BLE, WiFi Direct).
    // When available, the select! loop polls for local mesh events.
    local_mesh: Option<Box<dyn LocalMeshPort>>,

    // Lifecycle event receiver for mobile foreground/background transitions.
    // When a `Foregrounded` event arrives, immediately recalculate PowerState.
    // Desktop: always `None` (no foreground/background concept).
    lifecycle_rx: Option<tokio::sync::mpsc::Receiver<LifecycleEvent>>,

    // DHT: Provider discovery forwarding to the active PlaybackCoordinator.
    // Replaced with a fresh channel on each spawn_playback() call.
    providers_tx: mpsc::Sender<(RecordingId, Vec<MeshAddress>)>,

    /// At-most-one active playback coordinator. `Some` iff a playback
    /// task is running (or finished but unreaped). `spawn_playback`
    /// rejects a fresh request when this slot holds an unfinished
    /// JoinHandle.
    ///
    /// This is the structural counterpart to the runtime gates the FFI
    /// previously needed: the invariant "only one playback at a time"
    /// is encoded in the field, not in scattered checks across
    /// callsites. Replaces the prior FFI-side dummy-channel pattern at
    /// `phalanx-ffi/src/playback.rs`.
    playback_slot: Option<JoinHandle<()>>,

    // Shield Wall: Trust channel for dispatching spectral anomaly offenses.
    pub trust_tx: mpsc::Sender<TrustCommand>,

    // Media capture channels — exposed for FFI frame injection.
    // Desktop sentinel ignores these; the FFI handle clones them for phalanx_push_video_frame().
    pub video_tx: mpsc::Sender<VideoShard>,
    pub audio_tx: mpsc::Sender<AudioShard>,

    // EclipseRouter command channel. Topology, eclipse remediation,
    // reciprocity sweep, revocation replay, and the per-peer first-seen /
    // revocation-synced ledgers all live on EclipseRouter now.
    eclipse_tx: mpsc::Sender<EclipseCommand>,

    // CanarySupervisor command channel. CanaryMonitor, peer_did_cache, and
    // the canary alert escalation/broadcast paths all live on CanarySupervisor.
    canary_tx: mpsc::Sender<CanaryCommand>,

    // VitalsActor command channel. Inbound heartbeat receive (decrypt +
    // strict-binding + spectral) and the periodic vitals/heartbeat publish.
    vitals_tx: mpsc::Sender<VitalsCommand>,

    // ArchiveCoordinator command channel. Stronghold custody staging + the
    // per-recording replica/deadline ledger.
    archive_tx: mpsc::Sender<ArchiveCommand>,

    // RevocationActor command channel. Inbound revocation token verify/apply/
    // propagate (cryptographic forgetting).
    revocation_tx: mpsc::Sender<RevocationCommand>,

    /// Recording-session state container. FFI mutates via `start_recording`
    /// / `stop_recording` methods on `MeshSentinel`, not by reaching in.
    pub session: RecordingSessionState,
    /// Trusted clock for forensic timestamps.
    pub clock: Arc<TrustedClock>,

    /// Live registry-derived community keyset. The watch sender lives on
    /// `TrustRegistry` and republishes whenever the HashMap mutates
    /// (Import / Dissolve / expiry). Reading: `borrow().clone()` in a
    /// single statement — never hold the `Ref<'_, T>` across `.await`,
    /// it deadlocks the watch system.
    pub community_ids_rx: tokio::sync::watch::Receiver<Vec<phalanx_proto::community::CommunityId>>,
    /// Static seeds layered on top of the live registry snapshot. Used by
    /// integration tests that don't stand up a full `TrustRegistry`
    /// `Community` object. Production callers pass an empty `Vec`. Cloned into
    /// CanarySupervisor and VitalsActor at spawn time — both the heartbeat
    /// receive and publish paths now live on VitalsActor. The sentinel retains
    /// the field as the canonical seed (and for test assertions).
    pub extra_community_ids: Vec<phalanx_proto::community::CommunityId>,

    /// Sender for `SentinelCommand`s. Cloned out by `EngineHandle::spawn`
    /// so the FFI can dispatch operations that need `&mut MeshSentinel`
    /// without ever acquiring a lock on the sentinel itself.
    pub sentinel_cmd_tx: mpsc::Sender<SentinelCommand>,
    /// Receiver half. Read only by the run loop's `select!`.
    sentinel_cmd_rx: mpsc::Receiver<SentinelCommand>,
}

impl<I: IngressPort> MeshSentinel<I> {
    pub async fn new<E, J>(mut deps: SentinelDependencies<I, E, J>) -> Result<Self, Box<dyn Error>>
    where
        E: EgressPort + 'static,
        J: TransientJournal + Send + 'static,
    {
        // Captured early so the vitals task spawn block (later in this
        // function) can use it without reaching back into `deps`.
        let local_mesh_address = deps.local_mesh_address.clone();

        // Shared cancellation signal — cloned into every spawned task so
        // `shutdown()` can signal them all at once. See ShutdownSignal docs
        // for why this is Arc<Notify>+AtomicBool and not tokio-util.
        let shutdown = ShutdownSignal::new();

        let local_did = deps.identity.did.clone();
        let _local_network_id = deps.identity.to_mesh_address();
        let local_witness_id = deps.identity.witness_id.clone();
        let reassembler = Reassembler::new();
        let raw_clock = TrustedClock::new();
        let clock_handle = Arc::new(raw_clock);
        let guardian = Guardian::new(
            &deps.config.storage.vault_path,
            &deps.config,
            local_did,
            clock_handle.clone(),
            deps.vault_key.clone(),
            deps.dek_master.clone(),
        );
        let phys_capacity = deps.system_governor.config.pipeline_capacity();

        let (video_tx, video_rx) = mpsc::channel(deps.config.storage.max_video_buffer);
        let (audio_tx, audio_rx) = mpsc::channel(deps.config.storage.max_audio_buffer);
        // Proximity-witness egress channel. RecordingSessionState drains
        // witnesses on stop() and hands them to MediaEgressActor through this
        // sender; MeshSentinel only wires it (no field, no witness logic here).
        let (proximity_tx, proximity_rx) = mpsc::channel(phys_capacity);

        let (storage_tx, storage_rx) = mpsc::channel(phys_capacity);
        let (ingestion_tx, ingestion_rx) = mpsc::channel(phys_capacity);
        let ingress_governor = IngressGovernor::new(phys_capacity);
        let (egress_tx, egress_rx) = mpsc::channel(100);
        let (retrieval_tx, retrieval_rx) = mpsc::channel(100);
        let (trust_tx, trust_rx) = mpsc::channel(100);
        let (discovery_tx, discovery_rx) = mpsc::channel(100);
        let (commit_notify_tx, commit_notify_rx) = mpsc::channel(100);
        // SentinelCommand mailbox — serviced by the run loop's `select!` so
        // external callers (FFI, sim) can mutate sentinel state via channel
        // commands instead of locking the sentinel.
        let (sentinel_cmd_tx, sentinel_cmd_rx) = mpsc::channel(32);

        // Stateless Recovery: Pull salvaged egress from the journal
        let salvaged_queue = deps
            .journal
            .read_all_pending_egress()
            .await
            .unwrap_or_default();

        if !salvaged_queue.is_empty() {
            tracing::info!(
                count = salvaged_queue.len(),
                "Engine Bootstrap: Recovered salvaged egress records"
            );
        }

        // Used-bytes gauge: mirrors guardian.ledger.total_local_bytes() into
        // a shared atomic so the vitals task can read it without a channel
        // round-trip. Refreshed on StorageActor's 1s maintenance tick.
        let used_bytes_gauge = Arc::new(std::sync::atomic::AtomicU64::new(0));

        // Vault instantiation (Pure IO configuration)
        let storage_actor = StorageActor {
            reassembler,
            guardian,
            journal: deps.journal,
            config: deps.config.clone(),
            identity: deps.identity.clone(),
            current_tolerance: Duration::from_millis(1000),
            system_governor: deps.system_governor.clone(),
            commit_notify_tx: Some(commit_notify_tx),
            replay_filter: phalanx_forensics::bloom::RotatingBloomFilter::new(
                phalanx_forensics::bloom::RotatingBloomFilter::DEFAULT_CAPACITY,
            ),
            shutdown: shutdown.clone(),
            used_bytes_gauge: used_bytes_gauge.clone(),
        };

        let storage_handle = tokio::spawn(async move {
            storage_actor.run(storage_rx).await;
        });

        // Egress Actor instantiation
        let egress_actor = EgressActor::new(
            deps.egress.clone(),
            egress_rx,
            salvaged_queue,
            deps.system_governor.clone(),
            clock_handle.clone(),
            shutdown.clone(),
        );

        let egress_handle = tokio::spawn(async move {
            egress_actor.run().await;
        });

        let arc_identity = Arc::new(deps.identity.clone());

        // Trust Manager Actor
        let reputation_projection = deps.trust_registry.projection_handle();
        // Subscribe to the live community-key watch BEFORE
        // `trust_registry` moves into TrustActor. Subscribers see the
        // initial snapshot (empty Vec on a fresh node — communities aren't
        // persisted) and every subsequent Import/Dissolve/expiry refresh.
        let community_ids_rx = deps.trust_registry.community_ids_subscribe();
        let extra_community_ids: Vec<_> = deps.extra_community_ids.drain(..).collect();
        let trust_registry = deps.trust_registry;
        let trust_actor = TrustActor::new(trust_registry, trust_rx, shutdown.clone());
        let trust_handle = tokio::spawn(trust_actor.run());

        // Use the real vault_key — shards are encrypted with this key by MediaEgressActor.
        // The previous [0x42; 32] was a placeholder that caused silent decryption failures.
        let network_key = Arc::new(deps.vault_key.clone());

        let retrieval_actor = RetrievalActor::new(
            arc_identity.clone(),
            clock_handle.clone(),
            deps.system_governor.clone(),
            storage_tx.clone(),
            egress_tx.clone(),
            reputation_projection.clone(),
            trust_tx.clone(), // Pass the sender to the retrieval actor
            network_key.clone(),
            retrieval_rx,
            shutdown.clone(),
        );
        let retrieval_handle = tokio::spawn(retrieval_actor.run());

        // Shield Wall: retain a trust_tx handle for spectral anomaly dispatch.
        let sentinel_trust_tx = trust_tx.clone();

        // Ingestion Actor
        let ingestion_actor = IngestionActor::new(
            deps.config.clone(),
            arc_identity.clone(),
            clock_handle.clone(),
            TrafficGovernor::new(),
            ingress_governor,
            reputation_projection.clone(),
            storage_tx.clone(),
            egress_tx.clone(),
            trust_tx,
            deps.system_governor.clone(),
            ingestion_rx,
            shutdown.clone(),
        );
        let ingestion_handle = tokio::spawn(ingestion_actor.run());

        // Media Egress Actor instantiation — WAL-backed outbound queue for retry
        // with integral feedback: outbound queue pressure → w_integral → FPS self-regulation.
        let outbound_wal_dir =
            std::path::PathBuf::from(&deps.config.storage.vault_path).join("outbound_wal");
        // Per-recording content key watch channel: MeshSentinel → MediaEgressActor.
        // When a recording starts, the content key (DEK) is sent via this channel.
        // MediaEgressActor prefers the content key over vault_key for encryption.
        let (content_key_tx, content_key_rx) =
            tokio::sync::watch::channel::<Option<phalanx_proto::crypto::SymmetricKey>>(None);
        let media_actor = MediaEgressActor::new(
            deps.egress.clone(),
            arc_identity.clone(),
            local_witness_id.clone(),
            MediaEgressConfig {
                video_rx,
                audio_rx,
                proximity_rx,
                video_topic: deps.config.network.video_topic.clone(),
                audio_topic: deps.config.network.audio_topic.clone(),
                symbol_size: deps.config.network.symbol_size,
                repair_ratio: deps.config.network.repair_ratio,
                symbol_bundle_size: deps.config.network.symbol_bundle_size,
                wal_dir: outbound_wal_dir,
                system_governor: deps.system_governor.clone(),
                max_storage_bytes: deps.config.storage.max_storage_bytes.as_u64(),
                vault_key: deps.vault_key.clone(),
                content_key_rx,
                clock: clock_handle.clone(),
                prnu_posterior: deps.prnu_posterior.clone(),
                storage_tx: storage_tx.clone(),
            },
            shutdown.clone(),
        )
        .await
        .map_err(|e| -> Box<dyn Error> {
            format!("Failed to initialize MediaEgressActor outbound queue: {e}").into()
        })?;

        let media_handle = tokio::spawn(media_actor.run());

        let config_arc = Arc::new(deps.config);

        if let Some(ref mesh) = deps.local_mesh {
            if mesh.is_available() {
                tracing::info!("Local mesh transport is AVAILABLE");
            } else {
                tracing::debug!("Local mesh transport provided but not available");
            }
        }

        // Extract lifecycle event receiver from hardware probe.
        // Mobile implementations push OS lifecycle callbacks into this channel.
        // Desktop (SysfsProbe) returns None.
        let lifecycle_rx = deps.system_governor.probe().lifecycle_events();

        // Placeholder providers_tx. Receiver is dropped immediately so the channel
        // is closed-at-birth; the field is overwritten with a live channel inside
        // `spawn_playback()`. Any `self.providers_tx.try_send(...)` before the first
        // playback starts will fail with `TrySendError::Closed` — that is the
        // intended no-op for pre-playback provider announcements.
        let (providers_tx, _) = mpsc::channel(1);

        // Shared HealthTracker (per-field RwLocks; see vitals/health.rs lock
        // discipline). MeshSentinel writes via register_activity; EclipseRouter
        // and CanarySupervisor read.
        let health_tracker = Arc::new(HealthTracker::new());

        // ── Shield Wall ─────────────────────────────────────────────────────
        // Spawn the security-actor group as one cohesive unit: EclipseRouter
        // (topology/admission), CanarySupervisor (silent canary), VitalsActor
        // (heartbeat publish+receive), ArchiveCoordinator (custody staging),
        // RevocationActor (cryptographic forgetting). Spawned after the shared
        // HealthTracker exists; its handles drain ahead of the storage/egress
        // recipients they send to (eclipse first). See `actors::fleet`.
        let shared = fleet::Shared {
            config: config_arc.clone(),
            identity: arc_identity.clone(),
            clock: clock_handle.clone(),
            system_governor: deps.system_governor.clone(),
            health_tracker: health_tracker.clone(),
            reputation: reputation_projection.clone(),
            used_bytes_gauge: used_bytes_gauge.clone(),
            shutdown: shutdown.clone(),
        };
        let fleet::ShieldWall {
            eclipse_tx,
            canary_tx,
            vitals_tx,
            archive_tx,
            revocation_tx,
            handles: shield_wall_handles,
        } = fleet::spawn_shield_wall(
            &shared,
            &storage_tx,
            &egress_tx,
            &sentinel_trust_tx,
            &community_ids_rx,
            &extra_community_ids,
            &local_mesh_address,
        );

        // Drain order: Shield Wall senders first (eclipse leading), then the
        // storage/egress/pipeline recipients they dispatch to.
        let mut background_tasks = shield_wall_handles;
        background_tasks.push(storage_handle);
        background_tasks.push(egress_handle);
        background_tasks.push(trust_handle);
        background_tasks.push(retrieval_handle);
        background_tasks.push(ingestion_handle);
        background_tasks.push(media_handle);

        Ok(Self {
            config: config_arc,
            identity: arc_identity,
            ingress: deps.ingress,
            health_tracker,
            system_governor: deps.system_governor.clone(),
            network_key: network_key.clone(),
            shutdown: shutdown.clone(),
            background_tasks,
            storage_tx,
            ingestion_tx,
            retrieval_tx,
            egress_tx,
            discovery_tx,
            commit_notify_rx,
            discovery_rx,
            local_mesh: deps.local_mesh,
            lifecycle_rx,
            providers_tx,
            playback_slot: None,
            trust_tx: sentinel_trust_tx,
            video_tx,
            audio_tx,
            eclipse_tx,
            canary_tx,
            vitals_tx,
            archive_tx,
            revocation_tx,
            session: RecordingSessionState::new(content_key_tx, proximity_tx),
            clock: clock_handle.clone(),
            community_ids_rx,
            extra_community_ids,
            sentinel_cmd_tx,
            sentinel_cmd_rx,
        })
    }

    /// Network event router. The select! arms only route events to specialised
    /// handlers — multi-field-state logic lives on sub-actors (EclipseRouter,
    /// CanarySupervisor) or on RecordingSessionState. Adding new event handlers
    /// here that read multi-field state is a regression toward the God Object
    /// shape this actor was split out of.
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Counter increments and timestamp arithmetic.
    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        loop {
            let should_shutdown = tokio::select! {
                Some(event) = self.ingress.next_event() => {
                    self.handle_network_event(event).await
                }

                // Poll local mesh transport for events (BLE, WiFi Direct).
                Some(local_event) = async {
                    match self.local_mesh.as_mut() {
                        Some(mesh) if mesh.is_available() => mesh.next_local_event().await,
                        _ => std::future::pending().await,
                    }
                } => {
                    tracing::debug!(event = "local_mesh_event", "Received event from local transport");
                    self.handle_network_event(local_event).await
                }

                Some(recording_id) = self.commit_notify_rx.recv() => {
                    self.handle_commit_notification(recording_id).await
                }

                Some((recording_id, _sequence_id)) = self.discovery_rx.recv() => {
                    self.handle_discovery_query(recording_id).await
                }

                Some(lifecycle_event) = async {
                    match self.lifecycle_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    self.handle_lifecycle_event(lifecycle_event)
                }

                Some(cmd) = self.sentinel_cmd_rx.recv() => {
                    self.handle_sentinel_command(cmd);
                    false
                }
            };

            if should_shutdown {
                break;
            }
        }
        Ok(())
    }

    /// Dispatch a `SentinelCommand` against `&mut self`. Runs inside the
    /// run loop's `select!` arm, so the caller never needs a lock on the
    /// sentinel — they just `send` on the command channel and await the
    /// per-variant `reply_to` oneshot.
    fn handle_sentinel_command(&mut self, cmd: SentinelCommand) {
        match cmd {
            SentinelCommand::SetRecordingState { id, reply_to } => {
                match id {
                    Some(rec_id) => self.start_recording(rec_id, None),
                    None => {
                        self.stop_recording();
                    }
                }
                let _ = reply_to.send(());
            }
            SentinelCommand::SpawnRecovery {
                status,
                cancel_rx,
                reply_to,
            } => {
                let jh = self.spawn_recovery(status, cancel_rx);
                let _ = reply_to.send(jh);
            }
            SentinelCommand::SpawnPlayback {
                recording_id,
                video_sink,
                audio_sink,
                reply_to,
            } => {
                let result = self.spawn_playback(recording_id, video_sink, audio_sink);
                let _ = reply_to.send(result);
            }
        }
    }

    /// Signal all background tasks to exit, then wait for them to drain.
    ///
    /// Idempotent: the underlying `ShutdownSignal` ignores repeated `cancel()`
    /// calls, and `std::mem::take` leaves `background_tasks` empty so any
    /// second invocation is a no-op.
    ///
    /// Shared 10-second deadline across all handles (not per-handle) so the
    /// worst-case shutdown is bounded at 10s, not 10s × task count.
    pub async fn shutdown(&mut self) {
        self.shutdown.cancel();

        let handles = std::mem::take(&mut self.background_tasks);
        // Instant + Duration can theoretically overflow, but adding 10s to a
        // freshly observed monotonic Instant cannot reach the saturation limit
        // on any supported platform — this is a shared deadline, not an
        // unbounded arithmetic expression.
        #[allow(clippy::arithmetic_side_effects)]
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

        for handle in handles {
            match tokio::time::timeout_at(deadline, handle).await {
                Ok(Ok(())) => {}
                Ok(Err(join_err)) => {
                    tracing::warn!(error = %join_err, "background task panicked during shutdown");
                }
                Err(_) => {
                    tracing::warn!("background task did not drain within deadline; abandoning");
                    break; // Remaining handles will also exceed the deadline.
                }
            }
        }

        tracing::info!("MeshSentinel background tasks drained");
    }

    // ── FFI facade methods ──────────────────────────────────────────────────

    /// Mark a recording as active. Pushes the optional content key via the
    /// session's watch channel; signals CanarySupervisor to clear watched state.
    /// Called by FFI in response to user-initiated recording starts.
    pub fn start_recording(&mut self, id: RecordingId, key: Option<[u8; 32]>) {
        self.session.start(id.clone(), key);
        let _ = self
            .canary_tx
            .try_send(CanaryCommand::RecordingStarted { recording_id: id });
    }

    /// Stop the active recording. The session seals and egresses any captured
    /// proximity witnesses, clears the content-key watch channel (revert to
    /// vault_key encryption), and signals CanarySupervisor to clear watched state.
    pub fn stop_recording(&mut self) {
        let _ = self.canary_tx.try_send(CanaryCommand::RecordingStopped);
        self.session.stop();
    }

    /// Clone of the content-key watch sender for the FFI handle. Allows FFI
    /// to push the per-recording key independently of the session state
    /// machine (the watch channel keeps the latest value, so concurrent
    /// senders do not conflict).
    #[must_use]
    pub fn content_key_tx(
        &self,
    ) -> tokio::sync::watch::Sender<Option<phalanx_proto::crypto::SymmetricKey>> {
        self.session.content_key_tx_clone()
    }

    /// DHT: StorageActor persisted a shard — announce as provider, and forward
    /// to `ArchiveCoordinator` to stage at any configured Stronghold custody
    /// peers (export-staging). `send().await` (not `try_send`) so a single-shard
    /// recording's lone staging directive is never dropped — deadlock-free
    /// because StorageActor emits `commit_notify` via `try_send`.
    async fn handle_commit_notification(&mut self, recording_id: RecordingId) -> bool {
        let _ = self
            .archive_tx
            .send(ArchiveCommand::StageRecording {
                recording_id: recording_id.clone(),
            })
            .await;
        if let Err(e) = self
            .egress_tx
            .send(EgressCommand::AnnounceRecording(recording_id))
            .await
        {
            tracing::warn!("Failed to announce recording on DHT — egress channel closed: {e}");
        }
        false
    }

    /// DHT: PlaybackCoordinator needs a missing shard — find providers.
    async fn handle_discovery_query(&mut self, recording_id: RecordingId) -> bool {
        if let Err(e) = self
            .egress_tx
            .send(EgressCommand::FindProviders(recording_id))
            .await
        {
            tracing::warn!("Failed to find providers — egress channel closed: {e}");
        }
        false
    }

    /// Lifecycle events from mobile OS (foreground/background).
    /// Immediately recalculates PowerState so capture resumes within milliseconds.
    /// Desktop: lifecycle_rx is None, so this arm blocks via pending().
    fn handle_lifecycle_event(&self, event: LifecycleEvent) -> bool {
        match event {
            LifecycleEvent::Foregrounded => {
                tracing::info!(
                    event = "lifecycle_foregrounded",
                    "App foregrounded — immediate PowerState recalculation"
                );
                self.system_governor.update_vitals();
            }
            LifecycleEvent::Backgrounded => {
                tracing::info!(
                    event = "lifecycle_backgrounded",
                    "App backgrounded — PowerState will transition to Dormant"
                );
                self.system_governor.update_vitals();
            }
        }
        false // Never shutdown from lifecycle events
    }

    /// Unified event handler for both network ingress and local mesh events.
    /// Returns `true` if the engine should shut down.
    #[tracing::instrument(level = "debug", skip_all)]
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Counter increments and timestamp arithmetic.
    async fn handle_network_event(&mut self, event: NetworkEvent) -> bool {
        match event {
            NetworkEvent::DataReceived {
                origin,
                topic,
                data,
            } => {
                self.handle_data_received(origin, topic, data).await;
                false
            }
            NetworkEvent::PeerDiscovered {
                peer,
                source,
                bucket,
                transport,
            } => {
                self.handle_peer_discovered(peer, source, bucket, transport)
                    .await;
                false
            }
            NetworkEvent::RecordingRequested {
                origin,
                request,
                channel_id,
            } => {
                let _ = self
                    .retrieval_tx
                    .send(RetrievalCommand::SecureRetrieval {
                        origin,
                        request,
                        channel_id,
                    })
                    .await;
                false
            }
            NetworkEvent::ProvidersDiscovered {
                recording_id,
                providers,
            } => {
                self.handle_providers_discovered(recording_id, providers);
                false
            }
            NetworkEvent::ArchiveRequested { channel_id, .. } => {
                // A publishing node is not a custody target — only Strongholds
                // accept pushes. Drop; the pusher's request will time out.
                tracing::debug!(
                    channel_id = %channel_id,
                    "Archive: push received by a non-custody node; ignoring"
                );
                false
            }
            NetworkEvent::ArchiveReceiptReceived { from: _, receipt } => {
                let _ = self
                    .archive_tx
                    .send(ArchiveCommand::ReceiptReceived { receipt })
                    .await;
                false
            }
            NetworkEvent::ShardResponseReceived { origin, envelopes } => {
                self.handle_shard_response(origin, envelopes).await;
                false
            }
            NetworkEvent::PeerDisconnected { peer } => {
                self.handle_peer_disconnected(peer).await;
                false
            }
            NetworkEvent::BleAuthChallengeReceived { .. }
            | NetworkEvent::BleAuthResponseReceived { .. } => {
                tracing::debug!(
                    "BLE auth event received — handled by Flutter FFI, not MeshSentinel"
                );
                false
            }
            NetworkEvent::Shutdown => {
                self.handle_shutdown().await;
                true
            }
        }
    }

    // ── Event Handlers ──────────────────────────────────────────────────

    /// Handles incoming data: oversized message rejection, control message
    /// spectral analysis, and bandwidth-gated ingestion forwarding.
    #[tracing::instrument(level = "debug", skip_all)]
    #[allow(clippy::arithmetic_side_effects)] // Size comparisons and memory pressure recording.
    async fn handle_data_received(&mut self, origin: MeshAddress, topic: MeshTopic, data: Vec<u8>) {
        // P5 FIX: Reject oversized messages before any processing.
        if data.len() > self.config.network.max_chunk_size_bytes * 2 {
            tracing::warn!(
                size = data.len(),
                limit = self.config.network.max_chunk_size_bytes * 2,
                peer = %origin,
                "P5: Oversized message rejected pre-queue"
            );
            return;
        }

        if topic.as_str() == self.config.network.control_topic.as_str() {
            // Inbound heartbeat → VitalsActor (drop-tolerant presence signal).
            let _ = self
                .vitals_tx
                .try_send(VitalsCommand::InboundHeartbeat { origin, data });
        } else if topic.as_str() == self.config.network.revocation_topic.as_str() {
            // Inbound revocation token → RevocationActor (no-drop: send().await).
            let _ = self
                .revocation_tx
                .send(RevocationCommand::InboundToken { origin, data })
                .await;
        } else {
            self.handle_data_chunk(origin, topic, data);
        }
    }

    #[allow(clippy::arithmetic_side_effects)] // Memory pressure arithmetic.
    fn handle_data_chunk(&mut self, origin: MeshAddress, topic: MeshTopic, data: Vec<u8>) {
        // Shield Wall: record data volume for spectral observation
        self.health_tracker
            .record_data_received(origin.clone(), data.len());

        // Bandwidth gate: reject at the edge when saturated
        if self.system_governor.bandwidth_scaler().0 < 0.05 {
            tracing::warn!(
                size = data.len(),
                peer = %origin,
                "Bandwidth saturated, dropping chunk"
            );
        } else if self
            .ingestion_tx
            .try_send(IngestionCommand::ProcessChunk {
                peer_id: origin,
                data,
                topic,
            })
            .is_err()
        {
            self.system_governor
                .record_memory_pressure(self.config.network.max_chunk_size_bytes * 200);
            tracing::warn!("Ingestion channel full, dropping chunk.");
        }
    }

    /// Network-event router for peer discovery: dispatches admission to
    /// EclipseRouter, captures proximity witnesses on success, and triggers
    /// revocation replay for first-time peers.
    async fn handle_peer_discovered(
        &mut self,
        peer: MeshAddress,
        source: DiscoverySource,
        bucket: SubnetBucket,
        transport: TransportClass,
    ) {
        let balance = self.compute_transport_balance();
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if self
            .eclipse_tx
            .send(EclipseCommand::TryAdmit {
                peer: peer.clone(),
                source,
                bucket,
                transport,
                transport_balance: balance,
                reply_to: reply_tx,
            })
            .await
            .is_err()
        {
            return;
        }
        let outcome: AdmitOutcome = match reply_rx.await {
            Ok(o) => o,
            Err(_) => return,
        };

        if !outcome.admitted {
            return;
        }

        // Silent Canary: cancel any pending dark-peer confirmation.
        let _ = self
            .canary_tx
            .try_send(CanaryCommand::OnPeerReconnected { peer: peer.clone() });

        // ProximityWitness capture: if recording and this is LocalMesh,
        // log the co-location event for the Corroboration Gate.
        if transport == TransportClass::LocalMesh {
            if let Some(rec_id) = self.session.recording_id().cloned() {
                self.session
                    .push_witness(phalanx_proto::corroboration::ProximityWitness {
                        local_did: self.identity.did.clone(),
                        remote_did: phalanx_proto::identity::Did::new(peer.0.clone()),
                        recording_id: rec_id,
                        observed_at: self.clock.now().unwrap_or_default(),
                        transport,
                    });
            }
        }

        // First-time peer: trigger revocation replay so partitioned devices
        // catch up on deletions they missed.
        if outcome.was_first_seen {
            let _ = self
                .eclipse_tx
                .send(EclipseCommand::ReplayRevocations { peer })
                .await;
        }
    }

    /// DHT: Filter out self, forward remote providers to PlaybackCoordinator.
    fn handle_providers_discovered(
        &mut self,
        recording_id: RecordingId,
        providers: Vec<MeshAddress>,
    ) {
        let local_id = self.identity.to_mesh_address();
        let remote_providers: Vec<_> = providers.into_iter().filter(|p| *p != local_id).collect();
        if !remote_providers.is_empty() {
            tracing::info!(
                recording = %recording_id,
                count = remote_providers.len(),
                "DHT: Providers discovered for recording"
            );
            // `Closed` is benign — see the placeholder note on `providers_tx` in `new()`.
            // `Full` would mean the active PlaybackCoordinator consumer is stalled.
            match self.providers_tx.try_send((recording_id, remote_providers)) {
                Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::warn!("providers_tx full — playback consumer stalled");
                }
            }
        }
    }

    /// DHT: Forward received shards to the recording log (fire-and-forget).
    ///
    /// Storage's `handle_write_shard` logs its own persistence and
    /// verification results; awaiting a per-envelope reply here would stall
    /// the MeshSentinel select loop on disk latency, blocking unrelated
    /// mesh events (peer discovery, canary escalation, revocation replay).
    ///
    /// Channel-level backpressure is preserved via `send().await` on the
    /// bounded mpsc to storage: if storage cannot drain, MeshSentinel
    /// blocks on the mpsc — not on disk — and the queue depth stays
    /// bounded by the channel capacity rather than by per-write latency.
    async fn handle_shard_response(
        &mut self,
        origin: MeshAddress,
        envelopes: Vec<WitnessEnvelope>,
    ) {
        let count = envelopes.len();
        tracing::info!(
            peer = %origin,
            count,
            "DHT: Shard response received"
        );
        for envelope in envelopes {
            // Silent Canary: dispatch DID + contribution registration. Canary
            // updates its peer_did_cache, gates on effective_trust + recording,
            // and notifies Eclipse via DidLearned. Fire-and-forget.
            use phalanx_forensics::crucible::EvidenceExt;
            let _ = self
                .canary_tx
                .try_send(CanaryCommand::RegisterContribution {
                    origin: origin.clone(),
                    envelope_did: envelope.did.clone(),
                    evidence_recording_id: envelope.evidence.recording_id().clone(),
                });

            // Fire-and-forget: the reply receiver is intentionally dropped.
            // Storage logs failures itself; the oneshot is only here to
            // satisfy `StorageCommand::WriteShard`'s type signature.
            let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
            if let Err(e) = self
                .storage_tx
                .send(StorageCommand::WriteShard {
                    envelope,
                    reply_to: reply_tx,
                })
                .await
            {
                tracing::warn!("DHT shard write: storage channel closed: {e}");
                continue;
            }
        }
        tracing::debug!(
            peer = %origin,
            count,
            "DHT: dispatched shard writes"
        );
    }

    async fn handle_peer_disconnected(&mut self, peer: MeshAddress) {
        tracing::info!(
            event = "peer_disconnected",
            peer = %peer,
            "Peer disconnected"
        );
        // Spectral observer cleanup is router-side (HealthTracker is the
        // network event handler's state).
        self.health_tracker.remove_spectral_peer(&peer);
        // Topology / governor cleanup happens inside EclipseRouter.
        let _ = self
            .eclipse_tx
            .send(EclipseCommand::PeerDisconnected { peer: peer.clone() })
            .await;
        // Canary side handles its own staleness escalation via
        // Arc<HealthTracker>.is_peer_stale().
        let _ = self
            .canary_tx
            .try_send(CanaryCommand::PeerDisconnected { peer });
    }

    async fn handle_shutdown(&mut self) {
        tracing::info!("Engine: Initiating emergency salvage");
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self
            .egress_tx
            .send(EgressCommand::DrainForSalvage { reply_to: tx })
            .await
            .is_ok()
        {
            if let Ok(payload) = timeout(Duration::from_millis(500), rx).await {
                let _ = self
                    .storage_tx
                    .send(StorageCommand::EmergencySalvage(
                        payload.unwrap_or_default(),
                    ))
                    .await;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    /// Spawn a `PlaybackCoordinator` for the given recording.
    ///
    /// Enforces the at-most-one-playback invariant via `playback_slot`:
    /// if the prior task is still running, returns `Err(AlreadyPlaying)`
    /// without touching any state. A finished prior is reaped silently
    /// (its `JoinHandle` is replaced).
    ///
    /// Synchronous because `handle_sentinel_command` (the only external
    /// driver) is sync — the inline `GetContentKey` query and the
    /// payload-type debug probe both run inside the spawned task rather
    /// than blocking the run loop.
    pub fn spawn_playback(
        &mut self,
        recording_id: RecordingId,
        video_sink: Box<dyn PlaybackSink + Send + Sync + 'static>,
        audio_sink: Box<dyn PlaybackSink + Send + Sync + 'static>,
    ) -> Result<(), AlreadyPlaying> {
        // Reap a finished prior, or reject.
        if let Some(jh) = self.playback_slot.as_ref() {
            if !jh.is_finished() {
                return Err(AlreadyPlaying);
            }
        }

        // Fresh channel per playback session — only one active at a time.
        // Replacing providers_tx drops the old sender, signaling the previous
        // PlaybackCoordinator's providers_rx that no more data will arrive.
        // The singleton check above guarantees the previous coordinator has
        // already exited.
        let (providers_tx, providers_rx) = mpsc::channel(100);
        self.providers_tx = providers_tx;

        let storage_tx = self.storage_tx.clone();
        let egress_tx = self.egress_tx.clone();
        let discovery_tx = self.discovery_tx.clone();
        let identity = self.identity.clone();
        let network_key = self.network_key.clone();

        let jh = tokio::spawn(async move {
            // GetContentKey runs inside the task — failure is now localized to
            // the playback lifecycle rather than blocking the sentinel's run
            // loop. Falls back to network_key for legacy recordings.
            let decryption_key = {
                let (tx, rx) = tokio::sync::oneshot::channel();
                let _ = storage_tx
                    .send(StorageCommand::GetContentKey {
                        recording_id: recording_id.clone(),
                        reply_to: tx,
                    })
                    .await;
                match rx.await {
                    Ok(Some(key_bytes)) => {
                        Some(phalanx_proto::crypto::SymmetricKey::from_bytes(key_bytes))
                    }
                    _ => Some((*network_key).clone()),
                }
            };

            // Payload-type debug probe on shard 1. Preserves the one
            // useful signal from the prior FFI-side diagnostic block: lets
            // device debugging distinguish "shard missing" from "decrypt
            // failed" without firing up logcat triage tooling. The other
            // four probes (ListRecordings / DebugRecordingInfo /
            // DebugVaultListing / a duplicate GetContentKey) have been
            // deleted as scaffolding from when playback wasn't working.
            {
                let (probe_tx, probe_rx) = tokio::sync::oneshot::channel();
                let _ = storage_tx
                    .send(StorageCommand::GetShard {
                        recording_id: recording_id.clone(),
                        sequence_id: phalanx_proto::evidence::StorageSequence(1),
                        reply_to: probe_tx,
                    })
                    .await;
                if let Ok(Some(env)) = probe_rx.await {
                    let kind = match &env.evidence {
                        phalanx_proto::evidence::Evidence::Video(v) => match &v.payload {
                            phalanx_proto::evidence::DataPayload::Missing => "Missing",
                            phalanx_proto::evidence::DataPayload::Clear(_) => "Clear",
                            phalanx_proto::evidence::DataPayload::Compressed(_) => "Compressed",
                            phalanx_proto::evidence::DataPayload::Encrypted { .. } => "Encrypted",
                        },
                        _ => "non-video",
                    };
                    tracing::info!(
                        target: "phalanx::playback",
                        recording = %recording_id.as_str(),
                        payload = kind,
                        "playback start: shard 1 payload type"
                    );
                }
            }

            let mut coordinator = PlaybackCoordinator::new(
                storage_tx,
                egress_tx,
                decryption_key,
                video_sink,
                audio_sink,
                discovery_tx,
                providers_rx,
                identity,
            );
            if let Err(e) = coordinator.run(recording_id).await {
                tracing::error!("Playback Coordinator terminated with error: {:?}", e);
            }
        });

        self.playback_slot = Some(jh);
        Ok(())
    }

    /// Spawn a manifest-walk recovery session. Mirrors `spawn_playback`'s
    /// channel-replacement pattern: replacing `providers_tx` drops the old
    /// sender, so the previous recovery / playback session's `providers_rx`
    /// observes its channel close. This enforces the single-tenant
    /// `providers_rx` invariant — the FFI layer adds symmetric gates so
    /// recovery / playback / capture cannot be started concurrently.
    ///
    /// Status updates land on the shared `Arc<Mutex<RecoveryStatus>>` —
    /// the FFI's `phalanx_recovery_status` reads a snapshot from this
    /// same mutex.
    pub fn spawn_recovery(
        &mut self,
        status: Arc<Mutex<phalanx_proto::recovery::RecoveryStatus>>,
        cancel_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> JoinHandle<()> {
        let (providers_tx, providers_rx) = mpsc::channel(PROVIDERS_CHANNEL_BUFFER);
        self.providers_tx = providers_tx;

        let ctx = RecoveryContext {
            identity: self.identity.clone(),
            storage_tx: self.storage_tx.clone(),
            egress_tx: self.egress_tx.clone(),
            providers_rx,
            status,
        };

        tokio::spawn(run_recovery(ctx, cancel_rx))
    }

    // ── Transport balance (orchestrator-side; passed to EclipseRouter on TryAdmit) ─

    /// Derive dynamic transport balance from existing SystemGovernor signals.
    /// Computed on the router side because it reads MeshSentinel-side `local_mesh`;
    /// the result is passed to EclipseRouter via the `TryAdmit` command payload.
    fn compute_transport_balance(&self) -> TransportBalance {
        if self.local_mesh.is_none() {
            return TransportBalance::new(0.1); // Minimum — no local mesh hardware
        }
        if !self.system_governor.internet_available() {
            return TransportBalance::new(0.4); // Shift toward local mesh when internet is down
        }
        TransportBalance::DEFAULT // 0.25 when both transports healthy
    }
}
