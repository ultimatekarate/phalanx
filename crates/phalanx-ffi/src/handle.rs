// crates/phalanx-ffi/src/handle.rs
//
// PhalanxHandle: The opaque state machine exposed across the C-ABI boundary.
//
// This is the Larynx — the vocal cords through which the linguistic model speaks.
// It mirrors the bootstrap sequence in `sentinel.rs` (config → identity → vault →
// trust → swarm → bridge → sentinel) but wraps it in a lifecycle state machine
// suitable for mobile: create → start → (operate) → stop → destroy.
//
// All Rust complexity is behind this single opaque pointer. Flutter sees only
// `PhalanxHandle*` and a flat set of `extern "C"` functions.

use crate::error::PhalanxError;
use crate::probe::MobileProbe;

use phalanx_forensics::PeerEvaluator;
use phalanx_node::actors::egress::EgressCommand;
use phalanx_node::actors::meshsentinel::SentinelDependencies;
use phalanx_node::actors::storage::StorageCommand;
use phalanx_node::actors::trust_actor::TrustCommand;
use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::network::orchestrator::setup_transport;
use phalanx_node::persistence::vault::{derive_vault_key, load_or_create_vault_salt};
use phalanx_node::trust::TrustRegistry;
use phalanx_node::vitals::{HomeostaticConfig, SystemGovernor, ThermalThresholds};
use phalanx_node::{FileJournal, MeshSentinel};
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::{AudioShard, ForensicMetrics, PrnuPosterior, VideoShard};
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::PhalanxIdentity;
use phalanx_transport::adapters::local_mesh::{LocalMeshAdapter, OutboundLocalPacket};
use phalanx_transport::prelude::Libp2pIngress;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use tokio::runtime::Runtime;
use tokio::sync::mpsc;

// =====================================================================
// HANDLE STATE MACHINE
// =====================================================================

/// Lifecycle states of the Phalanx engine.
///
/// Transitions: `Booting → Running → Stopped`
/// Invalid: `Running → Booting`, `Stopped → Running`
pub(crate) enum HandleState {
    /// Engine is being initialized. No operations permitted.
    Booting,
    /// Engine is running. All operations permitted.
    Running {
        /// Send to initiate graceful shutdown.
        _shutdown_tx: tokio::sync::oneshot::Sender<()>,
    },
    /// Engine has been stopped. Only `phalanx_destroy` is valid.
    Stopped,
}

/// The opaque handle type exposed to C/Dart.
///
/// This is the single point of contact between Rust and the outside world.
/// All fields are behind synchronization primitives suitable for concurrent
/// FFI access from arbitrary Dart isolates.
pub struct PhalanxHandle {
    /// Tokio runtime — owns all async tasks.
    pub(crate) runtime: Runtime,
    /// Lifecycle state.
    pub(crate) state: Mutex<HandleState>,
    /// Homeostatic governor — query API for power state, stress, etc.
    pub(crate) governor: Arc<SystemGovernor>,
    /// Atomics-based hardware probe for mobile sensor data.
    pub(crate) probe: Arc<MobileProbe>,
    /// Trust command channel — dispatch trust operations to the TrustActor.
    pub(crate) trust_tx: mpsc::Sender<TrustCommand>,
    /// Storage command channel — recording start/stop, export requests.
    pub(crate) storage_tx: mpsc::Sender<StorageCommand>,
    /// Egress command channel — DHT provider lookups, mesh distribution.
    pub(crate) egress_tx: mpsc::Sender<EgressCommand>,
    /// Content key broadcast — per-recording encryption key for MediaEgressActor.
    pub(crate) content_key_tx: tokio::sync::watch::Sender<Option<SymmetricKey>>,
    /// Video shard sender — FFI pushes processed frames here.
    pub(crate) video_tx: Option<mpsc::Sender<VideoShard>>,
    /// Audio shard sender — FFI pushes PCM audio here.
    pub(crate) audio_tx: Option<mpsc::Sender<AudioShard>>,
    /// The sentinel itself, behind a Mutex for `spawn_playback(&mut self)`.
    /// This is the only Mutex on PhalanxHandle — justified by genuine
    /// cross-thread access (FFI thread + h.runtime.spawn() tasks).
    pub(crate) sentinel: Mutex<Option<SentinelRef>>,
    /// Node DID — immutable after creation.
    pub(crate) node_did: String,
    /// Whether a recording is currently active.
    pub(crate) recording_active: AtomicBool,
    /// Local mesh inbound sender — FFI push functions send NetworkEvents here.
    pub(crate) local_mesh_tx: Option<mpsc::Sender<NetworkEvent>>,
    /// Local mesh outbound receiver — Flutter polls outbound packets from here.
    pub(crate) local_mesh_outbound_rx: Mutex<Option<mpsc::Receiver<OutboundLocalPacket>>>,
    /// Local mesh availability flag — shared with LocalMeshAdapter.
    pub(crate) local_mesh_available: Arc<AtomicBool>,
    /// Vault key — retained for export decryption. The key also lives inside
    /// MeshSentinel's actors (Guardian, MediaEgressActor), but those are behind
    /// the actor boundary and inaccessible from FFI. This clone allows the
    /// export path to decrypt shards directly. ZeroizeOnDrop ensures cleanup.
    pub(crate) vault_key: Arc<SymmetricKey>,
    /// Node identity — retained for C2PA signing with the node's real DID.
    /// The ephemeral signer pattern (random key per export) was defeated by
    /// red team review — provenance requires the actual node identity.
    pub(crate) identity: Arc<PhalanxIdentity>,
    /// PRNU calibration frame buffer. `Some` = calibration in progress,
    /// `None` = idle. Capped at `MAX_CALIBRATION_FRAMES` to prevent
    /// unbounded allocation from rogue FFI calls.
    pub(crate) calibration_metrics: Mutex<Option<Vec<ForensicMetrics>>>,
    /// Bayesian PRNU posterior — shared with MediaEgressActor via Arc.
    /// Updated on every video frame (capture path), read by the egress gate.
    /// 44 bytes of payload; lock held for nanoseconds (6 f64 additions).
    pub(crate) prnu_posterior: Arc<Mutex<PrnuPosterior>>,
}

/// Type-erased reference to the running MeshSentinel.
/// We need this to call `spawn_playback()`.
type SentinelRef = Arc<tokio::sync::Mutex<MeshSentinel<Libp2pIngress>>>;

// =====================================================================
// FFI LIFECYCLE FUNCTIONS
// =====================================================================

/// Creates a new PhalanxHandle by bootstrapping the full engine stack.
///
/// Mirrors `sentinel.rs` lines 24-91:
/// config → identity → vault → trust → probe → swarm → bridge → sentinel
///
/// Returns `null` on any failure. Rust's `Drop` semantics clean up partial state.
///
/// # Safety
/// * `config_path` must be a valid null-terminated C string, or null for defaults.
/// * `storage_path` must be a valid null-terminated C string pointing to writable storage.
/// * `passphrase` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn phalanx_create(
    config_path: *const c_char,
    storage_path: *const c_char,
    passphrase: *const c_char,
    out_genesis_phrase: *mut *mut c_char,
) -> *mut PhalanxHandle {
    // Initialize out-param to null (no genesis phrase by default)
    if !out_genesis_phrase.is_null() {
        *out_genesis_phrase = std::ptr::null_mut();
    }

    // Validate required parameters
    if storage_path.is_null() || passphrase.is_null() {
        return std::ptr::null_mut();
    }

    let storage_str = match CStr::from_ptr(storage_path).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let passphrase_str = match CStr::from_ptr(passphrase).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    // Optional config path — use defaults if null
    let config = if config_path.is_null() {
        NodeConfig::default()
    } else {
        match CStr::from_ptr(config_path).to_str() {
            Ok(path) => NodeConfig::load(path).unwrap_or_default(),
            Err(_) => return std::ptr::null_mut(),
        }
    };

    // Build tokio runtime
    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return std::ptr::null_mut(),
    };

    // Run the async bootstrap sequence on the runtime.
    // Each step returns Result — on failure, prior resources drop naturally.
    let handle_result =
        runtime.block_on(async { bootstrap(config, storage_str, passphrase_str).await });

    match handle_result {
        Ok((mut handle, genesis_phrase)) => {
            // Move the runtime into the handle (it was created outside the async block)
            handle.runtime = runtime;

            // Write genesis phrase to out-param if a new identity was created
            if let Some(phrase) = genesis_phrase {
                if !out_genesis_phrase.is_null() {
                    if let Ok(cstr) = CString::new(phrase) {
                        *out_genesis_phrase = cstr.into_raw();
                    }
                }
            }

            Box::into_raw(Box::new(handle))
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Internal async bootstrap — mirrors `sentinel.rs` dependency graph.
/// Returns `(PhalanxHandle, Option<String>)` where the String is the BIP39
/// mnemonic phrase when a new identity was generated (genesis). `None` when
/// loading an existing identity from disk.
async fn bootstrap(
    mut config: NodeConfig,
    storage_path: &str,
    passphrase: &str,
) -> Result<(PhalanxHandle, Option<String>), PhalanxError> {
    // Override vault_path to match the mobile storage directory.
    // The default config points to ./sim_vault which doesn't exist on Android.
    let vault_dir = Path::new(storage_path).join("vault");
    config.storage.vault_path = vault_dir.to_string_lossy().into_owned();
    // Diagnostic: write boot log to a file since stderr doesn't reach logcat
    let log = |msg: &str| {
        let log_path = Path::new(storage_path).join("boot.log");
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            let _ = writeln!(f, "{msg}");
        }
    };

    // Identity
    log(&format!("storage_path={storage_path}"));
    let identity_path = Path::new(storage_path).join("identity.bin");
    let (identity, genesis_phrase) =
        PhalanxIdentity::init(&identity_path, passphrase).map_err(|e| {
            log(&format!("identity init failed: {e:?}"));
            PhalanxError::BootFailed
        })?;

    let node_did = identity.did.as_str().to_string();
    log(&format!("identity OK: {node_did}"));

    // Vault
    let vault_path = Path::new(storage_path).join("vault");
    let vault_str = vault_path.to_str().ok_or(PhalanxError::BootFailed)?;
    let vault_salt = load_or_create_vault_salt(vault_str).map_err(|e| {
        log(&format!("vault salt failed: {e:?}"));
        PhalanxError::BootFailed
    })?;
    let vault_key = derive_vault_key(&identity, &vault_salt);
    log("vault OK");

    // Load Bayesian PRNU posterior from encrypted vault (if persisted).
    // Guardian doesn't exist yet — read the file directly with the vault key.
    let prnu_posterior = {
        let posterior_path = vault_path.join("prnu_posterior.bin");
        match phalanx_node::persistence::vault::read_encrypted_file(&posterior_path, &vault_key)
            .await
        {
            Ok(bytes) => match postcard::from_bytes::<PrnuPosterior>(&bytes) {
                Ok(p) => {
                    log(&format!("PRNU posterior loaded: n={}", p.n));
                    p
                }
                Err(_) => {
                    log("PRNU posterior: corrupt data, starting uninformed");
                    PrnuPosterior::new_uninformed()
                }
            },
            Err(_) => {
                log("PRNU posterior: cold start (no persisted file)");
                PrnuPosterior::new_uninformed()
            }
        }
    };
    let prnu_posterior = Arc::new(Mutex::new(prnu_posterior));

    // Journal (WAL)
    let wal_path = Path::new(storage_path).join("sentinel_transient_wal.bin");
    let wal_str = wal_path.to_str().ok_or(PhalanxError::BootFailed)?;
    let journal = FileJournal::new(wal_str, vault_key.clone())
        .await
        .map_err(|e| {
            log(&format!("journal failed: {e:?}"));
            PhalanxError::BootFailed
        })?;
    log("journal OK");

    // Trust
    let trust_registry = TrustRegistry::build(&config).await;
    let reputation_projection = trust_registry.projection_handle();
    log("trust OK");

    // Mobile hardware probe (atomics-based).
    // RAM=0: falls back to reference device default (4GB).
    // TODO: Pass actual device RAM from Flutter via phalanx_create parameter.
    let probe = Arc::new(MobileProbe::new(ThermalThresholds::default(), 0));

    // Network
    // Ensure vault directory exists for DHT store
    let vault_for_dht = Path::new(&config.storage.vault_path);
    log(&format!(
        "vault_path for DHT: {}",
        config.storage.vault_path
    ));
    log(&format!("vault_path exists: {}", vault_for_dht.exists()));
    if !vault_for_dht.exists() {
        std::fs::create_dir_all(vault_for_dht).map_err(|e| {
            log(&format!("vault dir create failed: {e:?}"));
            PhalanxError::BootFailed
        })?;
        log("vault dir created");
    }
    let (ingress, egress) = setup_transport(
        &identity,
        &config,
        None, // PSK: None for public swarm on mobile (can be extended later)
        Arc::new(reputation_projection) as Arc<dyn PeerEvaluator>,
    )
    .map_err(|e| {
        log(&format!("transport failed: {e:?}"));
        PhalanxError::BootFailed
    })?;
    log("transport OK");

    // Wire socket-level I/O counters from the egress port into the governor
    // for Volterra integral sampling. Drops and ops are sampled together so
    // the governor can compute drops/ops as a self-normalizing ratio.
    let governor = Arc::new(
        SystemGovernor::with_probe(
            HomeostaticConfig::default(),
            probe.clone() as Arc<dyn phalanx_node::vitals::HardwareProbe>,
        )
        .with_io_counters(
            egress.socket_bytes_sent(),
            egress.socket_bytes_received(),
            egress.socket_io_ops(),
            egress.dropped_event_count(),
        ),
    );

    // Local mesh adapter — channel bridge for BLE/WiFi Direct via Flutter FFI
    let (local_mesh_adapter, local_mesh_tx, local_mesh_outbound_rx, local_mesh_available) =
        LocalMeshAdapter::new(64);

    // Retain clones for FFI export path before deps consumes the originals.
    // vault_key: needed for shard decryption during C2PA export.
    // identity: needed for C2PA signing with the node's real DID.
    let handle_vault_key = Arc::new(vault_key.clone());
    let handle_identity = Arc::new(identity.clone());

    // Build SentinelDependencies (mirrors sentinel.rs lines 74-84)
    let deps = SentinelDependencies {
        config,
        identity,
        ingress,
        egress,
        journal,
        trust_registry,
        system_governor: governor.clone(),
        vault_key,
        local_mesh: Some(Box::new(local_mesh_adapter)),
        prnu_posterior: prnu_posterior.clone(),
    };

    let engine = MeshSentinel::new(deps)
        .await
        .map_err(|_| PhalanxError::BootFailed)?;

    // Extract channels before wrapping in Arc<Mutex>.
    // These clones live on the handle so FFI calls never need to lock the sentinel.
    // The sentinel run loop holds its tokio::sync::Mutex for its entire lifetime,
    // so any FFI call that tried sentinel_ref.lock().await would deadlock.
    let trust_tx = engine.trust_tx.clone();
    let storage_tx = engine.storage_tx.clone();
    let egress_tx = engine.egress_tx.clone();
    let content_key_tx = engine.content_key_tx.clone();
    let video_tx = Some(engine.video_tx.clone());
    let audio_tx = Some(engine.audio_tx.clone());

    let sentinel = Arc::new(tokio::sync::Mutex::new(engine));

    // Create a dummy runtime — will be replaced by the caller
    let dummy_rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|_| PhalanxError::BootFailed)?;

    Ok((
        PhalanxHandle {
            runtime: dummy_rt,
            state: Mutex::new(HandleState::Booting),
            governor,
            probe,
            trust_tx,
            storage_tx,
            egress_tx,
            content_key_tx,
            video_tx,
            audio_tx,
            sentinel: Mutex::new(Some(sentinel)),
            node_did,
            recording_active: AtomicBool::new(false),
            local_mesh_tx: Some(local_mesh_tx),
            local_mesh_outbound_rx: Mutex::new(Some(local_mesh_outbound_rx)),
            local_mesh_available,
            vault_key: handle_vault_key,
            identity: handle_identity,
            calibration_metrics: Mutex::new(None),
            prnu_posterior,
        },
        genesis_phrase,
    ))
}

/// Starts the engine's main run loop on a background tokio task.
///
/// Transitions: `Booting → Running`.
/// Returns `PhalanxError::AlreadyRunning` if called twice.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
#[no_mangle]
pub unsafe extern "C" fn phalanx_start(handle: *mut PhalanxHandle) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    let Ok(mut state) = h.state.lock() else {
        return PhalanxError::InvalidState.code();
    };

    match &*state {
        HandleState::Running { .. } => return PhalanxError::AlreadyRunning.code(),
        HandleState::Stopped => return PhalanxError::InvalidState.code(),
        HandleState::Booting => {}
    }

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    // Clone the sentinel Arc for the spawned task
    let sentinel_ref = {
        let Ok(guard) = h.sentinel.lock() else {
            return PhalanxError::InvalidState.code();
        };
        match guard.as_ref() {
            Some(s) => s.clone(),
            None => return PhalanxError::InvalidState.code(),
        }
    };

    // Spawn the engine's run loop
    h.runtime.spawn(async move {
        let mut engine = sentinel_ref.lock().await;

        tokio::select! {
            result = engine.run() => {
                if let Err(e) = result {
                    tracing::error!("MeshSentinel exited with error: {}", e);
                }
            }
            _ = shutdown_rx => {
                tracing::info!("MeshSentinel shutdown signal received.");
            }
        }
    });

    *state = HandleState::Running {
        _shutdown_tx: shutdown_tx,
    };

    PhalanxError::Ok.code()
}

/// Stops the engine gracefully by dropping the shutdown oneshot sender.
///
/// Transitions: `Running → Stopped`.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
#[no_mangle]
pub unsafe extern "C" fn phalanx_stop(handle: *mut PhalanxHandle) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    let Ok(mut state) = h.state.lock() else {
        return PhalanxError::InvalidState.code();
    };

    match &*state {
        HandleState::Running { .. } => {
            // Replace with Stopped — dropping the old state drops shutdown_tx,
            // which signals the select! loop to terminate.
            *state = HandleState::Stopped;
            PhalanxError::Ok.code()
        }
        HandleState::Booting => PhalanxError::NotRunning.code(),
        HandleState::Stopped => PhalanxError::NotRunning.code(),
    }
}

/// Destroys the handle and frees all resources.
///
/// After this call, the pointer is invalid. Double-destroy is UB.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * Must be called exactly once per handle.
/// * Null is a safe no-op.
#[no_mangle]
pub unsafe extern "C" fn phalanx_destroy(handle: *mut PhalanxHandle) {
    if !handle.is_null() {
        // Reconstruct the Box so Rust drops everything in order:
        // runtime drop → cancels all spawned tasks → channels close → actors stop
        let _ = Box::from_raw(handle);
    }
}

// =====================================================================
// INTERNAL HELPERS
// =====================================================================

impl PhalanxHandle {
    /// Check if the engine is in the Running state.
    pub(crate) fn is_running(&self) -> bool {
        self.state
            .lock()
            .map(|s| matches!(&*s, HandleState::Running { .. }))
            .unwrap_or(false)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::undocumented_unsafe_blocks,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn null_handle_start_returns_error() {
        unsafe {
            assert_eq!(
                phalanx_start(std::ptr::null_mut()),
                PhalanxError::NullPointer.code()
            );
        }
    }

    #[test]
    fn null_handle_stop_returns_error() {
        unsafe {
            assert_eq!(
                phalanx_stop(std::ptr::null_mut()),
                PhalanxError::NullPointer.code()
            );
        }
    }

    #[test]
    fn destroy_null_is_noop() {
        unsafe {
            phalanx_destroy(std::ptr::null_mut());
        }
    }

    #[test]
    fn create_with_null_storage_returns_null() {
        unsafe {
            let passphrase = CString::new("test").expect("valid");
            let handle = phalanx_create(
                std::ptr::null(),
                std::ptr::null(),
                passphrase.as_ptr(),
                std::ptr::null_mut(),
            );
            assert!(handle.is_null());
        }
    }

    #[test]
    fn create_with_null_passphrase_returns_null() {
        unsafe {
            let storage = CString::new("/tmp/phalanx_test").expect("valid");
            let handle = phalanx_create(
                std::ptr::null(),
                storage.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
            );
            assert!(handle.is_null());
        }
    }

    #[test]
    fn create_with_both_null_returns_null() {
        unsafe {
            let handle = phalanx_create(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
            );
            assert!(handle.is_null());
        }
    }
}
