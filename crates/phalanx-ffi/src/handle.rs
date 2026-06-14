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
use phalanx_node::actors::meshsentinel::{SentinelCommand, SentinelDependencies};
use phalanx_node::actors::storage::StorageCommand;
use phalanx_node::actors::trust_actor::TrustCommand;
use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::network::orchestrator::setup_transport;
use phalanx_node::persistence::vault::{derive_vault_key, load_or_create_vault_salt};
use phalanx_node::trust::TrustRegistry;
use phalanx_node::vitals::{HomeostaticConfig, SystemGovernor, ThermalThresholds};
use phalanx_node::{EngineLifecycle, FileJournal, UnspawnedEngine};
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::{AudioShard, ForensicMetrics, PrnuPosterior, VideoShard};
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::PhalanxIdentity;
use phalanx_proto::recovery::RecoveryStatus;
use phalanx_transport::adapters::local_mesh::{LocalMeshAdapter, OutboundLocalPacket};
use phalanx_transport::prelude::Libp2pIngress;
use std::time::Duration;

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
/// Transitions: `Booting → Running → Stopped`. The variant *holds* the
/// engine state for its phase, so linear ownership is enforced by the
/// type system:
/// - `Booting` owns the bootstrapped-but-not-running engine (an
///   `UnspawnedEngine`). The only way to start the run loop is to
///   `mem::replace` this variant and consume the inner value.
/// - `Running` owns the `EngineLifecycle`. The only way to stop is to
///   `mem::replace` and call the consume-by-value `shutdown(self, …)`.
/// - `Stopped` is terminal — no engine state, no further transitions.
///
/// `MeshSentinel` is never stored in a shared cell (no `Arc<Mutex<…>>`).
/// The structural impossibility of locking it from FFI is what makes the
/// H1/H2/H3 deadlock class unrepresentable in this codebase.
pub(crate) enum HandleState {
    /// Engine has been bootstrapped but the run loop is not yet spawned.
    /// `phalanx_start` consumes the inner `UnspawnedEngine`. `Box`ed to
    /// keep the enum variant sizes balanced — `UnspawnedEngine` is a
    /// fairly large struct and Stopped is empty.
    Booting {
        unspawned: Box<UnspawnedEngine<Libp2pIngress>>,
    },
    /// Engine run loop is running. `phalanx_stop` consumes the inner
    /// `EngineLifecycle` to drive a graceful shutdown.
    Running { lifecycle: EngineLifecycle },
    /// Terminal — only `phalanx_destroy` is valid from here.
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
    /// SentinelCommand channel — operations that require `&mut MeshSentinel`
    /// (start/stop recording, spawn recovery). The engine's `select!` arm
    /// services these inside its own context, so FFI never needs to lock
    /// the sentinel itself. This is the structural replacement for the
    /// deadlock-prone `sentinel_ref.lock().await` pattern that the audit
    /// found in `ble_auth`, `community::set_recording_state`, and
    /// `recovery::start_recovery`.
    pub(crate) sentinel_cmd_tx: mpsc::Sender<SentinelCommand>,
    /// Content key broadcast — per-recording encryption key for MediaEgressActor.
    pub(crate) content_key_tx: tokio::sync::watch::Sender<Option<SymmetricKey>>,
    /// Video shard sender — FFI pushes processed frames here.
    pub(crate) video_tx: Option<mpsc::Sender<VideoShard>>,
    /// Audio shard sender — FFI pushes PCM audio here.
    pub(crate) audio_tx: Option<mpsc::Sender<AudioShard>>,
    /// Node DID — immutable after creation.
    pub(crate) node_did: String,
    /// Whether a recording is currently active. This is an `Arc` clone of
    /// the *engine's* recording flag — owned by `RecordingSessionState`
    /// and flipped only by `start_recording` / `stop_recording` running
    /// inside the engine's `select!` arm. The FFI is a reader; writes go
    /// through `SentinelCommand::SetRecordingState`, so there is exactly
    /// one writer and no possibility of FFI/engine desync.
    pub(crate) recording_active: Arc<AtomicBool>,
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
    /// Polled snapshot of the in-progress recovery walk. The orchestrator
    /// (`run_recovery` in phalanx-node) updates this at every stage
    /// transition and on every poll iteration; the FFI's
    /// `phalanx_recovery_status` reads a clone.
    pub(crate) recovery_status: Arc<Mutex<RecoveryStatus>>,
    /// Cancel signal for the current recovery. `Some` while a recovery is
    /// running; `None` otherwise. `phalanx_cancel_recovery` `take()`s and
    /// fires it (idempotent: a second call is a no-op).
    pub(crate) recovery_cancel: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    /// Join handle for the current recovery task. Held so a fresh
    /// `phalanx_start_recovery` after a clean exit can drop the prior
    /// handle without leaking. Aborted on FFI shutdown via `Drop` of the
    /// runtime.
    pub(crate) recovery_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

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
    crate::panic_safety::ffi_panic_safe(std::ptr::null_mut(), || {
        // SAFETY: caller upholds the # Safety contract on the parent
        // `unsafe extern "C" fn`. The body is wrapped in the panic
        // boundary because bootstrap touches many third-party crates
        // (identity, vault, libp2p, postcard) whose panic safety on
        // corrupt persisted data isn't audited.
        unsafe {
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

            // Optional config path — use the default profile if null. A
            // non-null but unparseable/incoherent config is a loud failure
            // (null handle), not a silent fall back to defaults.
            let config = if config_path.is_null() {
                NodeConfig::default()
            } else {
                match CStr::from_ptr(config_path).to_str() {
                    Ok(path) => match NodeConfig::load(path) {
                        Ok(validated) => validated.into_inner(),
                        Err(e) => {
                            tracing::warn!(
                                target: "phalanx::ffi",
                                config_path = %path,
                                error = %e,
                                "NodeConfig::load failed; refusing to start on a silent default"
                            );
                            return std::ptr::null_mut();
                        }
                    },
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

                    // Write genesis phrase to out-param if a new identity was created.
                    // BIP39 mnemonics are ASCII space-separated words, so CString::new
                    // realistically cannot reject one for an interior NUL — but log
                    // the impossible path so the failure isn't silent if invariants
                    // ever change.
                    if let Some(phrase) = genesis_phrase {
                        if !out_genesis_phrase.is_null() {
                            match CString::new(phrase) {
                                Ok(cstr) => *out_genesis_phrase = cstr.into_raw(),
                                Err(_) => tracing::warn!(
                                    target: "phalanx::ffi",
                                    "BIP39 genesis phrase contained an interior NUL; dropping (unreachable path)"
                                ),
                            }
                        }
                    }

                    Box::into_raw(Box::new(handle))
                }
                Err(_) => std::ptr::null_mut(),
            }
        }
    })
}

/// Restore an identity from an existing BIP-39 mnemonic phrase and bootstrap
/// the engine. Symmetric with `phalanx_create` except the identity is derived
/// from the user-provided phrase rather than freshly generated. Fails with a
/// non-null handle only on success.
///
/// Returns `null` on any failure. Specific error semantics:
/// - If `storage_path` already contains an `identity.bin`, fails (no handle
///   returned). Caller must surface this to the user, confirm, delete the
///   existing identity, and retry. We deliberately do not auto-overwrite —
///   silently destroying an on-device identity is a destructive operation
///   even when the BIP-39 phrase recovers the same keys.
/// - If `mnemonic_phrase` fails to parse against any of the 10 BIP-39
///   wordlists, fails (no handle returned).
/// - Any post-identity bootstrap failure (vault, transport, etc.) also
///   produces a null handle; partial state on disk is bounded by the
///   transactional `save_to_disk_atomic` step.
///
/// By design, the FFI surfaces only a null handle on failure rather than a
/// richer status code: the Flutter side calls `phalanx_validate_mnemonic`
/// first to pre-screen the phrase, leaving the remaining null causes as
/// "boot failed" from the user's perspective. This is intentional — a
/// per-cause restore-status API would be added here only if product needs
/// justify distinguishing the residual failure modes.
///
/// # Safety
/// * `config_path` may be null (use defaults) or a valid null-terminated C
///   string.
/// * `storage_path`, `passphrase`, and `mnemonic_phrase` must be valid
///   null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn phalanx_restore(
    config_path: *const c_char,
    storage_path: *const c_char,
    passphrase: *const c_char,
    mnemonic_phrase: *const c_char,
) -> *mut PhalanxHandle {
    crate::panic_safety::ffi_panic_safe(std::ptr::null_mut(), || {
        // SAFETY: caller upholds the # Safety contract on the parent
        // `unsafe extern "C" fn`. Wrapped in the panic boundary for the
        // same reasons as `phalanx_create`.
        unsafe {
            if storage_path.is_null() || passphrase.is_null() || mnemonic_phrase.is_null() {
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
            let mnemonic_str = match CStr::from_ptr(mnemonic_phrase).to_str() {
                Ok(s) => s,
                Err(_) => return std::ptr::null_mut(),
            };

            let config = if config_path.is_null() {
                NodeConfig::default()
            } else {
                match CStr::from_ptr(config_path).to_str() {
                    Ok(path) => match NodeConfig::load(path) {
                        Ok(validated) => validated.into_inner(),
                        Err(e) => {
                            tracing::warn!(
                                target: "phalanx::ffi",
                                config_path = %path,
                                error = %e,
                                "NodeConfig::load failed; refusing to start on a silent default"
                            );
                            return std::ptr::null_mut();
                        }
                    },
                    Err(_) => return std::ptr::null_mut(),
                }
            };

            let runtime = match Runtime::new() {
                Ok(rt) => rt,
                Err(_) => return std::ptr::null_mut(),
            };

            let handle_result = runtime.block_on(async {
                restore_bootstrap(config, storage_str, passphrase_str, mnemonic_str).await
            });

            match handle_result {
                Ok(mut handle) => {
                    handle.runtime = runtime;
                    Box::into_raw(Box::new(handle))
                }
                Err(_) => std::ptr::null_mut(),
            }
        }
    })
}

/// Diagnostic: write boot log to a file since stderr doesn't reach logcat
/// on Android. Caller passes `storage_path`; the closure appends to
/// `<storage_path>/boot.log`.
fn make_boot_logger(storage_path: &str) -> impl Fn(&str) {
    let log_path = Path::new(storage_path).join("boot.log");
    move |msg: &str| {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            let _ = writeln!(f, "{msg}");
        }
    }
}

/// Internal async bootstrap — mirrors `sentinel.rs` dependency graph.
/// Returns `(PhalanxHandle, Option<String>)` where the String is the BIP39
/// mnemonic phrase when a new identity was generated (genesis). `None` when
/// loading an existing identity from disk.
async fn bootstrap(
    config: NodeConfig,
    storage_path: &str,
    passphrase: &str,
) -> Result<(PhalanxHandle, Option<String>), PhalanxError> {
    let log = make_boot_logger(storage_path);

    // Identity
    log(&format!("storage_path={storage_path}"));
    let identity_path = Path::new(storage_path).join("identity.bin");
    let (identity, genesis_phrase) =
        PhalanxIdentity::init(&identity_path, passphrase).map_err(|e| {
            log(&format!("identity init failed: {e:?}"));
            PhalanxError::BootFailed
        })?;

    let handle = bootstrap_with_identity(config, storage_path, identity).await?;
    Ok((handle, genesis_phrase))
}

/// Restore-from-phrase bootstrap. Derives the identity from `mnemonic_phrase`
/// (BIP-39, any of 10 supported wordlists), persists it transactionally,
/// then runs the same post-identity bootstrap as the generate path.
///
/// Fails with `PhalanxError::IdentityAlreadyExists` if `identity.bin` is
/// already present at `storage_path` — the caller (UI) must explicitly
/// confirm and delete the existing on-disk identity before retrying.
async fn restore_bootstrap(
    config: NodeConfig,
    storage_path: &str,
    passphrase: &str,
    mnemonic_phrase: &str,
) -> Result<PhalanxHandle, PhalanxError> {
    let log = make_boot_logger(storage_path);

    log(&format!("restore: storage_path={storage_path}"));
    let identity_path = Path::new(storage_path).join("identity.bin");

    if identity_path.exists() {
        log("restore: identity.bin already exists; refusing");
        return Err(PhalanxError::IdentityAlreadyExists);
    }

    let identity = PhalanxIdentity::restore(mnemonic_phrase).map_err(|e| {
        log(&format!("restore: derive identity failed: {e:?}"));
        PhalanxError::MnemonicParseError
    })?;
    log(&format!(
        "restore: derived identity {}",
        identity.did.as_str()
    ));

    identity
        .save_to_disk_atomic(&identity_path, passphrase)
        .map_err(|e| {
            log(&format!("restore: atomic save failed: {e:?}"));
            PhalanxError::BootFailed
        })?;
    log("restore: identity persisted atomically");

    bootstrap_with_identity(config, storage_path, identity).await
}

/// Post-identity portion of the bootstrap sequence. Identical between the
/// generate path (`phalanx_create`) and the restore path (`phalanx_restore`);
/// extracted so the two callers don't duplicate ~200 lines of orchestrator
/// wiring.
async fn bootstrap_with_identity(
    mut config: NodeConfig,
    storage_path: &str,
    identity: PhalanxIdentity,
) -> Result<PhalanxHandle, PhalanxError> {
    // Install the Android tracing subscriber before any bootstrap work runs.
    crate::observability::init_android_observability();

    // Override vault_path to match the mobile storage directory.
    // The default config points to ./sim_vault which doesn't exist on Android.
    let vault_dir = Path::new(storage_path).join("vault");
    config.storage.vault_path = vault_dir.to_string_lossy().into_owned();
    let log = make_boot_logger(storage_path);

    let node_did = identity.did.as_str().to_string();
    log(&format!("identity OK: {node_did}"));

    // Vault
    let vault_path = Path::new(storage_path).join("vault");
    let vault_str = vault_path.to_str().ok_or(PhalanxError::BootFailed)?;
    let vault_salt = load_or_create_vault_salt(vault_str).await.map_err(|e| {
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

    // Mobile hardware probe (atomics-based). Constructed with RAM=0 (reference
    // device fallback); Flutter sets the real value once after create via
    // `phalanx_update_device_ram`, avoiding an ABI change to the create call.
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
        )
        .with_queue_depth(egress.outbound_queue_depth()),
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
    // local_mesh_address: production binds the libp2p PeerId base58 form
    // so heartbeats' claimed `sender` matches `propagation_source` on
    // receive. See the field doc on SentinelDependencies for why mixing
    // encodings silently breaks every heartbeat.
    let local_mesh_address = phalanx_transport::identity_ext::Libp2pExt::to_mesh_address(&identity);
    let dek_master = identity.dek_master.clone();
    let deps = SentinelDependencies {
        config,
        identity,
        ingress,
        egress,
        journal,
        trust_registry,
        system_governor: governor.clone(),
        vault_key,
        dek_master,
        local_mesh: Some(Box::new(local_mesh_adapter)),
        prnu_posterior: prnu_posterior.clone(),
        extra_community_ids: Vec::new(),
        local_mesh_address,
    };

    // Build the engine via the public façade. `UnspawnedEngine` wraps the
    // MeshSentinel privately — no `Arc<Mutex<MeshSentinel>>` is constructed
    // anywhere on the FFI side, so the H1/H2/H3 deadlock pattern (FFI
    // awaiting sentinel.lock() while engine.run() owns the borrow for life)
    // is unrepresentable. The structural property is what the audit-driven
    // refactor demands.
    let unspawned = UnspawnedEngine::build(deps)
        .await
        .map_err(|_| PhalanxError::BootFailed)?;

    // Clone channels from the unspawned engine. The actor tasks inside
    // MeshSentinel are spawned during `build`, so these channels are
    // already alive — no need to wait for `phalanx_start`. The handle
    // retains its own clones so FFI calls (e.g. signing flows that don't
    // need the orchestrator) work between create and start.
    let trust_tx = unspawned.trust_tx();
    let storage_tx = unspawned.storage_tx();
    let egress_tx = unspawned.egress_tx();
    let sentinel_cmd_tx = unspawned.sentinel_cmd_tx();
    let content_key_tx = unspawned.content_key_tx();
    let video_tx = Some(unspawned.video_tx());
    let audio_tx = Some(unspawned.audio_tx());
    // Single source of truth for "is a recording active" — owned by the
    // engine's RecordingSessionState, shared into the handle as an Arc.
    let recording_active = unspawned.recording_active();

    // Create a dummy runtime — will be replaced by the caller. This is the
    // same trick the old bootstrap used; we keep it to avoid restructuring
    // the create/start handoff. The dummy never runs anything.
    let dummy_rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|_| PhalanxError::BootFailed)?;

    Ok(PhalanxHandle {
        runtime: dummy_rt,
        state: Mutex::new(HandleState::Booting {
            unspawned: Box::new(unspawned),
        }),
        governor,
        probe,
        trust_tx,
        storage_tx,
        egress_tx,
        sentinel_cmd_tx,
        content_key_tx,
        video_tx,
        audio_tx,
        node_did,
        recording_active,
        local_mesh_tx: Some(local_mesh_tx),
        local_mesh_outbound_rx: Mutex::new(Some(local_mesh_outbound_rx)),
        local_mesh_available,
        vault_key: handle_vault_key,
        identity: handle_identity,
        calibration_metrics: Mutex::new(None),
        prnu_posterior,
        recovery_status: Arc::new(Mutex::new(RecoveryStatus::default())),
        recovery_cancel: Mutex::new(None),
        recovery_handle: Mutex::new(None),
    })
}

/// Starts the engine's main run loop on a background tokio task.
///
/// Transitions: `Booting → Running`. Consumes the `UnspawnedEngine` stored
/// in `HandleState::Booting` by `mem::replace`-ing the variant and calling
/// `unspawned.spawn(&runtime)`. The returned `EngineLifecycle` is stored
/// in the new `HandleState::Running` variant; `phalanx_stop` consumes it.
/// The companion `EngineHandle` is discarded — the FFI's flat channel
/// fields already carry equivalent clones from bootstrap time.
///
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

    // Extract the UnspawnedEngine by `mem::replace`-ing the Booting
    // variant with a temporary Stopped placeholder. The replace is sound:
    // if anything below fails we restore the prior state.
    let unspawned = match std::mem::replace(&mut *state, HandleState::Stopped) {
        HandleState::Booting { unspawned } => unspawned,
        prior @ HandleState::Running { .. } => {
            *state = prior;
            return PhalanxError::AlreadyRunning.code();
        }
        HandleState::Stopped => return PhalanxError::InvalidState.code(),
    };

    // Spawn the run loop. `UnspawnedEngine::spawn` consumes by value and
    // moves the sentinel into the tokio task — no shared reference, no
    // way for any other code to ever lock the sentinel.
    let (_engine_handle, lifecycle) = (*unspawned).spawn(&h.runtime);
    *state = HandleState::Running { lifecycle };

    PhalanxError::Ok.code()
}

/// Stops the engine gracefully by consuming the `EngineLifecycle` and
/// awaiting its bounded-deadline shutdown.
///
/// Transitions: `Running → Stopped`. The lifecycle's `shutdown(self, …)`
/// signature enforces single-shot semantics at the type level; the
/// borrow checker forbids calling it twice.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
#[no_mangle]
pub unsafe extern "C" fn phalanx_stop(handle: *mut PhalanxHandle) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    // Extract the lifecycle (mem::replace to keep the lock guard short),
    // then drop the guard before doing async work via block_on.
    let lifecycle = {
        let Ok(mut state) = h.state.lock() else {
            return PhalanxError::InvalidState.code();
        };
        match std::mem::replace(&mut *state, HandleState::Stopped) {
            HandleState::Running { lifecycle } => lifecycle,
            prior @ (HandleState::Booting { .. } | HandleState::Stopped) => {
                *state = prior;
                return PhalanxError::NotRunning.code();
            }
        }
    };

    // Drive shutdown with a 10s drain deadline. Matches the deadline
    // `MeshSentinel::shutdown()` already uses internally so the worst-case
    // is bounded across both layers.
    match h
        .runtime
        .block_on(lifecycle.shutdown(Duration::from_secs(10)))
    {
        Ok(()) => PhalanxError::Ok.code(),
        Err(e) => {
            tracing::warn!(
                target: "phalanx::ffi",
                error = %e,
                "engine shutdown did not complete cleanly"
            );
            // Still return Ok — state is already Stopped; the run-loop
            // task is either gone or will be cancelled by the runtime
            // when `phalanx_destroy` drops it.
            PhalanxError::Ok.code()
        }
    }
}

/// Destroys the handle and frees all resources.
///
/// If the engine is still `Running`, first invokes the equivalent of
/// `phalanx_stop` so the run-loop task drains within its 10-second
/// deadline. Skipping that drain (the old destroy-without-stop path)
/// would cancel in-flight shard writes when the runtime drops. Subsumes
/// audit finding M2 — the safe path is now the default, not opt-in.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * Must be called exactly once per handle.
/// * Null is a safe no-op.
#[no_mangle]
pub unsafe extern "C" fn phalanx_destroy(handle: *mut PhalanxHandle) {
    if !handle.is_null() {
        // If the engine is still Running, drive shutdown first. Ignore
        // the return code — destroy proceeds regardless, and the runtime
        // drop below will force-cancel anything stragglers left over.
        let _ = phalanx_stop(handle);
        // Reconstruct the Box so Rust drops everything in order:
        // runtime drop → cancels any remaining spawned tasks → channels close → actors stop
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
