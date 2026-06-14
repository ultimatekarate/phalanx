use std::error::Error;
use std::sync::Arc;
use tracing::info;

// Internal Modules from Workspace
use phalanx_forensics::PeerEvaluator;
use phalanx_node::actors::meshsentinel::MeshSentinel;
use phalanx_node::actors::meshsentinel::SentinelDependencies;
use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::network::orchestrator::setup_transport;
use phalanx_node::paths::NodePaths;
use phalanx_node::persistence::vault::{derive_vault_key, load_or_create_vault_salt};
use phalanx_node::psk::load_swarm_key;
use phalanx_node::trust::TrustRegistry;
use phalanx_node::vitals::init_observability_in;
use phalanx_node::FileJournal;
use phalanx_proto::prelude::PhalanxIdentity;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Resolve the single on-disk state root (PHALANX_HOME override, else the
    // OS-correct local data dir) and create its directories BEFORE telemetry —
    // the rolling guardian.log lives under it.
    let paths = NodePaths::resolve()?;

    // Telemetry & Initialization
    init_observability_in(paths.log_dir());
    info!(data_root = %paths.base().display(), "Phalanx state directory resolved");

    // Ctrl-C wiring: the handler sends on a oneshot. `engine.run()` is raced
    // against the receiver so SIGINT unwinds back to the `shutdown().await`
    // path below instead of short-circuiting through `std::process::exit`,
    // which would skip all actor drain.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_tx = std::sync::Mutex::new(Some(shutdown_tx));
    ctrlc::set_handler(move || {
        println!("\n[PHALANX] Shutdown initiated. Sealing vault...");
        if let Ok(mut guard) = shutdown_tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.send(());
            }
        }
    })?;

    // Configuration Loading. A set-but-invalid PHALANX_CONFIG aborts here
    // (loud failure) rather than silently falling back to compiled defaults;
    // unset selects the default deployment profile (logged). The validated
    // proof token is unwrapped into the plain config the actors consume.
    let mut config = NodeConfig::load_from_env()?.into_inner();
    // Place the vault under the resolved state root unless the operator set an
    // explicit (non-dev-default) vault_path via PHALANX_CONFIG. The salt, DHT
    // store, and PRNU posterior all live under this directory.
    if config.storage.vault_path == phalanx_node::paths::DEV_DEFAULT_VAULT_PATH {
        config.storage.vault_path = paths.vault().to_string_lossy().into_owned();
    }

    // The identity passphrase is supplied via the environment for this headless
    // daemon — the correct production mechanism (e.g. a systemd EnvironmentFile
    // or a secrets manager). The node refuses to start without it.
    let identity_passphrase = std::env::var("PHALANX_IDENTITY_PASSPHRASE")
        .map_err(|_| "Security Violation: PHALANX_IDENTITY_PASSPHRASE not set")?;

    // Identity & Security Setup
    let (my_identity, _genesis_phrase) =
        PhalanxIdentity::init(paths.identity(), &identity_passphrase)?;
    let psk = load_swarm_key(&paths.swarm_key());

    if psk.is_some() {
        info!("Joining Private Swarm (Static PSK Loaded).");
    } else {
        info!("Joining Public Swarm (No PSK).");
    }

    info!("Initializing Transient WAL");
    let vault_salt = load_or_create_vault_salt(&config.storage.vault_path).await?;
    let vault_key = derive_vault_key(&my_identity, &vault_salt);
    let journal = FileJournal::new(paths.wal(), vault_key.clone()).await?;

    // --- ZERO-TRUST DEPENDENCY GRAPH ---
    // External registry for swarm's gossipsub validator.
    // MeshSentinel::new() builds its own internal registry for actor operations.
    let trust_registry = TrustRegistry::build(&config).await;
    let reputation_projection = trust_registry.projection_handle();

    // Production Network Adapter Setup (Hexagonal Port Injection)
    let (ingress, egress) = setup_transport(
        &my_identity,
        &config,
        psk,
        Arc::new(reputation_projection) as Arc<dyn PeerEvaluator>,
    )?;

    // Engine Initialization via Parameter Object.
    // Compute the local MeshAddress before moving `my_identity` into deps.
    // Production binds the libp2p PeerId base58 form so heartbeats' claimed
    // `sender` matches `propagation_source` on receive.
    let local_mesh_address =
        phalanx_transport::identity_ext::Libp2pExt::to_mesh_address(&my_identity);
    let dek_master = my_identity.dek_master.clone();
    let deps = SentinelDependencies {
        config,
        identity: my_identity,
        ingress,
        journal,
        trust_registry,
        system_governor: Arc::new(
            phalanx_node::vitals::SystemGovernor::new()
                .with_io_counters(
                    egress.socket_bytes_sent(),
                    egress.socket_bytes_received(),
                    egress.socket_io_ops(),
                    egress.dropped_event_count(),
                )
                .with_queue_depth(egress.outbound_queue_depth()),
        ),
        vault_key,
        dek_master,
        local_mesh: None, // NoOp — BLE/WiFi Direct injected during mobile integration
        egress,
        prnu_posterior: std::sync::Arc::new(std::sync::Mutex::new(
            phalanx_proto::evidence::PrnuPosterior::new_uninformed(),
        )),
        extra_community_ids: Vec::new(),
        local_mesh_address,
    };

    let mut engine = MeshSentinel::new(deps).await?;

    println!("--- PHALANX SENSOR: ONLINE (WAN + LAN) ---");

    // Race the sentinel's main loop against the ctrl-c oneshot. When the
    // ctrl-c arm wins, `engine.run()` is dropped mid-iteration — the message
    // currently being handled may be lost, which is accepted SIGINT semantics.
    // Actors still drain cleanly via `shutdown().await` below.
    let run_result: Result<(), Box<dyn Error>> = tokio::select! {
        result = engine.run() => result,
        _ = shutdown_rx => Ok(()),
    };

    // Always drain background tasks, even on run() error, so pending work
    // (including EgressActor's DrainForSalvage output) lands in the journal.
    engine.shutdown().await;

    run_result
}
