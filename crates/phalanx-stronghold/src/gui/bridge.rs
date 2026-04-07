// crates/phalanx-stronghold/src/gui/bridge.rs
//
// DaemonBridge: owns the tokio runtime and cloned handles into the
// Stronghold's actor system. Constructed on "Launch" from the startup
// panel. Dropped when eframe exits — runtime drop cancels all tasks.
//
// Hands layer — runtime wiring only.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use phalanx_forensics::cryptography::identity::{seal_identity, unseal_identity};
use phalanx_proto::community::Community;
use phalanx_proto::identity::PhalanxIdentity;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::actors::aggregation::AggregationCommand;
use crate::actors::community::CommunityCommand;
use crate::config::StrongholdConfig;
use crate::governor::StrongholdGovernor;
use crate::persistence::evidence_store::EvidenceStore;
use crate::sentinel::StrongholdDependencies;
use crate::swarm::setup_stronghold_swarm;
use crate::StrongholdSentinel;

// ── DaemonBridge ───────────────────────────────────────────────────────

pub struct DaemonBridge {
    pub runtime: tokio::runtime::Runtime,
    pub aggregation_tx: mpsc::Sender<AggregationCommand>,
    pub community_tx: mpsc::Sender<CommunityCommand>,
    pub governor: Arc<StrongholdGovernor>,
    pub identity: Arc<PhalanxIdentity>,
    pub config: Arc<StrongholdConfig>,
    pub vault_path: PathBuf,
}

impl DaemonBridge {
    /// Build the tokio runtime, load identity, set up swarm, spawn sentinel.
    /// Blocks briefly for argon2 key derivation (~500ms–2s on Pi).
    pub fn launch(passphrase: &str, config_path: &str) -> Result<Self, String> {
        // 1. Build tokio runtime
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("Failed to build tokio runtime: {e}"))?;

        // Enter runtime context so tokio::spawn in sentinel::new binds correctly
        let _guard = runtime.enter();

        // 2. Load config
        let config = load_config(config_path)?;
        let vault_path = PathBuf::from(&config.storage.vault_path);

        // 3. Load or generate identity
        let identity = load_identity(&vault_path, passphrase)?;

        // 4. Set up mesh transport (sync — ephemeral DHT, no blocking IO)
        let (ingress, _egress) = setup_stronghold_swarm(&identity, &config.network)
            .map_err(|e| format!("Failed to set up swarm: {e}"))?;

        // 5. Construct stores and sentinel dependencies
        let evidence_store = EvidenceStore::new(vault_path.clone());

        let deps = StrongholdDependencies {
            config: config.clone(),
            identity,
            ingress,
            evidence_store,
        };

        // 6. Construct sentinel — spawns actors on the runtime
        let mut sentinel = StrongholdSentinel::new(deps);

        // 7. Clone handles before moving sentinel
        let aggregation_tx = sentinel.aggregation_tx().clone();
        let community_tx = sentinel.community_tx().clone();
        let governor = sentinel.governor().clone();
        let identity = sentinel.identity().clone();
        let config = sentinel.config().clone();

        // 8. Auto-import communities from disk into the live actor
        let community_tx_clone = community_tx.clone();
        let vault_clone = vault_path.clone();
        runtime.block_on(async {
            auto_import_communities(&vault_clone, &community_tx_clone).await;
        });

        // 9. Spawn sentinel event loop
        runtime.spawn(async move {
            sentinel.run().await;
        });

        info!("DaemonBridge: Stronghold launched");

        Ok(Self {
            runtime,
            aggregation_tx,
            community_tx,
            governor,
            identity,
            config,
            vault_path,
        })
    }
}

// ── Helpers ────────────────────────────────────────────────────────────

fn load_config(path: &str) -> Result<StrongholdConfig, String> {
    if !Path::new(path).exists() {
        return Ok(StrongholdConfig::default());
    }

    let text =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read config {path}: {e}"))?;
    toml::from_str(&text).map_err(|e| format!("Failed to parse config {path}: {e}"))
}

/// Load or generate the Stronghold's identity.
/// Same pattern as the CLI binary, but takes passphrase as parameter
/// instead of reading from env var.
fn load_identity(vault_path: &Path, passphrase: &str) -> Result<PhalanxIdentity, String> {
    let identity_path = vault_path.join("stronghold_identity.bin");

    if identity_path.exists() {
        let file_bytes =
            std::fs::read(&identity_path).map_err(|e| format!("Failed to read identity: {e}"))?;
        let identity = unseal_identity(&file_bytes, passphrase)
            .map_err(|e| format!("Failed to decrypt identity: {e}"))?;

        info!(did = %identity.did, "Identity loaded");
        Ok(identity)
    } else {
        let identity = PhalanxIdentity::new_ephemeral();
        let file_bytes = seal_identity(&identity, passphrase)
            .map_err(|e| format!("Failed to encrypt identity: {e}"))?;

        std::fs::create_dir_all(vault_path)
            .map_err(|e| format!("Failed to create vault dir: {e}"))?;
        std::fs::write(&identity_path, &file_bytes)
            .map_err(|e| format!("Failed to write identity: {e}"))?;

        info!(did = %identity.did, "New identity generated");
        Ok(identity)
    }
}

/// Scan the communities directory and import each community file into
/// the live CommunityActor. This ensures the routing table is populated
/// on startup without requiring manual re-import.
async fn auto_import_communities(vault_path: &Path, community_tx: &mpsc::Sender<CommunityCommand>) {
    let communities_dir = vault_path.join("communities");
    if !communities_dir.exists() {
        return;
    }

    let mut entries = match tokio::fs::read_dir(&communities_dir).await {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, "Failed to read communities directory");
            return;
        }
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("bin") {
            continue;
        }

        let bytes = match tokio::fs::read(&path).await {
            Ok(b) => b,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to read community file");
                continue;
            }
        };

        let community: Community = match postcard::from_bytes(&bytes) {
            Ok(c) => c,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to deserialize community");
                continue;
            }
        };

        let name = community.name.to_string();
        let (tx, rx) = oneshot::channel();
        if community_tx
            .try_send(CommunityCommand::Import {
                community,
                reply_to: tx,
            })
            .is_ok()
        {
            match rx.await {
                Ok(Ok(id)) => {
                    info!(name = %name, id = ?id, "Auto-imported community");
                }
                Ok(Err(e)) => {
                    warn!(name = %name, error = %e, "Failed to import community");
                }
                Err(_) => {
                    warn!(name = %name, "Community actor did not reply");
                }
            }
        }
    }
}
