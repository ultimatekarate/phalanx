// crates/phalanx-stronghold/src/bin/stronghold.rs
//
// Stronghold CLI. Wires clap subcommands to the ops and persistence layers.
// Identity is loaded from disk (argon2-encrypted) or generated on first run.

use std::path::{Path, PathBuf};
use std::process;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use phalanx_proto::community::{Community, CommunityId};
use phalanx_proto::identity::{PhalanxIdentity, RecordingId};
use phalanx_stronghold::config::StrongholdConfig;
use phalanx_stronghold::persistence::evidence_store::EvidenceStore;
use phalanx_stronghold::persistence::proof_store::ProofStore;
use phalanx_stronghold::sentinel::StrongholdDependencies;
use phalanx_stronghold::swarm::setup_stronghold_swarm;

// ── CLI Definition ──────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "stronghold",
    about = "Phalanx Stronghold: Corroboration Server"
)]
struct Cli {
    #[arg(short, long, default_value = "stronghold.toml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Stronghold daemon (passive evidence collection).
    Run,
    /// Import a community roster from a postcard file.
    ImportCommunity {
        #[arg(short, long)]
        file: String,
    },
    /// List known communities (reads stored community files).
    Communities,
    /// List collected recordings for a community.
    Recordings {
        #[arg(short, long)]
        community: String,
    },
    /// Run the Corroboration Gate on a set of recordings.
    Corroborate {
        #[arg(short, long)]
        community: String,
        #[arg(short, long, num_args = 1..)]
        grants: Vec<String>,
        #[arg(short, long, num_args = 2..)]
        recordings: Vec<String>,
    },
    /// Export a proof and its evidence to disk.
    Export {
        #[arg(long)]
        community: String,
        #[arg(long)]
        proof: String,
        #[arg(short, long, num_args = 1..)]
        grants: Vec<String>,
        #[arg(short, long, default_value = "./export")]
        output: String,
    },
}

// ── Main ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    if let Err(e) = run(cli).await {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(&cli.config)?;
    let vault_path = PathBuf::from(&config.storage.vault_path);

    match cli.command {
        Commands::Run => {
            cmd_run(&config, &vault_path).await?;
        }
        Commands::ImportCommunity { file } => {
            cmd_import_community(&vault_path, &file).await?;
        }
        Commands::Communities => {
            cmd_list_communities(&vault_path).await?;
        }
        Commands::Recordings { community } => {
            let cid = parse_community_id(&community)?;
            cmd_list_recordings(&vault_path, &cid).await?;
        }
        Commands::Corroborate {
            community,
            grants,
            recordings,
        } => {
            let identity = load_identity(&vault_path)?;
            let cid = parse_community_id(&community)?;
            let grant_paths: Vec<PathBuf> = grants.iter().map(PathBuf::from).collect();
            let recording_ids: Vec<RecordingId> = recordings.iter().map(RecordingId::new).collect();
            cmd_corroborate(
                &identity,
                &vault_path,
                &config,
                &cid,
                &grant_paths,
                &recording_ids,
            )
            .await?;
        }
        Commands::Export {
            community,
            proof,
            grants,
            output,
        } => {
            let identity = load_identity(&vault_path)?;
            let cid = parse_community_id(&community)?;
            let proof_hash = parse_hex_hash(&proof)?;
            let grant_paths: Vec<PathBuf> = grants.iter().map(PathBuf::from).collect();
            let output_dir = PathBuf::from(&output);
            cmd_export(
                &identity,
                &vault_path,
                &config,
                &cid,
                &proof_hash,
                &grant_paths,
                &output_dir,
            )
            .await?;
        }
    }

    Ok(())
}

// ── Command Implementations ─────────────────────────────────────────────

async fn cmd_run(
    config: &StrongholdConfig,
    vault_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity = load_identity(vault_path)?;

    eprintln!("Stronghold daemon starting...");
    eprintln!("  DID: {}", identity.did);

    // Set up the mesh transport with ephemeral DHT
    let (ingress, _egress) = setup_stronghold_swarm(&identity, &config.network)?;

    // Construct stores
    let evidence_store = EvidenceStore::new(vault_path.to_path_buf());

    // Build and run the sentinel
    let deps = StrongholdDependencies {
        config: config.clone(),
        identity,
        ingress,
        evidence_store,
    };

    let mut sentinel = phalanx_stronghold::StrongholdSentinel::new(deps);

    // Shutdown handler
    ctrlc::set_handler(move || {
        eprintln!("\nStronghold: shutdown initiated...");
        std::process::exit(0);
    })
    .map_err(|e| format!("Failed to set Ctrl-C handler: {e}"))?;

    eprintln!("Stronghold daemon online — listening for shards");
    sentinel.run().await;

    Ok(())
}

async fn cmd_import_community(
    vault_path: &Path,
    file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = tokio::fs::read(file).await?;
    let community: Community = postcard::from_bytes(&bytes)
        .map_err(|e| format!("Failed to deserialize community file: {e}"))?;

    let community_id = community.fingerprint;

    // Store the community roster to disk for later use
    let communities_dir = vault_path.join("communities");
    tokio::fs::create_dir_all(&communities_dir).await?;
    let out_path = communities_dir.join(format!("{}.community.bin", hex_encode(&community_id.0)));
    tokio::fs::write(&out_path, &bytes).await?;

    println!("Imported community: {}", community.name);
    println!("  ID:      {}", hex_encode(&community_id.0));
    println!("  Members: {}", community.members.len());
    println!("  Stored:  {}", out_path.display());
    Ok(())
}

async fn cmd_list_communities(vault_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let communities_dir = vault_path.join("communities");
    if !communities_dir.exists() {
        println!("No communities imported yet.");
        return Ok(());
    }

    let mut entries = tokio::fs::read_dir(&communities_dir).await?;
    let mut count = 0u32;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("bin") {
            continue;
        }

        let bytes = tokio::fs::read(&path).await?;
        if let Ok(community) = postcard::from_bytes::<Community>(&bytes) {
            println!(
                "  {} — {} ({} members)",
                hex_encode(&community.fingerprint.0),
                community.name,
                community.members.len(),
            );
            count += 1;
        }
    }

    if count == 0 {
        println!("No communities imported yet.");
    } else {
        println!("{count} community(ies) found.");
    }
    Ok(())
}

async fn cmd_list_recordings(
    vault_path: &Path,
    community_id: &CommunityId,
) -> Result<(), Box<dyn std::error::Error>> {
    let evidence_store = EvidenceStore::new(vault_path.to_path_buf());
    let recordings = evidence_store.list_recordings(community_id).await?;

    if recordings.is_empty() {
        println!(
            "No recordings for community {}.",
            hex_encode(&community_id.0)
        );
        return Ok(());
    }

    for rid in &recordings {
        let rec = evidence_store.read_recording(community_id, rid).await?;
        let status = if rec.is_complete { "complete" } else { "gaps" };
        println!(
            "  {} — {} artifacts, {}",
            rid.as_str(),
            rec.artifacts.len(),
            status,
        );
    }

    println!("{} recording(s) found.", recordings.len());
    Ok(())
}

async fn cmd_corroborate(
    identity: &PhalanxIdentity,
    vault_path: &Path,
    config: &StrongholdConfig,
    community_id: &CommunityId,
    grant_paths: &[PathBuf],
    recording_ids: &[RecordingId],
) -> Result<(), Box<dyn std::error::Error>> {
    let evidence_store = EvidenceStore::new(vault_path.to_path_buf());
    let proof_store = ProofStore::new(vault_path.to_path_buf());

    let proof = phalanx_stronghold::ops::corroborate::run_corroboration(
        identity,
        &evidence_store,
        &proof_store,
        &config.corroboration,
        community_id,
        grant_paths,
        recording_ids,
    )
    .await
    .map_err(|e| format!("Corroboration failed: {e}"))?;

    println!("Corroboration proof produced:");
    println!("  Proof hash:    {}", hex_encode(&proof.proof_hash));
    println!("  Attestations:  {}", proof.attestations.len());
    println!("  Divergences:   {}", proof.divergences.len());
    println!("  Proximity:     {}", proof.proximity_evidence.len());
    println!("  Producer DID:  {}", proof.producer_did);
    Ok(())
}

async fn cmd_export(
    identity: &PhalanxIdentity,
    vault_path: &Path,
    config: &StrongholdConfig,
    community_id: &CommunityId,
    proof_hash: &[u8; 32],
    grant_paths: &[PathBuf],
    output_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let evidence_store = EvidenceStore::new(vault_path.to_path_buf());
    let proof_store = ProofStore::new(vault_path.to_path_buf());

    let files = phalanx_stronghold::ops::export::run_export(
        identity,
        &evidence_store,
        &proof_store,
        &config.corroboration,
        community_id,
        proof_hash,
        grant_paths,
        output_dir,
    )
    .await
    .map_err(|e| format!("Export failed: {e}"))?;

    println!(
        "Exported {} file(s) to {}:",
        files.len(),
        output_dir.display()
    );
    for f in &files {
        println!("  {}", f.display());
    }
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn load_config(path: &str) -> Result<StrongholdConfig, Box<dyn std::error::Error>> {
    if !Path::new(path).exists() {
        eprintln!("Config file {path} not found, using defaults.");
        return Ok(StrongholdConfig::default());
    }

    let text = std::fs::read_to_string(path)?;
    let config: StrongholdConfig =
        toml::from_str(&text).map_err(|e| format!("Failed to parse config {path}: {e}"))?;
    Ok(config)
}

/// Load or generate the Stronghold's identity.
///
/// Uses shared seal/unseal functions (Laboratory) for Argon2 + XChaCha20-Poly1305.
/// Handles only file IO (Hands). Passphrase from PHALANX_IDENTITY_PASSPHRASE env var.
fn load_identity(vault_path: &Path) -> Result<PhalanxIdentity, Box<dyn std::error::Error>> {
    use phalanx_forensics::cryptography::identity::{seal_identity, unseal_identity};

    let passphrase = std::env::var("PHALANX_IDENTITY_PASSPHRASE")
        .map_err(|_| "PHALANX_IDENTITY_PASSPHRASE not set. Export it before running.")?;

    let identity_path = vault_path.join("stronghold_identity.bin");

    if identity_path.exists() {
        let file_bytes = std::fs::read(&identity_path)?;
        let identity = unseal_identity(&file_bytes, &passphrase)
            .map_err(|e| format!("Failed to decrypt identity: {e}"))?;

        eprintln!("Identity loaded: {}", identity.did);
        Ok(identity)
    } else {
        let identity = PhalanxIdentity::new_ephemeral();
        let file_bytes = seal_identity(&identity, &passphrase)
            .map_err(|e| format!("Failed to encrypt identity: {e}"))?;

        std::fs::create_dir_all(vault_path)?;
        std::fs::write(&identity_path, &file_bytes)?;

        eprintln!("New identity generated: {}", identity.did);
        eprintln!("Saved to: {}", identity_path.display());
        Ok(identity)
    }
}

/// Parse a 64-char hex string into CommunityId.
fn parse_community_id(hex: &str) -> Result<CommunityId, Box<dyn std::error::Error>> {
    let bytes = parse_hex_bytes(hex)?;
    if bytes.len() != 32 {
        return Err(format!(
            "Community ID must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        )
        .into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(CommunityId(arr))
}

/// Parse a 64-char hex string into [u8; 32].
fn parse_hex_hash(hex: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = parse_hex_bytes(hex)?;
    if bytes.len() != 32 {
        return Err(format!("Hash must be 32 bytes (64 hex chars), got {}", bytes.len()).into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_hex_bytes(hex: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !hex.len().is_multiple_of(2) {
        return Err("Hex string must have even length".into());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte_str = hex.get(i..i + 2).ok_or("Invalid hex")?;
        bytes.push(u8::from_str_radix(byte_str, 16)?);
    }
    Ok(bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
