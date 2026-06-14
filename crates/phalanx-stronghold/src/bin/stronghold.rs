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

    /// Override the data root (vault, identity, proofs). Highest precedence;
    /// otherwise PHALANX_STRONGHOLD_HOME, then config `vault_path`, then the
    /// OS-correct platform data directory.
    #[arg(long)]
    data_dir: Option<String>,

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
    /// Sign a vouch for a community member using the Stronghold's identity.
    Vouch {
        /// DID of the member to vouch for.
        #[arg(long)]
        member_did: String,
        /// Hex-encoded 32-byte community fingerprint.
        #[arg(long)]
        community_id: String,
        /// Ceremony-level joined_at timestamp (milliseconds since epoch).
        #[arg(long)]
        joined_at: u64,
        /// Output file path for the serialized Vouch.
        #[arg(short, long)]
        output: String,
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
    /// Assemble a community from a collected set of vouches. Delegates all
    /// invariants (freshness, expiration bounds, quorum, QR budget) to
    /// `phalanx_forensics::identity::assemble_community`.
    CreateCommunity {
        /// Community pet name (1-64 chars).
        #[arg(long)]
        name: String,
        /// Quorum threshold — minimum distinct vouchers per member.
        #[arg(long)]
        quorum: u8,
        /// Path to the TOML file containing the collected ceremony vouches.
        #[arg(long)]
        vouches: String,
        /// Ceremony joined_at (RFC3339, e.g. 2026-04-14T17:00:00Z).
        #[arg(long)]
        joined_at: String,
        /// Community expiry (RFC3339).
        #[arg(long)]
        expires_at: String,
        /// Optional Stronghold DID (operator's own identity) to associate.
        #[arg(long)]
        stronghold_did: Option<String>,
        /// Output path for the postcard-serialized Community token.
        #[arg(short, long)]
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
    // Resolve the data root to an OS-correct, machine-local directory for the
    // shipped daemon (never the dev-relative ./stronghold-data unless the
    // operator opts in). Fails loudly if no location can be determined.
    let vault_path = phalanx_stronghold::paths::resolve_data_dir(
        &config.storage.vault_path,
        cli.data_dir.as_deref(),
    )?;
    std::fs::create_dir_all(&vault_path)?;

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
        Commands::Vouch {
            member_did,
            community_id,
            joined_at,
            output,
        } => {
            let identity = load_identity(&vault_path)?;
            let cid = parse_community_id(&community_id)?;
            cmd_vouch(&identity, &member_did, &cid, joined_at, &output)?;
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
        Commands::CreateCommunity {
            name,
            quorum,
            vouches,
            joined_at,
            expires_at,
            stronghold_did,
            output,
        } => {
            cmd_create_community(
                &name,
                quorum,
                &vouches,
                &joined_at,
                &expires_at,
                stronghold_did.as_deref(),
                &output,
            )?;
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
    let (ingress, egress) = setup_stronghold_swarm(&identity, &config.network)?;

    // Construct stores
    let evidence_store = EvidenceStore::new(vault_path.to_path_buf());

    // Build and run the sentinel
    let deps = StrongholdDependencies {
        config: config.clone(),
        identity,
        ingress,
        egress,
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
    use phalanx_forensics::identity::strip_payload_version;

    let bytes = tokio::fs::read(file).await?;
    // The file is an envelope-wrapped postcard body, produced by
    // `cmd_create_community`. Strip the version byte before deserializing.
    let body =
        strip_payload_version(&bytes).map_err(|e| format!("Community envelope rejected: {e}"))?;
    let community: Community = postcard::from_bytes(body)
        .map_err(|e| format!("Failed to deserialize community file: {e}"))?;

    let community_id = community.fingerprint;

    // Store the original wrapped bytes so every reader sees the same envelope.
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

#[allow(clippy::arithmetic_side_effects)] // Counter increment bounded by directory entries.
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
        // Each file is a wrapped envelope — strip the version byte before
        // postcard decode. Silently skip malformed/legacy files.
        let Ok(body) = phalanx_forensics::identity::strip_payload_version(&bytes) else {
            continue;
        };
        if let Ok(community) = postcard::from_bytes::<Community>(body) {
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

// ── `create-community` subcommand ───────────────────────────────────────

/// TOML-friendly shape of the vouches file.
#[derive(serde::Deserialize)]
struct VouchesFile {
    members: Vec<CeremonyMemberEntry>,
}

#[derive(serde::Deserialize)]
struct CeremonyMemberEntry {
    did: String,
    vouches: Vec<VouchEntry>,
}

#[derive(serde::Deserialize)]
struct VouchEntry {
    voucher_did: String,
    signature: String,
}

/// Assemble a community from the operator's collected vouches and emit the
/// community token plus three share-ready forms (raw bytes, custom scheme,
/// Universal Link). Delegates every invariant to
/// `phalanx_forensics::identity::assemble_community`.
#[allow(clippy::too_many_arguments)]
fn cmd_create_community(
    name_str: &str,
    quorum: u8,
    vouches_path: &str,
    joined_at_str: &str,
    expires_at_str: &str,
    stronghold_did_str: Option<&str>,
    output: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use phalanx_forensics::identity::{
        assemble_community, wrap_payload_version, CommunityAssemblyParams,
    };
    use phalanx_proto::community::{
        CeremonyMember, CommunityGrants, Quorum, Vouch, VouchSignature,
    };
    use phalanx_proto::identity::Did;
    use phalanx_proto::time::{SystemClock, TrustedClock};
    use phalanx_proto::trust::{PetName, TrustLevel};

    // ── Parse arguments ────────────────────────────────────────────────
    let name = PetName::new(name_str).map_err(|e| format!("Invalid name: {e}"))?;
    let quorum = Quorum::new(quorum)
        .ok_or_else::<Box<dyn std::error::Error>, _>(|| "Quorum must be > 0".into())?;
    let joined_ts = rfc3339_to_millis(joined_at_str)
        .map_err(|e| format!("Invalid --joined-at {joined_at_str:?}: {e}"))?;
    let expires_ts = rfc3339_to_millis(expires_at_str)
        .map_err(|e| format!("Invalid --expires-at {expires_at_str:?}: {e}"))?;
    let stronghold_did = stronghold_did_str.map(Did::new);

    // ── Load vouches TOML ──────────────────────────────────────────────
    let text = std::fs::read_to_string(vouches_path)
        .map_err(|e| format!("Failed to read {vouches_path:?}: {e}"))?;
    let file: VouchesFile = toml::from_str(&text)
        .map_err(|e| format!("Failed to parse vouches TOML {vouches_path:?}: {e}"))?;

    let members: Result<Vec<CeremonyMember>, Box<dyn std::error::Error>> = file
        .members
        .into_iter()
        .map(|m| {
            let did = Did::new(&m.did);
            let vouches =
                m.vouches
                    .into_iter()
                    .map(|v| {
                        let sig_bytes = parse_hex_bytes(&v.signature)?;
                        let signature = VouchSignature::try_from_slice(&sig_bytes)
                            .ok_or_else::<Box<dyn std::error::Error>, _>(|| {
                                format!(
                                    "Vouch signature for {} has {} bytes; expected 64",
                                    v.voucher_did,
                                    sig_bytes.len()
                                )
                                .into()
                            })?;
                        Ok::<Vouch, Box<dyn std::error::Error>>(Vouch {
                            voucher_did: Did::new(&v.voucher_did),
                            signature,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
            Ok(CeremonyMember { did, vouches })
        })
        .collect();
    let members = members?;

    // ── Delegate assembly to forensics verb ───────────────────────────
    let params = CommunityAssemblyParams {
        name: name.clone(),
        quorum,
        joined_at: joined_ts,
        expires_at: expires_ts,
        stronghold_did,
        baseline_trust: TrustLevel::Verified,
        grants: CommunityGrants::default(),
        members,
    };
    let now = SystemClock.now();
    let community =
        assemble_community(params, now).map_err(|e| format!("Community assembly rejected: {e}"))?;

    // ── Serialize + emit ───────────────────────────────────────────────
    let body = phalanx_forensics::gate::marshal(&community, "create_community")
        .map_err(|e| format!("Failed to serialize community: {e}"))?;
    let payload = wrap_payload_version(&body);
    std::fs::write(output, &payload).map_err(|e| format!("Failed to write {output:?}: {e}"))?;

    let base64url = URL_SAFE_NO_PAD.encode(&payload);

    println!("Community assembled and serialized.");
    println!("  ID:          {}", hex_encode(&community.fingerprint.0));
    println!("  Name:        {}", community.name);
    println!("  Members:     {}", community.members.len());
    println!(
        "  Payload:     {} bytes (envelope + postcard body)",
        payload.len()
    );
    println!("  Output file: {output}");
    println!();
    println!("Share-ready forms:");
    println!("  base64url:        {base64url}");
    println!("  Custom scheme:    phalanx://community/join#data={base64url}");
    println!("  Universal Link:   https://phalanx.app/c/join#data={base64url}");

    Ok(())
}

fn rfc3339_to_millis(text: &str) -> Result<PhalanxTimestamp, Box<dyn std::error::Error>> {
    use chrono::DateTime;
    use phalanx_proto::time::PhalanxTimestamp;
    let parsed: DateTime<chrono::FixedOffset> = DateTime::parse_from_rfc3339(text)?;
    let millis = parsed.timestamp_millis();
    if millis < 0 {
        return Err("timestamp is before UNIX epoch".into());
    }
    #[allow(clippy::cast_sign_loss)] // checked above
    let millis = millis as u64;
    Ok(PhalanxTimestamp::from_millis(millis))
}

// Need PhalanxTimestamp in the return type for rfc3339_to_millis.
use phalanx_proto::time::PhalanxTimestamp;

fn cmd_vouch(
    identity: &PhalanxIdentity,
    member_did_str: &str,
    community_id: &CommunityId,
    joined_at: u64,
    output: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use phalanx_proto::identity::Did;
    use phalanx_proto::time::PhalanxTimestamp;

    let member_did = Did::new(member_did_str);
    let timestamp = PhalanxTimestamp(joined_at);

    let vouch = phalanx_forensics::identity::sign_vouch(
        &identity.keypair,
        &identity.did,
        &member_did,
        community_id,
        timestamp,
    );

    let bytes = phalanx_forensics::gate::marshal(&vouch, "stronghold_vouch")
        .map_err(|e| format!("Failed to serialize vouch: {e}"))?;

    std::fs::write(output, &bytes)?;

    println!("Vouch signed for {member_did_str}");
    println!("  Voucher: {}", identity.did);
    println!("  Output:  {output}");
    println!("  Size:    {} bytes", bytes.len());
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn load_config(path: &str) -> Result<StrongholdConfig, Box<dyn std::error::Error>> {
    if !Path::new(path).exists() {
        eprintln!("Config file {path} not found, using defaults.");
        return Ok(StrongholdConfig::default());
    }
    // Parse the profile + [instance] schema and assemble. A set-but-invalid or
    // incoherent file (e.g. a non-Stronghold profile) is a hard error here.
    // The custody-TTL floor clamp is applied inside `assemble`.
    Ok(StrongholdConfig::load(path)?.into_inner())
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

#[allow(clippy::arithmetic_side_effects)] // Hex index arithmetic — i*2 bounded by string length.
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

#[allow(clippy::arithmetic_side_effects)] // Hex string capacity — bytes * 2.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
