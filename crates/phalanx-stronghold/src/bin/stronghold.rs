// crates/phalanx-stronghold/src/bin/stronghold.rs
//
// Stronghold CLI entry point.
//
// Scaffolding: parses args and prints placeholders.
// Real wiring comes after integration tests validate the core ops.

use clap::{Parser, Subcommand};

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
    /// Import a community roster.
    ImportCommunity {
        #[arg(short, long)]
        file: String,
    },
    /// List known communities.
    Communities,
    /// List collected recordings for a community.
    Recordings {
        #[arg(short, long)]
        community: String,
    },
    /// Run the Corroboration Gate.
    Corroborate {
        #[arg(short, long)]
        community: String,
        #[arg(short, long, num_args = 1..)]
        grants: Vec<String>,
        #[arg(short, long, num_args = 2..)]
        recordings: Vec<String>,
    },
    /// Export a proof as evidence files.
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

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    println!("Phalanx Stronghold — config: {}", cli.config);

    match cli.command {
        Commands::Run => {
            println!("Stronghold daemon starting...");
            // TODO: Load config, initialize identity, wire up
            // StrongholdSentinel, and run the aggregation loop.
            println!("  (placeholder — daemon not yet wired)");
        }
        Commands::ImportCommunity { file } => {
            println!("Importing community roster from: {file}");
            // TODO: Parse roster file, validate signatures, store in
            // community manager.
        }
        Commands::Communities => {
            println!("Listing known communities...");
            // TODO: Load community manager, list all communities.
        }
        Commands::Recordings { community } => {
            println!("Listing recordings for community: {community}");
            // TODO: Load evidence store, list recordings for the
            // specified community.
        }
        Commands::Corroborate {
            community,
            grants,
            recordings,
        } => {
            println!("Running Corroboration Gate:");
            println!("  community: {community}");
            println!("  grants:    {grants:?}");
            println!("  recordings: {recordings:?}");
            // TODO: Wire up run_corroboration() from ops::corroborate.
            //
            //   let config = load_config(&cli.config);
            //   let identity = PhalanxIdentity::init(...)?;
            //   let evidence_store = EvidenceStore::new(...);
            //   let proof_store = ProofStore::new(...);
            //   let community_id = parse_community_id(&community)?;
            //   let grant_paths: Vec<PathBuf> = grants.iter().map(PathBuf::from).collect();
            //   let recording_ids = parse_recording_ids(&recordings)?;
            //   let proof = phalanx_stronghold::ops::corroborate::run_corroboration(
            //       &identity, &evidence_store, &proof_store,
            //       &config.corroboration, &community_id,
            //       &grant_paths, &recording_ids,
            //   ).await?;
            //   println!("Proof hash: {:?}", proof.proof_hash);
        }
        Commands::Export {
            community,
            proof,
            grants,
            output,
        } => {
            println!("Exporting proof as evidence files:");
            println!("  community: {community}");
            println!("  proof:     {proof}");
            println!("  grants:    {grants:?}");
            println!("  output:    {output}");
            // TODO: Wire up run_export() from ops::export.
            //
            //   let config = load_config(&cli.config);
            //   let identity = PhalanxIdentity::init(...)?;
            //   let evidence_store = EvidenceStore::new(...);
            //   let proof_store = ProofStore::new(...);
            //   let community_id = parse_community_id(&community)?;
            //   let proof_hash = parse_hex_hash(&proof)?;
            //   let grant_paths: Vec<PathBuf> = grants.iter().map(PathBuf::from).collect();
            //   let output_dir = PathBuf::from(&output);
            //   let files = phalanx_stronghold::ops::export::run_export(
            //       &identity, &evidence_store, &proof_store,
            //       &config.corroboration, &community_id,
            //       &proof_hash, &grant_paths, &output_dir,
            //   ).await?;
            //   println!("Exported {} files to {}", files.len(), output);
        }
    }
}
