#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
// Receiver-side integration test for M2.3 autonomous export: a directed archive
// PUSH carrying an export grant (sealed to the Stronghold) is persisted under
// custody, and once it settles the Stronghold autonomously unlocks the grant,
// transcodes + C2PA-signs the recording, and writes the signed MP4 plus a
// self-verifying ExportReceipt to the durable sink. Drives the real
// AggregationActor over its mailbox — no swarm, no FFI.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use phalanx_forensics::PayloadCipher;
use phalanx_forensics::archive::verify_export_receipt;
use phalanx_forensics::cryptography::grant::GrantAuthority;
use phalanx_forensics::gate::{LensThresholds, verify_provenance_from_jpeg};
use phalanx_forensics::reassembler::{compress_frame, create_video_shard};
use phalanx_forensics::witness::WitnessAuthority;
use phalanx_proto::archive::ExportReceipt;
use phalanx_proto::community::CommunityId;
use phalanx_proto::crypto::{GrantPermissions, SealedLocator, SymmetricKey};
use phalanx_proto::evidence::{Evidence, ForensicMetrics, StorageSequence, WitnessEnvelope};
use phalanx_proto::identity::{PhalanxIdentity, RecordingId, WitnessId};
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_proto::types::Fps;
use phalanx_stronghold::actors::aggregation::{AggregationActor, AggregationCommand, ArchiveAdmit};
use phalanx_stronghold::config::StrongholdConfig;
use phalanx_stronghold::governor::StrongholdGovernor;
use phalanx_stronghold::persistence::evidence_store::EvidenceStore;
use tempfile::tempdir;
use tokio::sync::mpsc;

/// Spawn an AggregationActor with a known Stronghold identity (so the test can
/// seal a grant to it) over a temp vault. Returns the command sender + handle.
fn spawn_actor(
    config: Arc<StrongholdConfig>,
    vault: std::path::PathBuf,
    identity: Arc<PhalanxIdentity>,
) -> (
    mpsc::Sender<AggregationCommand>,
    tokio::task::JoinHandle<()>,
) {
    let store = EvidenceStore::new(vault);
    let governor = Arc::new(StrongholdGovernor::new());
    let (tx, rx) = mpsc::channel(64);
    let actor = AggregationActor::new(store, governor, config, identity, tx.downgrade(), rx);
    let handle = tokio::spawn(actor.run());
    (tx, handle)
}

/// A faint, JPEG-stable 256×256 frame (single bright patch on black): clears
/// `verify_provenance_from_jpeg` via the documented low-luminance path while
/// keeping PRNU/Laplacian non-zero. Mirrors the FFI export test's fixture.
fn faint_frame_jpeg(seed: u32) -> Vec<u8> {
    let (w, h) = (256usize, 256usize);
    let mut y = vec![0u8; w * h];
    let shift = seed as usize % 8;
    let px0 = w / 2 - 8 + shift;
    let py0 = h / 2 - 8;
    for dy in 0..16 {
        for dx in 0..16 {
            let x = (px0 + dx).min(w - 1);
            let yy = (py0 + dy).min(h - 1);
            y[yy * w + x] = 200;
        }
    }
    let uv = vec![128u8; (w / 2) * (h / 2) * 2];
    compress_frame(&y, &uv, w as u32, h as u32, false).expect("compress faint frame")
}

/// A video envelope of three faint frames, encrypted under `key`, owner-signed.
fn encrypted_video_envelope(
    seq: u32,
    rec: &RecordingId,
    key: &SymmetricKey,
    owner: &PhalanxIdentity,
) -> WitnessEnvelope {
    let frames = vec![
        faint_frame_jpeg(seq),
        faint_frame_jpeg(seq + 1),
        faint_frame_jpeg(seq + 2),
    ];
    let mut shard = create_video_shard(
        frames,
        StorageSequence(seq),
        Fps::new(30),
        rec.clone(),
        ForensicMetrics::default(),
        PhalanxTimestamp::from_millis(1_700_000_000_000 + u64::from(seq) * 33),
    )
    .expect("video shard");
    shard.payload.apply_encryption(key).expect("encrypt video");
    WitnessEnvelope::sign_envelope(Evidence::Video(shard), owner, WitnessId::random(), None)
        .expect("sign video envelope")
}

#[tokio::test]
async fn grant_bearing_push_autonomously_exports_signed_artifact() {
    let dir = tempdir().unwrap();
    let export_sink = dir.path().join("exports-sink");

    let mut config = StrongholdConfig::default();
    config.storage.vault_path = dir.path().to_string_lossy().to_string();
    config.storage.export_path = Some(export_sink.to_string_lossy().to_string());
    config.storage.export_quiescence_secs = 1; // settle fast for the test
    let config = Arc::new(config);

    // The Stronghold identity the grant is sealed to.
    let stronghold = Arc::new(PhalanxIdentity::new_ephemeral());
    let (tx, handle) = spawn_actor(config, dir.path().to_path_buf(), stronghold.clone());

    // Owner routes to a community the Stronghold serves.
    let owner = PhalanxIdentity::new_ephemeral();
    let community = CommunityId([3u8; 32]);
    let mut routing = HashMap::new();
    routing.insert(owner.did.clone(), vec![community]);
    tx.send(AggregationCommand::RefreshRouting { routing })
        .await
        .unwrap();

    // Encrypt evidence under a DEK, and seal that DEK to the Stronghold as an
    // export grant (escrow-for-export, export permission granted).
    let dek_bytes = [0x42u8; 32];
    let key = SymmetricKey::from_bytes(dek_bytes);
    let rid = RecordingId::new("rec-export");

    // Sanity: the fixture clears the provenance gate the export re-runs.
    verify_provenance_from_jpeg(&faint_frame_jpeg(1), &LensThresholds::default())
        .expect("faint frame passes provenance gate");

    let envelopes = vec![
        encrypted_video_envelope(1, &rid, &key, &owner),
        encrypted_video_envelope(2, &rid, &key, &owner),
    ];
    let grant = SealedLocator::seal(
        rid.clone(),
        &dek_bytes,
        &owner,
        stronghold.did.clone(),
        GrantPermissions {
            playback: false,
            export: true,
        },
    )
    .expect("seal export grant");

    // Push the recording WITH the grant.
    let (rtx, rrx) = oneshot::channel();
    tx.send(AggregationCommand::PersistEnvelopes {
        recording_id: rid.clone(),
        envelopes,
        owner_did: owner.did.clone(),
        grant: Some(grant),
        reply_to: rtx,
    })
    .await
    .unwrap();
    assert!(
        matches!(rrx.await.unwrap(), ArchiveAdmit::Stored { .. }),
        "grant-bearing push should be admitted into custody"
    );

    // Let the recording settle past the quiescence window, then trigger the
    // export scan (what the sentinel's maintenance tick does in production).
    tokio::time::sleep(Duration::from_millis(1300)).await;
    tx.send(AggregationCommand::ScanExports).await.unwrap();

    // The artifact + receipt filenames derive from blake3(recording_id).
    let stem = blake3::hash(rid.as_str().as_bytes()).to_hex().to_string();
    let mp4_path = export_sink.join(format!("{stem}.mp4"));
    let receipt_path = export_sink.join(format!("{stem}.receipt.bin"));

    // Poll for the off-loop export task to land the artifact (transcode is real).
    let mut waited = 0;
    while !mp4_path.exists() && waited < 150 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        waited += 1;
    }
    assert!(
        mp4_path.exists(),
        "autonomous export should write the signed MP4 to the sink"
    );

    let mp4 = std::fs::read(&mp4_path).unwrap();
    assert!(!mp4.is_empty(), "exported mp4 is non-empty");

    // The signed ExportReceipt self-verifies, names the Stronghold, and binds
    // the exact artifact bytes that landed.
    let receipt_bytes = std::fs::read(&receipt_path).unwrap();
    let receipt: ExportReceipt = postcard::from_bytes(&receipt_bytes).unwrap();
    assert!(
        verify_export_receipt(&receipt),
        "export receipt must self-verify against the Stronghold DID"
    );
    assert_eq!(receipt.recording_id, rid);
    assert_eq!(receipt.exported_by, stronghold.did);
    assert_eq!(
        receipt.artifact_hash,
        *blake3::hash(&mp4).as_bytes(),
        "receipt artifact_hash must bind the exact bytes written"
    );

    drop(tx);
    let _ = handle.await;
}
