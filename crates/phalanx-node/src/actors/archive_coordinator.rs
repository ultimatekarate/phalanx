// crates/phalanx-node/src/actors/archive_coordinator.rs
//
// Archive custody coordinator. Owns the per-session Stronghold-staging dedup
// set and the per-recording custody ledger, and runs the directed archive PUSH
// workflow OFF the MeshSentinel run loop: fetch a recording's envelopes from
// storage, mint per-peer export grants, and dispatch `PushArchive` to each
// configured archival peer. Also records inbound custody receipts.
//
// Matches the `PlaybackCoordinator` taxonomy (state-heavy "Coordinator").

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};

use phalanx_forensics::archive::{build_archive_request_with_grant, verify_archive_receipt};
use phalanx_proto::archive::ArchiveReceipt;
use phalanx_proto::prelude::*;

use crate::actors::egress::EgressCommand;
use crate::actors::shutdown::ShutdownSignal;
use crate::actors::storage::StorageCommand;
use crate::config::NodeConfig;

/// Commands accepted by the archive coordinator. No autonomous tick — purely
/// command-driven (CanarySupervisor convention).
#[derive(Debug)]
pub enum ArchiveCommand {
    /// StorageActor committed a shard. Stage the recording at the configured
    /// Stronghold custody peers (deduped per session). Maps from MeshSentinel's
    /// `commit_notify_rx` run-loop arm.
    StageRecording { recording_id: RecordingId },
    /// A custody receipt arrived from a Stronghold. Verify its self-signature
    /// and record the replica + `held_until` deadline. Maps from
    /// `NetworkEvent::ArchiveReceiptReceived`.
    ReceiptReceived { receipt: ArchiveReceipt },
}

pub struct ArchiveCoordinator {
    // Owned state (moved off MeshSentinel).
    /// Recordings already pushed to Stronghold custody peers this session
    /// (dedup — prevents per-shard storms; mirrors the DHT announce dedup).
    archived_to_strongholds: HashSet<RecordingId>,
    /// Per-recording Stronghold replicas and the deadline each committed to
    /// hold until. Point-in-time / last-known, refreshable.
    custody: HashMap<RecordingId, HashMap<Did, PhalanxTimestamp>>,

    // Arc-shared dependencies (clones of MeshSentinel's).
    config: Arc<NodeConfig>,
    identity: Arc<PhalanxIdentity>,

    // Outbound senders.
    storage_tx: mpsc::Sender<StorageCommand>,
    egress_tx: mpsc::Sender<EgressCommand>,

    // Inbound + lifecycle.
    rx: mpsc::Receiver<ArchiveCommand>,
    shutdown: Arc<ShutdownSignal>,
}

impl ArchiveCoordinator {
    pub fn new(
        config: Arc<NodeConfig>,
        identity: Arc<PhalanxIdentity>,
        storage_tx: mpsc::Sender<StorageCommand>,
        egress_tx: mpsc::Sender<EgressCommand>,
        rx: mpsc::Receiver<ArchiveCommand>,
        shutdown: Arc<ShutdownSignal>,
    ) -> Self {
        Self {
            archived_to_strongholds: HashSet::new(),
            custody: HashMap::new(),
            config,
            identity,
            storage_tx,
            egress_tx,
            rx,
            shutdown,
        }
    }

    pub async fn run(mut self) {
        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => break,
                Some(cmd) = self.rx.recv() => {
                    self.handle_command(cmd).await;
                }
                else => break,
            }
        }

        // Post-loop drain: finish any staging queued before cancellation while
        // storage/egress are still alive (the drain order keeps them up).
        while let Ok(cmd) = self.rx.try_recv() {
            self.handle_command(cmd).await;
        }
    }

    async fn handle_command(&mut self, cmd: ArchiveCommand) {
        match cmd {
            ArchiveCommand::StageRecording { recording_id } => {
                self.stage_recording(recording_id).await;
            }
            ArchiveCommand::ReceiptReceived { receipt } => {
                self.record_receipt(receipt);
            }
        }
    }

    /// Directed archive PUSH: stage a recording at the configured Stronghold
    /// custody peers so it survives device seizure long enough to be exported.
    /// Deduped per recording per session; idempotent on the Stronghold side.
    async fn stage_recording(&mut self, recording_id: RecordingId) {
        if self.config.network.archival_peers.is_empty() {
            return;
        }
        if !self.archived_to_strongholds.insert(recording_id.clone()) {
            return; // already staged this session
        }
        // Fetch this recording's own envelopes (same query the retrieval
        // responder uses; owner == self so the ownership guard passes).
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .storage_tx
            .send(StorageCommand::Retrieval {
                recording_id: recording_id.clone(),
                owner_did: Some(self.identity.did.clone()),
                reply_to: reply_tx,
            })
            .await
            .is_err()
        {
            return;
        }
        let Ok(envelopes) = reply_rx.await else {
            return;
        };
        if envelopes.is_empty() {
            return;
        }
        // One request per peer: a peer configured with a Stronghold DID gets an
        // export grant sealed to it (escrow-for-export); a DID-less peer gets a
        // custody-only push (grant = None). The grant is bound into the request
        // signature, so each peer's request is built and signed individually.
        for peer in &self.config.network.archival_peers {
            // The push target is the peer id from the dial multiaddr's
            // `/p2p/<id>` tail (the node already dials the full address at
            // startup, so it is a connected peer). No peer id ⇒ not a directed
            // target; skip it.
            let Some(peer_id) = peer.peer_id() else {
                tracing::warn!(
                    address = %peer.address,
                    "Archive: archival peer address has no /p2p/<peer-id>; skipping push"
                );
                continue;
            };
            let grant = peer.stronghold_did.as_ref().and_then(|did| {
                crate::actors::archive_grant::mint_export_grant(&self.identity, &recording_id, did)
            });
            let request = build_archive_request_with_grant(
                &self.identity,
                recording_id.clone(),
                envelopes.clone(),
                grant,
            );
            let target = MeshAddress::new(peer_id);
            let _ = self
                .egress_tx
                .send(EgressCommand::PushArchive { target, request })
                .await;
        }
    }

    /// A custody receipt arrived from a Stronghold. Verify its self-signature and
    /// record the replica + its `held_until` deadline against the recording.
    fn record_receipt(&mut self, receipt: ArchiveReceipt) {
        if !verify_archive_receipt(&receipt) {
            tracing::warn!("Archive: ignoring unverifiable custody receipt");
            return;
        }
        let ArchiveReceipt::Stored {
            recording_id,
            replica_did,
            held_until,
            ..
        } = receipt
        else {
            return; // unreachable: only Stored verifies
        };
        let entry = self.custody.entry(recording_id.clone()).or_default();
        entry.insert(replica_did, held_until);
        tracing::info!(
            recording = %recording_id,
            replicas = entry.len(),
            target = self.config.network.target_replica_count,
            "Archive: custody confirmed at a Stronghold"
        );
    }
}
