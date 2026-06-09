// crates/phalanx-stronghold/src/sentinel.rs
//
// StrongholdSentinel: event router for the daemon.
// Dispatches NetworkEvents to AggregationActor and CommunityActor.
// Bounded channels, try_send, Volterra-driven ingestion throttle.
//
// Hands layer. Owns the IngressPort, spawns actors, routes events.

use std::sync::Arc;
use std::time::Duration;

use phalanx_forensics::archive::{build_archive_receipt, verify_archive_request};
use phalanx_forensics::gate;
use phalanx_proto::archive::{ArchiveReceipt, ArchiveRequest};
use phalanx_proto::identity::PhalanxIdentity;
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::network::{EgressPort, IngressPort};
use phalanx_proto::prelude::ShardChunk;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::actors::aggregation::{AggregationActor, AggregationCommand, ArchiveAdmit};
use crate::actors::community::{CommunityActor, CommunityCommand};
use crate::config::StrongholdConfig;
use crate::governor::StrongholdGovernor;
use crate::persistence::evidence_store::EvidenceStore;

// ── Channel Capacity ─────────────────────────────────────────────────────

const ACTOR_CHANNEL_CAPACITY: usize = 512;

// ── Dependencies ─────────────────────────────────────────────────────────

pub struct StrongholdDependencies<I: IngressPort, E: EgressPort> {
    pub config: StrongholdConfig,
    pub identity: PhalanxIdentity,
    pub ingress: I,
    pub egress: E,
    pub evidence_store: EvidenceStore,
}

// ── Sentinel ─────────────────────────────────────────────────────────────

pub struct StrongholdSentinel<I: IngressPort, E: EgressPort> {
    config: Arc<StrongholdConfig>,
    identity: Arc<PhalanxIdentity>,
    ingress: I,
    /// Egress for replying to archive pushes (custody receipts) and announcing
    /// custody on the DHT. The daemon was previously passive (egress discarded).
    egress: E,
    aggregation_tx: mpsc::Sender<AggregationCommand>,
    community_tx: mpsc::Sender<CommunityCommand>,
    governor: Arc<StrongholdGovernor>,
    // Actor task handles
    aggregation_handle: tokio::task::JoinHandle<()>,
    community_handle: tokio::task::JoinHandle<()>,
}

impl<I: IngressPort + 'static, E: EgressPort + 'static> StrongholdSentinel<I, E> {
    /// Construct the sentinel, spawn actors, return ready-to-run sentinel.
    pub fn new(deps: StrongholdDependencies<I, E>) -> Self {
        let config = Arc::new(deps.config);
        let identity = Arc::new(deps.identity);
        let governor = Arc::new(StrongholdGovernor::new());

        // Create bounded channels for actor communication.
        let (aggregation_tx, aggregation_rx) = mpsc::channel(ACTOR_CHANNEL_CAPACITY);
        let (community_tx, community_rx) = mpsc::channel(ACTOR_CHANNEL_CAPACITY);

        // Construct and spawn AggregationActor. It gets the identity (to unlock
        // export grants + sign ExportReceipts) and a WEAK handle to its own
        // mailbox (so spawned export tasks can post ExportCompleted back without
        // keeping the channel alive past shutdown).
        let aggregation_actor = AggregationActor::new(
            deps.evidence_store,
            governor.clone(),
            config.clone(),
            identity.clone(),
            aggregation_tx.downgrade(),
            aggregation_rx,
        );
        let aggregation_handle = tokio::spawn(aggregation_actor.run());

        // Construct and spawn CommunityActor.
        let community_actor = CommunityActor::new(community_rx);
        let community_handle = tokio::spawn(community_actor.run());

        Self {
            config,
            identity,
            ingress: deps.ingress,
            egress: deps.egress,
            aggregation_tx,
            community_tx,
            governor,
            aggregation_handle,
            community_handle,
        }
    }

    /// Run the sentinel event loop. Blocks until Shutdown or ingress closes.
    pub async fn run(&mut self) {
        info!("StrongholdSentinel: entering run loop");

        let mut maintenance = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                event = self.ingress.next_event() => {
                    match event {
                        Some(ev) => {
                            if self.handle_event(ev).await {
                                break;
                            }
                        }
                        None => {
                            info!("StrongholdSentinel: ingress closed, shutting down");
                            break;
                        }
                    }
                }
                _ = maintenance.tick() => {
                    self.refresh_routing().await;
                    // Custody TTL sweep: reclaim expired recordings.
                    if self
                        .aggregation_tx
                        .try_send(AggregationCommand::SweepExpired)
                        .is_err()
                    {
                        warn!("StrongholdSentinel: aggregation channel full, skipping custody sweep");
                    }
                    // Autonomous export: scan for settled, grant-bearing
                    // recordings and export them to durable storage.
                    if self
                        .aggregation_tx
                        .try_send(AggregationCommand::ScanExports)
                        .is_err()
                    {
                        warn!("StrongholdSentinel: aggregation channel full, skipping export scan");
                    }
                }
            }
        }

        info!("StrongholdSentinel: exited run loop");
    }

    /// Dispatch a single NetworkEvent. Returns `true` if shutdown requested.
    async fn handle_event(&self, event: NetworkEvent) -> bool {
        match event {
            NetworkEvent::DataReceived { data, topic, .. } => {
                // Cryptographic Forgetting: route revocation tokens
                if topic.as_str() == phalanx_proto::topic::MeshTopic::revocation().as_str() {
                    self.handle_revocation(&data);
                    return false;
                }

                // Wire format is `Vec<ShardChunk>` (length 1 for single-symbol
                // publishes, length N for bundled). Deserialize and dispatch
                // each chunk individually to the AggregationActor.
                let bundle: Vec<ShardChunk> =
                    match gate::unmarshal(&data, "StrongholdSentinel::ingest") {
                        Ok(c) => c,
                        Err(e) => {
                            debug!(error = %e, "StrongholdSentinel: failed to unmarshal bundle");
                            return false;
                        }
                    };

                for chunk in bundle {
                    if let Err(e) = self
                        .aggregation_tx
                        .try_send(AggregationCommand::IngestChunk { chunk })
                    {
                        warn!(
                            error = %e,
                            "StrongholdSentinel: aggregation channel full, dropping chunk"
                        );
                    }
                }
                false
            }

            // Directed archive PUSH: a publisher staging a recording for custody.
            NetworkEvent::ArchiveRequested {
                request,
                channel_id,
                ..
            } => {
                // Spawn so a slow/large push — or a flood of them — cannot block
                // the ingress event loop (head-of-line). The persist round-trip,
                // receipt, and DHT announce all happen off the loop.
                tokio::spawn(Self::run_archive_request(
                    self.egress.clone(),
                    self.identity.clone(),
                    self.aggregation_tx.clone(),
                    request,
                    channel_id,
                ));
                false
            }

            NetworkEvent::Shutdown => {
                info!("StrongholdSentinel: shutdown event received");
                true
            }

            // All other event variants are ignored by the Stronghold.
            // PeerDiscovered, RecordingRequested, ProvidersDiscovered,
            // ShardResponseReceived, ArchiveReceiptReceived, PeerDisconnected,
            // BLE auth events are handled by the phone's MeshSentinel.
            _ => false,
        }
    }

    /// Handle a directed archive PUSH (runs on a spawned task, not the ingress
    /// loop): verify the pusher, persist under the custody fairness gate (via
    /// AggregationActor), and reply with a signed custody receipt. On success,
    /// announce custody on the DHT. Takes owned handles so it is `'static`.
    async fn run_archive_request(
        egress: E,
        identity: Arc<PhalanxIdentity>,
        aggregation_tx: mpsc::Sender<AggregationCommand>,
        request: ArchiveRequest,
        channel_id: String,
    ) {
        // 1. Authenticate the pusher's request-level signature.
        if !verify_archive_request(&request) {
            warn!("StrongholdSentinel: archive push failed signature verification, rejecting");
            let _ = egress
                .send_archive_response(&channel_id, ArchiveReceipt::Rejected)
                .await;
            return;
        }

        let recording_id = request.recording_id.clone();
        let owner_did = request.sender_did.clone();

        // 2. Persist via the AggregationActor (membership + per-envelope verify
        //    + fairness gate + persist + ledger + custody deadline). The export
        //    grant (if any) rides along so the actor can autonomously export
        //    this recording once it settles. It is already bound into the
        //    request signature verified in step 1, so it cannot have been
        //    stripped or substituted in flight.
        let (reply_tx, reply_rx) = oneshot::channel();
        if aggregation_tx
            .send(AggregationCommand::PersistEnvelopes {
                recording_id: recording_id.clone(),
                envelopes: request.envelopes,
                owner_did,
                grant: request.grant,
                reply_to: reply_tx,
            })
            .await
            .is_err()
        {
            warn!("StrongholdSentinel: aggregation channel closed; cannot persist archive push");
            return;
        }
        let outcome = match reply_rx.await {
            Ok(o) => o,
            Err(_) => {
                warn!("StrongholdSentinel: aggregation did not reply to archive push");
                return;
            }
        };

        // 3. Build the receipt. `Stored` is signed by this Stronghold's identity
        //    over the bounds the actor's clock fixed.
        let (receipt, stored) = match outcome {
            ArchiveAdmit::Stored {
                envelope_count,
                stored_at,
                held_until,
            } => (
                build_archive_receipt(
                    &identity,
                    recording_id.clone(),
                    stored_at,
                    held_until,
                    envelope_count,
                ),
                true,
            ),
            ArchiveAdmit::QuotaExceeded => (ArchiveReceipt::QuotaExceeded, false),
            ArchiveAdmit::Rejected => (ArchiveReceipt::Rejected, false),
        };

        if let Err(e) = egress.send_archive_response(&channel_id, receipt).await {
            warn!(error = %e, "StrongholdSentinel: failed to send archive receipt");
        }

        // 4. Announce custody on the DHT (the live/broad durability signal).
        if stored {
            if let Err(e) = egress.announce_recording(&recording_id).await {
                warn!(error = %e, "StrongholdSentinel: failed to announce custody on DHT");
            }
        }
    }

    /// Cryptographic Forgetting: verify and forward revocation tokens to AggregationActor.
    fn handle_revocation(&self, data: &[u8]) {
        let token: phalanx_proto::revocation::RevocationToken =
            match gate::unmarshal(data, "StrongholdSentinel::revocation") {
                Ok(t) => t,
                Err(e) => {
                    debug!(error = %e, "StrongholdSentinel: malformed revocation token");
                    return;
                }
            };

        if let Err(e) = phalanx_forensics::revocation::verify_revocation_token(&token) {
            warn!(
                recording = %token.recording_id,
                error = %e,
                "StrongholdSentinel: invalid revocation token rejected"
            );
            return;
        }

        if let Err(e) = self.aggregation_tx.try_send(AggregationCommand::Revoke {
            recording_id: token.recording_id.clone(),
        }) {
            warn!(error = %e, "StrongholdSentinel: aggregation channel full, dropping revocation");
        } else {
            info!(recording = %token.recording_id, "Revocation forwarded to aggregation");
        }
    }

    /// Refresh community routing in AggregationActor by querying CommunityActor.
    async fn refresh_routing(&self) {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .community_tx
            .try_send(CommunityCommand::SnapshotRouting { reply_to: reply_tx })
            .is_err()
        {
            warn!("StrongholdSentinel: community channel full, skipping routing refresh");
            return;
        }

        match reply_rx.await {
            Ok(routing) => {
                let did_count = routing.len();
                if let Err(e) = self
                    .aggregation_tx
                    .try_send(AggregationCommand::RefreshRouting { routing })
                {
                    warn!(
                        error = %e,
                        "StrongholdSentinel: aggregation channel full, routing refresh dropped"
                    );
                } else {
                    debug!(dids = did_count, "StrongholdSentinel: routing refreshed");
                }
            }
            Err(_) => {
                warn!("StrongholdSentinel: community actor did not reply to routing snapshot");
            }
        }
    }

    /// Expose the community channel for external callers (e.g., CLI import).
    pub fn community_tx(&self) -> &mpsc::Sender<CommunityCommand> {
        &self.community_tx
    }

    /// Expose the aggregation channel for external callers (e.g., corroboration ops).
    pub fn aggregation_tx(&self) -> &mpsc::Sender<AggregationCommand> {
        &self.aggregation_tx
    }

    /// Expose the governor for external callers.
    pub fn governor(&self) -> &Arc<StrongholdGovernor> {
        &self.governor
    }

    /// Expose the config for external callers.
    pub fn config(&self) -> &Arc<StrongholdConfig> {
        &self.config
    }

    /// Expose the identity for external callers (e.g., proof signing).
    pub fn identity(&self) -> &Arc<PhalanxIdentity> {
        &self.identity
    }

    /// Graceful shutdown: drop actor channels and await task completion.
    pub async fn shutdown(self) {
        info!("StrongholdSentinel: shutting down actors");

        // Drop senders to close actor channels, triggering their exit.
        drop(self.aggregation_tx);
        drop(self.community_tx);

        // Await actor tasks to ensure clean exit.
        let _ = self.aggregation_handle.await;
        let _ = self.community_handle.await;

        info!("StrongholdSentinel: all actors stopped");
    }
}
