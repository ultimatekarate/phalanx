// crates/phalanx-stronghold/src/sentinel.rs
//
// StrongholdSentinel: event router for the daemon.
// Dispatches NetworkEvents to AggregationActor and CommunityActor.
// Bounded channels, try_send, Volterra-driven ingestion throttle.
//
// Hands layer. Owns the IngressPort, spawns actors, routes events.

use std::sync::Arc;
use std::time::Duration;

use phalanx_forensics::gate;
use phalanx_proto::identity::PhalanxIdentity;
use phalanx_proto::network::IngressPort;
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::ShardChunk;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::actors::aggregation::{AggregationActor, AggregationCommand};
use crate::actors::community::{CommunityActor, CommunityCommand};
use crate::config::StrongholdConfig;
use crate::governor::StrongholdGovernor;
use crate::persistence::evidence_store::EvidenceStore;

// ── Channel Capacity ─────────────────────────────────────────────────────

const ACTOR_CHANNEL_CAPACITY: usize = 512;

// ── Dependencies ─────────────────────────────────────────────────────────

pub struct StrongholdDependencies<I: IngressPort> {
    pub config: StrongholdConfig,
    pub identity: PhalanxIdentity,
    pub ingress: I,
    pub evidence_store: EvidenceStore,
}

// ── Sentinel ─────────────────────────────────────────────────────────────

pub struct StrongholdSentinel<I: IngressPort> {
    config: Arc<StrongholdConfig>,
    identity: Arc<PhalanxIdentity>,
    ingress: I,
    aggregation_tx: mpsc::Sender<AggregationCommand>,
    community_tx: mpsc::Sender<CommunityCommand>,
    governor: Arc<StrongholdGovernor>,
    // Actor task handles
    aggregation_handle: tokio::task::JoinHandle<()>,
    community_handle: tokio::task::JoinHandle<()>,
}

impl<I: IngressPort> StrongholdSentinel<I> {
    /// Construct the sentinel, spawn actors, return ready-to-run sentinel.
    pub fn new(deps: StrongholdDependencies<I>) -> Self {
        let config = Arc::new(deps.config);
        let identity = Arc::new(deps.identity);
        let governor = Arc::new(StrongholdGovernor::new());

        // Create bounded channels for actor communication.
        let (aggregation_tx, aggregation_rx) = mpsc::channel(ACTOR_CHANNEL_CAPACITY);
        let (community_tx, community_rx) = mpsc::channel(ACTOR_CHANNEL_CAPACITY);

        // Construct and spawn AggregationActor.
        let aggregation_actor =
            AggregationActor::new(deps.evidence_store, governor.clone(), aggregation_rx);
        let aggregation_handle = tokio::spawn(aggregation_actor.run());

        // Construct and spawn CommunityActor.
        let community_actor = CommunityActor::new(community_rx);
        let community_handle = tokio::spawn(community_actor.run());

        Self {
            config,
            identity,
            ingress: deps.ingress,
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

                // Deserialize ShardChunk from the wire bytes.
                let chunk: ShardChunk = match gate::unmarshal(&data, "StrongholdSentinel::ingest") {
                    Ok(c) => c,
                    Err(e) => {
                        debug!(error = %e, "StrongholdSentinel: failed to unmarshal chunk");
                        return false;
                    }
                };

                // Dispatch to AggregationActor via try_send — drop on full channel.
                if let Err(e) = self
                    .aggregation_tx
                    .try_send(AggregationCommand::IngestChunk { chunk })
                {
                    warn!(
                        error = %e,
                        "StrongholdSentinel: aggregation channel full, dropping chunk"
                    );
                }
                false
            }

            NetworkEvent::Shutdown => {
                info!("StrongholdSentinel: shutdown event received");
                true
            }

            // All other event variants are ignored by the Stronghold.
            // PeerDiscovered, RecordingRequested, ProvidersDiscovered,
            // ShardResponseReceived, PeerDisconnected, BLE auth events
            // are handled by the phone's MeshSentinel, not the Stronghold.
            _ => false,
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
