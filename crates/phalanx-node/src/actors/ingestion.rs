use crate::actors::egress::EgressCommand;
use crate::actors::storage::StorageCommand;
use crate::actors::trust_actor::TrustCommand;
use crate::clock::TrustedClock;
use crate::config::NodeConfig;
use crate::trust::{ReputationProjection, TrustOracle};
use crate::vitals::Homeostasis;
use crate::vitals::SystemGovernor;
use phalanx_forensics::gate::TrustGate;
use phalanx_forensics::policy::{IngressGovernor, TrafficGovernor};

use phalanx_proto::prelude::*;
use phalanx_proto::trust::Offense;
use phalanx_proto::types::{ForensicUnit, Unverified, Verified};
use phalanx_transport::identity_ext::Libp2pExt;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Duration;

pub enum IngestionCommand {
    ProcessChunk {
        peer_id: NetworkId,
        data: Vec<u8>,
        topic: MeshTopic,
    },
}

pub struct IngestionActor {
    config: NodeConfig,
    identity: Arc<PhalanxIdentity>,
    clock: Arc<TrustedClock>,
    traffic_governor: TrafficGovernor,
    ingress_governor: IngressGovernor,
    trust_oracle: ReputationProjection,
    storage_tx: mpsc::Sender<StorageCommand>,
    egress_tx: mpsc::Sender<EgressCommand>,
    trust_tx: mpsc::Sender<TrustCommand>,
    system_governor: Arc<SystemGovernor>,
    rx: mpsc::Receiver<IngestionCommand>,
}

impl IngestionActor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: NodeConfig,
        identity: Arc<PhalanxIdentity>,
        clock: Arc<TrustedClock>,
        traffic_governor: TrafficGovernor,
        ingress_governor: IngressGovernor,
        trust_oracle: ReputationProjection,
        storage_tx: mpsc::Sender<StorageCommand>,
        egress_tx: mpsc::Sender<EgressCommand>,
        trust_tx: mpsc::Sender<TrustCommand>,
        system_governor: Arc<SystemGovernor>,
        rx: mpsc::Receiver<IngestionCommand>,
    ) -> Self {
        Self {
            config,
            identity,
            clock,
            traffic_governor,
            ingress_governor,
            trust_oracle,
            storage_tx,
            egress_tx,
            trust_tx,
            system_governor,
            rx,
        }
    }

    pub async fn run(mut self) {
        while let Some(cmd) = self.rx.recv().await {
            match cmd {
                IngestionCommand::ProcessChunk {
                    peer_id,
                    data,
                    topic,
                } => {
                    self.handle_network_ingress(peer_id, &data, topic).await;
                }
            }
        }
    }

    async fn handle_network_ingress(&mut self, peer_id: NetworkId, data: &[u8], topic: MeshTopic) {
        // 1. TOPIC ROUTING (Edge Filtering)
        let topic_str = topic.as_str();
        if topic_str != self.config.network.video_topic.as_str()
            && topic_str != self.config.network.audio_topic.as_str()
        {
            tracing::warn!("Ingestion dropped chunk: Invalid topic {}", topic_str);
            return;
        }

        let scale = self.system_governor.ingestion_scaler();
        let delay = scale.as_throttle_delay(10);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }

        if !self
            .traffic_governor
            .should_accept(&peer_id, &self.identity.to_network_id())
        {
            return;
        }

        let start_cpu = tokio::time::Instant::now();

        if let Ok(raw_chunk) = phalanx_forensics::gate::unmarshal::<ShardChunk>(data, "ingestion") {
            // Per-peer bandwidth tracking via Volterra integral
            self.system_governor
                .record_peer_bandwidth(&peer_id.to_string());
            if !self
                .system_governor
                .is_peer_bandwidth_ok(&peer_id.to_string())
            {
                tracing::warn!(peer = %peer_id, "Per-peer bandwidth exceeded, dropping");
                return;
            }

            let unverified = ForensicUnit::<_, Unverified>::new(raw_chunk);
            let sender_did = unverified.data.owner_did.clone();

            if !self.system_governor.is_peer_coupled(&peer_id.to_string())
                || sender_did.verify_standing(&self.trust_oracle).is_err()
            {
                let _ = self
                    .egress_tx
                    .send(EgressCommand::Dispatch {
                        channel_id: "ban".to_string(),
                        response: VolleyResponse::Unauthorized,
                    })
                    .await;
                // The EgressActor does not need a way to ban peers. Banning on egress is purely
                // about preserving capacity, not about violating trust. The integral equations handle
                // that.
                return;
            }

            let shard_birth = unverified.data.timestamp;
            let now_ms = self.clock.now().unwrap_or(shard_birth);
            let age = Duration::from_millis(now_ms.0.saturating_sub(shard_birth.0));

            self.system_governor.record_latency_pressure(age);
            let tolerance = self.system_governor.temporal_tolerance();

            if age > tolerance {
                tracing::warn!(peer = %peer_id, age = ?age, tol = ?tolerance, "Dropped: Stale Shard");
                return;
            }

            let trust_level = self.trust_oracle.check_trust_by_did(&sender_did);
            let stress = self.system_governor.current_stress();

            let endowment = self.system_governor.sybil_endowment();
            self.ingress_governor.base_max_slots = endowment.0 as usize;

            match self
                .ingress_governor
                .try_allocate(peer_id.clone(), trust_level, stress)
            {
                Ok(Some(_evicted)) => {}
                Ok(None) => {}
                Err(_) => {
                    tracing::error!(target: "siege_debug", "INGRESS GOVERNOR FULL! Dropping {}", peer_id);
                    return;
                }
            }
            self.system_governor.record_entry_pressure();

            let _slot_guard = SlotGuard::new(&mut self.ingress_governor, peer_id.clone());

            let (reply_tx, reply_rx) = oneshot::channel();
            let verified_unit = ForensicUnit::<_, Verified>::new_verified(unverified.unpack());

            // T6 FIX: Evidence TTL is fixed from config, not coupled to dynamic tolerance.
            // Dynamic tolerance is only used for staleness checks above.
            let evidence_ttl = Duration::from_secs(self.config.storage.evidence_ttl_secs);

            if self
                .storage_tx
                .send(StorageCommand::Ingest {
                    unit: verified_unit,
                    reply_to: reply_tx,
                    ttl: evidence_ttl,
                })
                .await
                .is_err()
            {
                tracing::error!("Vault disconnected");
                return;
            }

            let vault_response = reply_rx.await;
            drop(_slot_guard);

            match vault_response {
                Ok(Ok(())) => {
                    self.system_governor
                        .record_peer_evidence(&peer_id.to_string(), true);
                }
                Ok(Err(guardian_error)) => {
                    self.system_governor
                        .record_peer_evidence(&peer_id.to_string(), false);
                    self.handle_forensic_violation(sender_did, guardian_error)
                        .await;
                }
                Err(_) => {} // Channel closed
            }
        }
        self.system_governor
            .record_metabolic_pressure(start_cpu.elapsed());
    }

    async fn handle_forensic_violation(&mut self, owner_did: Did, err: GuardianError) {
        let offense = match err {
            GuardianError::VerificationFailed(_) | GuardianError::InvalidSignature(_) => {
                Some(Offense::InvalidSignature)
            }
            GuardianError::QuotaExceeded(_) => Some(Offense::QuotaExceeded),
            GuardianError::ReplayDetected(_) => Some(Offense::ReplayAttack),
            GuardianError::AmbiguousOwnership => None,
            GuardianError::PolicyViolation(_) => Some(Offense::IdentityTheft),
            GuardianError::ChainIntegrityViolation(_) => Some(Offense::ProtocolViolation),
            _ => Some(Offense::ProtocolViolation),
        };

        if let Some(offense_type) = offense {
            let _ = self
                .trust_tx
                .send(TrustCommand::RecordOffense {
                    did: owner_did,
                    offense: offense_type,
                })
                .await;
        }
    }
}

struct SlotGuard<'a> {
    governor: &'a mut IngressGovernor,
    peer_id: NetworkId,
}
impl<'a> SlotGuard<'a> {
    fn new(governor: &'a mut IngressGovernor, peer_id: NetworkId) -> Self {
        Self { governor, peer_id }
    }
}
impl<'a> Drop for SlotGuard<'a> {
    fn drop(&mut self) {
        self.governor.release_slot(&self.peer_id);
    }
}
