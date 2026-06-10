// crates/phalanx-node/src/actors/vitals_actor.rs
//
// Vitals actor. Owns the node's presence cadence — the periodic vitals refresh
// + Tier 2 Shield Wall heartbeat PUBLISH, and the inbound heartbeat RECEIVE
// (per-community decrypt, strict-binding, spectral-consistency evaluation).
// Both halves operate on the same community keyset and the shared
// `Arc<HealthTracker>`, so they live in one cohesive actor (the existing code
// already documents heartbeat publish riding the vitals cadence).
//
// The publish timer is a single pinned sleep, reset ONLY after it fires —
// processing inbound heartbeats must never reset it, or a busy mesh would
// starve our own publish cadence.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, watch};
use tokio::time::{Duration, Instant};

use phalanx_proto::community::CommunityId;
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::identity::MeshAddress;
use phalanx_proto::network::topic::MeshTopic;
use phalanx_proto::vitals::ControlMessage;

use crate::actors::egress::EgressCommand;
use crate::actors::mesh_policy;
use crate::actors::shutdown::ShutdownSignal;
use crate::vitals::health::BroadcastGate;
use crate::vitals::{HealthTracker, SystemGovernor};

/// Commands accepted by the vitals actor.
#[derive(Debug)]
pub enum VitalsCommand {
    /// An inbound heartbeat arrived on the control topic. `origin` is the
    /// libp2p propagation source; `data` is the encrypted frame.
    InboundHeartbeat { origin: MeshAddress, data: Vec<u8> },
}

pub struct VitalsActor {
    // Arc-shared dependencies.
    system_governor: Arc<SystemGovernor>,
    /// The SAME `Arc<HealthTracker>` MeshSentinel exposes — EclipseRouter and
    /// CanarySupervisor read it; this actor writes via `register_activity`.
    health_tracker: Arc<HealthTracker>,
    used_bytes_gauge: Arc<AtomicU64>,

    // Community keyset (clones of MeshSentinel's originals — Canary pattern).
    community_ids_rx: watch::Receiver<Vec<CommunityId>>,
    extra_community_ids: Vec<CommunityId>,

    // Outbound + config snapshots.
    egress_tx: mpsc::Sender<EgressCommand>,
    control_topic: MeshTopic,
    /// The MeshAddress this node claims as `sender` on outbound heartbeats.
    local_mesh_address: MeshAddress,
    /// `config.storage.max_storage_bytes.as_u64()`, captured at construction.
    max_storage_bytes: u64,

    // Inbound + lifecycle.
    rx: mpsc::Receiver<VitalsCommand>,
    shutdown: Arc<ShutdownSignal>,
}

#[allow(clippy::too_many_arguments)] // Spawn-time deps; mirrors the other actors.
impl VitalsActor {
    pub fn new(
        system_governor: Arc<SystemGovernor>,
        health_tracker: Arc<HealthTracker>,
        used_bytes_gauge: Arc<AtomicU64>,
        community_ids_rx: watch::Receiver<Vec<CommunityId>>,
        extra_community_ids: Vec<CommunityId>,
        egress_tx: mpsc::Sender<EgressCommand>,
        control_topic: MeshTopic,
        local_mesh_address: MeshAddress,
        max_storage_bytes: u64,
        rx: mpsc::Receiver<VitalsCommand>,
        shutdown: Arc<ShutdownSignal>,
    ) -> Self {
        Self {
            system_governor,
            health_tracker,
            used_bytes_gauge,
            community_ids_rx,
            extra_community_ids,
            egress_tx,
            control_topic,
            local_mesh_address,
            max_storage_bytes,
            rx,
            shutdown,
        }
    }

    pub async fn run(mut self) {
        let mut gate = BroadcastGate::new();
        // The interval value currently in effect (reported as `heartbeat_ms`).
        let mut interval = self.system_governor.vitals_polling_interval();
        // Single pinned timer — reset only after it fires (NOT on inbound).
        let sleep = tokio::time::sleep(interval);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => break,
                _ = &mut sleep => {
                    self.publish_tick(interval, &mut gate);
                    interval = self.system_governor.vitals_polling_interval();
                    // `Instant::now() + interval` cannot saturate on any
                    // supported platform for 5–60 s vitals intervals.
                    #[allow(clippy::arithmetic_side_effects)]
                    let next = Instant::now() + interval;
                    sleep.as_mut().reset(next);
                }
                Some(cmd) = self.rx.recv() => {
                    self.handle_command(cmd);
                }
                else => break,
            }
        }

        // Post-loop drain: process any inbound heartbeats queued before
        // cancellation (deterministic for tests that assert on HealthTracker
        // after shutdown()).
        while let Ok(cmd) = self.rx.try_recv() {
            self.handle_command(cmd);
        }
    }

    fn handle_command(&mut self, cmd: VitalsCommand) {
        match cmd {
            VitalsCommand::InboundHeartbeat { origin, data } => {
                self.handle_inbound(origin, &data);
            }
        }
    }

    /// Vitals refresh + Tier 2 heartbeat publish. Encrypts one ciphertext per
    /// held community key and publishes on the control topic, gated by
    /// `BroadcastGate` so a stable load suppresses sub-30 s republishes. A node
    /// in no community publishes nothing.
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
    fn publish_tick(&mut self, interval: Duration, gate: &mut BroadcastGate) {
        self.system_governor.update_vitals();
        // CRITICAL: read+clone in a single statement. Watch's `borrow()` returns
        // a `Ref<'_, T>` holding an internal RwLock guard; the `.clone()`
        // releases it immediately.
        let mut snapshot: Vec<CommunityId> = self.community_ids_rx.borrow().clone();
        for cid in &self.extra_community_ids {
            if !snapshot.contains(cid) {
                snapshot.push(*cid);
            }
        }
        if snapshot.is_empty() {
            // Open-mesh-only node: no community keys, no heartbeats.
            return;
        }
        let load = self.system_governor.load_factor();
        if gate.should_broadcast(load) {
            // Compute storage only when actually publishing.
            let used = self.used_bytes_gauge.load(Ordering::Relaxed);
            let remaining_bytes = self.max_storage_bytes.saturating_sub(used);
            // Cap the wire value at u32::MAX MB (~4 PiB) even when uncapped.
            let storage_remaining_mb = (remaining_bytes / 1_048_576).min(u32::MAX as u64);
            // `as_millis()` returns u128, but vitals intervals (5–60 s) fit u64.
            let heartbeat_ms =
                phalanx_proto::vitals::HeartbeatInterval(interval.as_millis() as u64).as_u64();
            let msg = ControlMessage {
                sender: self.local_mesh_address.clone(),
                load_factor: load,
                storage_remaining_mb,
                heartbeat_ms,
                is_leaf: self.system_governor.is_leaf_state(),
                integral_summary: Some(self.system_governor.integral_summary()),
            };
            let plaintext = match postcard::to_allocvec(&msg) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(error = %e, "Heartbeat: serialize failed");
                    return;
                }
            };
            // One ciphertext per community — receivers try-decrypt with each key
            // they hold. Different domain-separation label from canary alerts.
            for cid in &snapshot {
                let key = SymmetricKey::from_bytes(blake3::derive_key(
                    "phalanx.heartbeat.v1.community",
                    &cid.0,
                ));
                let (nonce, ciphertext) =
                    match phalanx_forensics::cryptography::encrypt_bytes(&key, &plaintext) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(error = %e, "Heartbeat: encryption failed");
                            continue;
                        }
                    };
                let mut payload = nonce;
                payload.extend(ciphertext);
                let _ = self.egress_tx.try_send(EgressCommand::PublishMesh {
                    topic: self.control_topic.clone(),
                    data: payload,
                });
            }
        }
    }

    /// Heartbeat receiver: decrypt with each held community key, then apply the
    /// strict-binding origin check (decrypted body's claimed sender must equal
    /// the libp2p propagation source). On success, register activity and
    /// evaluate spectral consistency.
    fn handle_inbound(&mut self, origin: MeshAddress, data: &[u8]) {
        // Min frame: 24-byte XChaCha20 nonce + 16-byte Poly1305 tag.
        if data.len() < 40 {
            return;
        }
        let (nonce, ciphertext) = data.split_at(24);

        // Live-snapshot the keyset (registry watch + static extras). Reads
        // current state per inbound message, so a community dissolved at
        // runtime stops being decryptable on the next heartbeat.
        for cid in
            &mesh_policy::current_community_ids(&self.community_ids_rx, &self.extra_community_ids)
        {
            let key = SymmetricKey::from_bytes(blake3::derive_key(
                "phalanx.heartbeat.v1.community",
                &cid.0,
            ));
            let Ok(plaintext) =
                phalanx_forensics::cryptography::decrypt_bytes(&key, nonce, ciphertext)
            else {
                // Wrong key for this ciphertext — try the next community.
                continue;
            };
            let Ok(msg) =
                phalanx_forensics::gate::unmarshal::<ControlMessage>(&plaintext, "control_message")
            else {
                tracing::warn!(
                    target: "phalanx::shield_wall",
                    "Heartbeat decrypted but failed to deserialize"
                );
                return;
            };
            if msg.sender != origin {
                tracing::warn!(
                    target: "phalanx::shield_wall",
                    event = "control_message_origin_mismatch",
                    claimed = %msg.sender,
                    origin = %origin,
                    "Heartbeat sender != propagation origin — dropping"
                );
                // Do NOT record a Trust offense on `origin` — honest relays
                // forward adversary-authored spoofs; punishing the relay lets
                // attackers frame any peer in the mesh.
                return;
            }
            let peer_id_for_spectral = origin.clone();
            self.health_tracker.register_activity(msg);

            // Shield Wall: evaluate spectral consistency.
            if let Some(residual) = self.health_tracker.evaluate_spectral(&peer_id_for_spectral) {
                if residual > self.health_tracker.spectral_anomaly_threshold() {
                    self.system_governor
                        .record_spectral_anomaly(&peer_id_for_spectral.to_string(), residual);
                    tracing::warn!(
                        target: "phalanx::shield_wall",
                        peer = %peer_id_for_spectral,
                        residual = %residual,
                        "SPECTRAL_ANOMALY_DETECTED"
                    );
                }
            }
            return;
        }
        // No held community key decrypts — silent drop.
    }
}
