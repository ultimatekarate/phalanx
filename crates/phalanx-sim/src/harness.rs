// crates/phalanx-sim/src/harness.rs
//
// The "Pen": The simulation author's API for writing simulation scripts.
// Spawns real MeshSentinel instances backed by virtual transport (SimIngress/SimEgress),
// with chaos injection, deterministic time, and telemetry collection.

use crate::clock::VirtualClock;
use crate::world::SimulationWorld;

use phalanx_forensics::policy::Homeostasis;
use phalanx_node::actors::meshsentinel::{MeshSentinel, SentinelDependencies};
use phalanx_node::config::NodeConfig;
use phalanx_node::persistence::vault::derive_vault_key;
use phalanx_node::trust::TrustRegistry;
use phalanx_node::vitals::SystemGovernor;
use phalanx_proto::identity::{NetworkId, NodeRole, PhalanxIdentity, RecordingId};
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::network::{EgressPort, IngressPort};
use phalanx_proto::prelude::*;
use phalanx_proto::storage::{PendingEgress, TransientJournal};
use phalanx_proto::telemetry::{ChaosMode, DiscoverySource, SimEvent};
use phalanx_transport::adapters::local_mesh::LocalMeshAdapter;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

// ===========================================================================
//  SimIngress — IngressPort adapter for simulated nodes
// ===========================================================================

/// Virtual ingress port that receives events from the simulation routing mesh.
/// Each simulated node gets its own `SimIngress` wrapping an `mpsc::Receiver`.
pub struct SimIngress {
    rx: mpsc::Receiver<NetworkEvent>,
}

#[async_trait::async_trait]
impl IngressPort for SimIngress {
    async fn next_event(&mut self) -> Option<NetworkEvent> {
        self.rx.recv().await
    }
}

// ===========================================================================
//  SimEgress — EgressPort adapter for simulated nodes
// ===========================================================================

/// Virtual egress port that routes publishes through the SimulationWorld.
/// Each node gets a clone with its own `source_did`/`source_network_id`.
/// The shared `Arc<RwLock<SimulationWorld>>` handles routing and chaos filtering.
#[derive(Clone)]
pub struct SimEgress {
    world: Arc<RwLock<SimulationWorld>>,
    source_did: Did,
    source_network_id: NetworkId,
    telemetry_tx: mpsc::Sender<SimEvent>,
}

#[async_trait::async_trait]
impl EgressPort for SimEgress {
    async fn publish(&self, topic: &MeshTopic, data: Vec<u8>) -> Result<(), String> {
        let world = self.world.read().await;
        world
            .route_publish(
                &self.source_did,
                self.source_network_id.clone(),
                topic.clone(),
                data.clone(),
            )
            .await?;

        // Best-effort telemetry: emit ShardPublished if the bytes deserialize as a ShardChunk.
        // Don't block the data path for telemetry — skip if deserialization fails.
        if let Ok(chunk) = postcard::from_bytes::<ShardChunk>(&data) {
            let _ = self
                .telemetry_tx
                .send(SimEvent::ShardPublished {
                    origin: self.source_network_id.clone(),
                    chunk,
                })
                .await;
        }

        Ok(())
    }

    async fn ban_peer(&self, peer: &NetworkId) {
        // Mirror the MockTransport telemetry pattern (mock.rs:64-77)
        let event = SimEvent::AttackAttemptBlocked {
            attacker: peer.clone(),
            target: self.source_network_id.clone(),
            reason: "Peer blacklisted by SimEgress policy".to_string(),
        };
        let _ = self.telemetry_tx.send(event).await;
    }

    async fn send_response(
        &self,
        _channel_id: &str,
        _response: RecordingResponse,
    ) -> Result<(), String> {
        // No-op in simulation — retrieval responses are not routed through the mesh
        Ok(())
    }

    async fn announce_recording(&self, _recording_id: &RecordingId) -> Result<(), String> {
        // No-op in simulation — DHT announcements are not simulated yet
        Ok(())
    }

    async fn find_providers(&self, _recording_id: &RecordingId) -> Result<(), String> {
        // No-op in simulation — DHT provider queries are not simulated yet
        Ok(())
    }

    async fn send_request(
        &self,
        _target: &NetworkId,
        _request: phalanx_proto::retrieval::RecordingRequest,
    ) -> Result<(), String> {
        // No-op in simulation — direct shard retrieval not simulated yet
        Ok(())
    }
}

// ===========================================================================
//  TelemetryCollector — Queryable event aggregator
// ===========================================================================

/// Per-node telemetry metrics, aggregated by the TelemetryCollector.
#[derive(Debug, Clone, Default)]
pub struct NodeMetrics {
    pub chunks_ingested: u64,
    pub bytes_processed: u64,
    pub shards_published: u64,
    pub attacks_blocked: u64,
}

/// Collects and aggregates SimEvents for post-simulation analysis.
///
/// Spawns a background task that consumes all events from the telemetry channel
/// and sorts them into queryable data structures. The harness and tests can
/// query aggregated metrics, filter events, or wait for specific event patterns.
pub struct TelemetryCollector {
    events: Arc<RwLock<Vec<(Instant, SimEvent)>>>,
    node_metrics: Arc<RwLock<HashMap<NetworkId, NodeMetrics>>>,
    /// Tracks the last event index consumed by `drain_new()`.
    /// Used by the dashboard to process only new events each frame.
    last_drained: Arc<tokio::sync::Mutex<usize>>,
}

impl TelemetryCollector {
    /// Spawn a background consumer task that reads from the telemetry channel
    /// and populates the internal metrics maps.
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Counter increments and byte-length casts in telemetry aggregation.
    pub fn spawn(mut rx: mpsc::Receiver<SimEvent>) -> Self {
        let events = Arc::new(RwLock::new(Vec::new()));
        let node_metrics = Arc::new(RwLock::new(HashMap::new()));

        let events_clone = events.clone();
        let metrics_clone = node_metrics.clone();

        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                let now = Instant::now();

                // Update per-node metrics
                {
                    let mut metrics = metrics_clone.write().await;
                    match &event {
                        SimEvent::ChunkIngested { origin, chunk } => {
                            let m: &mut NodeMetrics = metrics.entry(origin.clone()).or_default();
                            m.chunks_ingested += 1;
                            m.bytes_processed += chunk.data.len() as u64;
                        }
                        SimEvent::ShardPublished { origin, chunk } => {
                            let m: &mut NodeMetrics = metrics.entry(origin.clone()).or_default();
                            m.shards_published += 1;
                            m.bytes_processed += chunk.data.len() as u64;
                        }
                        SimEvent::AttackAttemptBlocked { target, .. } => {
                            let m: &mut NodeMetrics = metrics.entry(target.clone()).or_default();
                            m.attacks_blocked += 1;
                        }
                        _ => {}
                    }
                }

                // Store the timestamped event
                events_clone.write().await.push((now, event));
            }
        });

        Self {
            events,
            node_metrics,
            last_drained: Arc::new(tokio::sync::Mutex::new(0)),
        }
    }

    /// Wait for an event matching the predicate, with timeout.
    ///
    /// Polls the event log at 10ms intervals until the predicate matches
    /// or the timeout expires. Returns the first matching event, or `None`.
    ///
    /// # Example
    /// ```ignore
    /// let attack = collector.wait_for(
    ///     |e| matches!(e, SimEvent::AttackAttemptBlocked { .. }),
    ///     Duration::from_secs(2),
    /// ).await;
    /// assert!(attack.is_some(), "Expected attack to be blocked");
    /// ```
    pub async fn wait_for<F>(&self, predicate: F, timeout: Duration) -> Option<SimEvent>
    where
        F: Fn(&SimEvent) -> bool,
    {
        #[allow(clippy::arithmetic_side_effects)] // Deadline = now + timeout.
        let deadline = Instant::now() + timeout;
        let mut last_checked = 0;

        loop {
            {
                let events = self.events.read().await;
                for (_, event) in events.iter().skip(last_checked) {
                    if predicate(event) {
                        return Some(event.clone());
                    }
                }
                last_checked = events.len();
            }

            if Instant::now() >= deadline {
                return None;
            }

            // Yield to let the background consumer process more events
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Snapshot of all events received so far.
    pub async fn events(&self) -> Vec<SimEvent> {
        self.events
            .read()
            .await
            .iter()
            .map(|(_, e)| e.clone())
            .collect()
    }

    /// All attack events: (attacker, target, reason).
    pub async fn attacks(&self) -> Vec<(NetworkId, NetworkId, String)> {
        self.events
            .read()
            .await
            .iter()
            .filter_map(|(_, e)| {
                if let SimEvent::AttackAttemptBlocked {
                    attacker,
                    target,
                    reason,
                } = e
                {
                    Some((attacker.clone(), target.clone(), reason.clone()))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Per-node aggregated metrics.
    pub async fn node_stats(&self, network_id: &NetworkId) -> NodeMetrics {
        self.node_metrics
            .read()
            .await
            .get(network_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Total bytes processed across all nodes.
    pub async fn total_bytes_processed(&self) -> u64 {
        self.node_metrics
            .read()
            .await
            .values()
            .map(|m| m.bytes_processed)
            .sum()
    }

    /// Human-readable telemetry summary.
    #[allow(clippy::arithmetic_side_effects)] // Counter increments in event aggregation.
    pub async fn summary(&self) -> String {
        let events = self.events.read().await;
        let metrics = self.node_metrics.read().await;

        let mut event_counts: HashMap<&str, usize> = HashMap::new();
        for (_, event) in events.iter() {
            let key = match event {
                SimEvent::ChunkIngested { .. } => "ChunkIngested",
                SimEvent::Heartbeat { .. } => "Heartbeat",
                SimEvent::OffloadComplete { .. } => "OffloadComplete",
                SimEvent::PeerDiscovered { .. } => "PeerDiscovered",
                SimEvent::ShardProcessed { .. } => "ShardProcessed",
                SimEvent::CrucibleFinalized { .. } => "CrucibleFinalized",
                SimEvent::AttackAttemptBlocked { .. } => "AttackAttemptBlocked",
                SimEvent::SystemStressUpdate(_) => "SystemStressUpdate",
                SimEvent::Shutdown => "Shutdown",
                SimEvent::ChaosUpdate { .. } => "ChaosUpdate",
                SimEvent::ShardPublished { .. } => "ShardPublished",
            };
            *event_counts.entry(key).or_insert(0) += 1;
        }

        let total_bytes: u64 = metrics.values().map(|m| m.bytes_processed).sum();
        let total_attacks: u64 = metrics.values().map(|m| m.attacks_blocked).sum();
        let node_count = metrics.len();

        let mut summary = format!(
            "=== Simulation Telemetry Summary ===\n\
            Nodes observed: {}\n\
            Total events: {}\n\
            Total bytes processed: {}\n\
            Total attacks blocked: {}\n\
            \n\
            Event breakdown:\n",
            node_count,
            events.len(),
            total_bytes,
            total_attacks,
        );

        // Sort event types for deterministic output
        let mut sorted_counts: Vec<_> = event_counts.into_iter().collect();
        sorted_counts.sort_by_key(|(k, _)| *k);
        for (event_type, count) in sorted_counts {
            summary.push_str(&format!("  {}: {}\n", event_type, count));
        }

        if !metrics.is_empty() {
            summary.push_str("\nPer-node metrics:\n");
            let mut sorted_nodes: Vec<_> = metrics.iter().collect();
            sorted_nodes.sort_by_key(|(id, _)| id.0.clone());
            for (network_id, m) in sorted_nodes {
                summary.push_str(&format!(
                    "  {}: chunks={}, shards={}, bytes={}, attacks_blocked={}\n",
                    network_id,
                    m.chunks_ingested,
                    m.shards_published,
                    m.bytes_processed,
                    m.attacks_blocked,
                ));
            }
        }

        summary
    }

    /// Drain events received since the last call to `drain_new()`.
    ///
    /// Returns a batch of new events for processing. Used by the dashboard
    /// to consume events in a non-blocking loop (replaces `try_recv()` on
    /// the raw channel).
    ///
    /// ```ignore
    /// // Dashboard main loop:
    /// for event in collector.drain_new().await {
    ///     state.ingest_telemetry(event);
    /// }
    /// ```
    pub async fn drain_new(&self) -> Vec<SimEvent> {
        let events = self.events.read().await;
        let mut last = self.last_drained.lock().await;
        let new_events: Vec<SimEvent> = events
            .get(*last..)
            .unwrap_or_default()
            .iter()
            .map(|(_, e)| e.clone())
            .collect();
        *last = events.len();
        new_events
    }
}

// ===========================================================================
//  RecoveryJournal — Mock journal for simulated state recovery
// ===========================================================================

/// A mock journal used to simulate state recovery from salvaged egress data.
pub struct RecoveryJournal(Vec<PendingEgress>);

impl RecoveryJournal {
    /// Constructs a RecoveryJournal with a predefined set of pending egress events.
    pub fn new(initial_egress: Vec<PendingEgress>) -> Self {
        Self(initial_egress)
    }
}

#[async_trait::async_trait]
impl TransientJournal for RecoveryJournal {
    async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError> {
        Ok(self.0.clone())
    }

    async fn record_pending_egress(&mut self, _: &[PendingEgress]) -> Result<(), ShardError> {
        Ok(())
    }

    async fn record_chunk(&mut self, _: &ShardChunk) -> Result<(), ShardError> {
        Ok(())
    }

    async fn sync(&mut self) -> Result<(), ShardError> {
        Ok(())
    }

    async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError> {
        Ok(vec![])
    }

    async fn clear(&mut self) -> Result<(), ShardError> {
        Ok(())
    }

    async fn record_workbench_state(&mut self, _: &[u8]) -> Result<(), ShardError> {
        Ok(())
    }

    async fn read_workbench_state(&mut self) -> Result<Vec<u8>, ShardError> {
        Ok(vec![])
    }
}

// ===========================================================================
//  SimulationHarness — The simulation author's API
// ===========================================================================

/// Configuration for a simulation run.
pub struct SimConfig;

/// The simulation author's API for writing simulation scripts.
///
/// Spawns real `MeshSentinel` instances backed by virtual transport adapters
/// (`SimIngress`/`SimEgress`), with chaos injection, deterministic time control,
/// and telemetry collection for post-simulation analysis.
///
/// # Example
///
/// ```ignore
/// let config = NodeConfig::test_defaults();
/// let physics = PhalanxPhysics::test_profile();
///
/// let (mut harness, collector) = SimulationHarness::init_mesh(config, physics);
///
/// let node_a = harness.spawn_node("Guardian-A", NodeRole::Guardian).await.unwrap();
/// let node_b = harness.spawn_node("Stronghold-B", NodeRole::Stronghold).await.unwrap();
///
/// // Inject chaos: 50% packet loss on node A
/// harness.inject_chaos(&node_a, ChaosMode::PacketLoss(0.5)).await;
///
/// // Advance time to trigger actor heartbeats
/// harness.advance_time(Duration::from_secs(10)).await;
///
/// // Analyze telemetry
/// println!("{}", collector.summary().await);
/// ```
pub struct SimulationHarness {
    config: NodeConfig,
    #[allow(dead_code)]
    physics: crate::physics::PhalanxPhysics,
    world: Arc<RwLock<SimulationWorld>>,
    telemetry_tx: mpsc::Sender<SimEvent>,
    /// Keep temp dirs alive for the duration of the simulation.
    /// Each node gets a unique vault_path via `tempfile::tempdir()`.
    node_temps: Vec<tempfile::TempDir>,
    /// Per-node governor references for scenario observation and direct injection.
    governors: HashMap<Did, Arc<SystemGovernor>>,
}

impl SimulationHarness {
    /// Initialize the simulation mesh.
    ///
    /// Creates the shared `SimulationWorld`, telemetry channel, and spawns the
    /// `TelemetryCollector`. Pauses tokio time for deterministic control.
    ///
    /// Returns `(harness, collector)` — the harness for controlling the simulation,
    /// and the collector for querying telemetry.
    pub fn init_mesh(
        config: NodeConfig,
        physics: crate::physics::PhalanxPhysics,
    ) -> (Self, TelemetryCollector) {
        VirtualClock::pause();

        let (telemetry_tx, telemetry_rx) = mpsc::channel(4096);
        let collector = TelemetryCollector::spawn(telemetry_rx);

        let harness = Self {
            config,
            physics,
            world: Arc::new(RwLock::new(SimulationWorld::new())),
            telemetry_tx,
            node_temps: Vec::new(),
            governors: HashMap::new(),
        };

        (harness, collector)
    }

    /// Spawn a simulated node backed by a full `MeshSentinel` actor system.
    ///
    /// Generates an ephemeral identity, creates virtual transport adapters,
    /// wires them into the simulation world routing table, and spawns the
    /// sentinel's actor constellation (StorageActor, IngestionActor, EgressActor, etc.).
    ///
    /// Returns the node's `Did` for use with `inject_event()`, `inject_chaos()`, etc.
    pub async fn spawn_node(
        &mut self,
        name: &str,
        role: NodeRole,
    ) -> Result<Did, Box<dyn std::error::Error + Send + Sync>> {
        let identity = PhalanxIdentity::new_ephemeral();
        let node_did = identity.did.clone();
        let network_id = identity.network_id.clone();

        // Each node gets its own temp directory for vault storage
        let temp_dir = tempfile::tempdir()?;
        let mut node_config = self.config.clone();
        node_config.storage.vault_path = temp_dir.path().to_string_lossy().to_string();
        self.node_temps.push(temp_dir);

        // Create virtual transport channels
        let (ingress_tx, ingress_rx) = mpsc::channel::<NetworkEvent>(4096);

        // Register in the simulation world
        {
            let mut world = self.world.write().await;
            world.register_node(node_did.clone(), network_id.clone(), ingress_tx);
        }

        tracing::info!(
            node = %name,
            did = %node_did,
            network_id = %network_id,
            "Spawning simulated node"
        );

        // Build transport adapters
        let sim_ingress = SimIngress { rx: ingress_rx };
        let sim_egress = SimEgress {
            world: self.world.clone(),
            source_did: node_did.clone(),
            source_network_id: network_id.clone(),
            telemetry_tx: self.telemetry_tx.clone(),
        };

        // Build the full MeshSentinel actor constellation
        let vault_key = derive_vault_key(&identity, &[0u8; 32]);
        let trust_registry = TrustRegistry::build(&node_config).await;

        let governor = Arc::new(SystemGovernor::new());
        self.governors.insert(node_did.clone(), governor.clone());

        let deps = SentinelDependencies {
            config: node_config,
            identity,
            ingress: sim_ingress,
            egress: sim_egress,
            journal: RecoveryJournal::new(vec![]),
            trust_registry,
            system_governor: governor,
            vault_key,
            local_mesh: None,
        };

        let mut sentinel = MeshSentinel::new(deps).await.map_err(
            |e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("Failed to initialize MeshSentinel: {}", e).into()
            },
        )?;

        // Detach sentinel execution
        tokio::spawn(async move {
            if let Err(e) = sentinel.run().await {
                tracing::error!(error = %e, "Simulation node terminated unexpectedly");
            }
        });

        // Emit telemetry: PeerDiscovered
        let _ = self
            .telemetry_tx
            .send(SimEvent::PeerDiscovered {
                peer: network_id,
                source: DiscoverySource::Bootstrap,
                role,
            })
            .await;

        Ok(node_did)
    }

    /// Resolve a node's forensic NetworkId from its DID.
    pub async fn resolve_did(
        &self,
        did: &Did,
    ) -> Result<NetworkId, Box<dyn std::error::Error + Send + Sync>> {
        let world = self.world.read().await;
        world
            .lookup_network_id(did)
            .ok_or_else(|| format!("Node {} not found in simulation world", did).into())
    }

    /// Inject a chaos mode for a specific node.
    ///
    /// Affects the node's outbound traffic (publishes routed through `SimulationWorld`).
    /// Takes effect immediately — the next `publish()` from this node will be filtered.
    pub async fn inject_chaos(&mut self, did: &Did, mode: ChaosMode) {
        {
            let mut world = self.world.write().await;
            world.chaos_registry.insert(did.clone(), mode);
        }

        // Resolve NetworkId for telemetry
        let network_id = {
            let world = self.world.read().await;
            world
                .lookup_network_id(did)
                .unwrap_or_else(|| NetworkId::from("unknown"))
        };

        tracing::info!(
            node = %did,
            mode = ?mode,
            "Chaos parameters updated"
        );

        // Emit telemetry: ChaosUpdate
        let _ = self
            .telemetry_tx
            .send(SimEvent::ChaosUpdate {
                target: network_id,
                mode,
            })
            .await;
    }

    /// Inject a network event directly into a node's ingress channel.
    ///
    /// Bypasses the SimEgress routing mesh — the event arrives as if it came
    /// from the network. Essential for attack simulation (injecting tampered
    /// envelopes that wouldn't pass through normal routing).
    pub async fn inject_event(
        &self,
        did: &Did,
        event: NetworkEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Model transport-layer bandwidth measurement for DataReceived events.
        // In production, IoCounters on the vitals tick capture wire bytes.
        // In simulation, we measure payload size directly.
        if let NetworkEvent::DataReceived { ref data, .. } = event {
            if let Some(governor) = self.governors.get(did) {
                governor.record_bandwidth_pressure(data.len());
            }
        }

        let world = self.world.read().await;
        let tx = world
            .ingress_routes
            .get(did)
            .ok_or_else(|| format!("Node {} not found in simulation routing table", did))?;

        tx.send(event).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Simulate total transport failure for a node.
    ///
    /// Sets the node's chaos mode to `Byzantine`, causing all outbound
    /// publishes to be silently dropped.
    pub async fn inject_transport_failure(&mut self, did: &Did) {
        self.inject_chaos(did, ChaosMode::Byzantine).await;
    }

    /// Advance virtual time by the given duration.
    ///
    /// Triggers all pending `tokio::time::sleep()` and `interval()` timers
    /// that would fire within the given duration. Use this to drive actor
    /// heartbeats, retry ticks, and cleanup intervals deterministically.
    pub async fn advance_time(&self, duration: Duration) {
        VirtualClock::advance(duration).await;
    }

    /// Spawn a simulated node with a `LocalMeshAdapter` wired in.
    ///
    /// Same as `spawn_node()` but creates a `LocalMeshAdapter` channel bridge
    /// and passes it into `SentinelDependencies`. Returns both the node's `Did`
    /// and an `mpsc::Sender<NetworkEvent>` so test scripts can inject local mesh
    /// events (BLE discovery, data received, peer disconnected) directly.
    pub async fn spawn_node_with_local_mesh(
        &mut self,
        name: &str,
        role: NodeRole,
    ) -> Result<(Did, mpsc::Sender<NetworkEvent>), Box<dyn std::error::Error + Send + Sync>> {
        let identity = PhalanxIdentity::new_ephemeral();
        let node_did = identity.did.clone();
        let network_id = identity.network_id.clone();
        let node_config = NodeConfig::default();

        // Create the ingress channel for simulated network events
        let (ingress_tx, ingress_rx) = mpsc::channel(256);

        // Register in the simulation world routing table
        {
            let mut world = self.world.write().await;
            world.register_node(node_did.clone(), network_id.clone(), ingress_tx);
        }

        tracing::info!(
            node = %name,
            did = %node_did,
            network_id = %network_id,
            "Spawning simulated node with local mesh"
        );

        // Build transport adapters
        let sim_ingress = SimIngress { rx: ingress_rx };
        let sim_egress = SimEgress {
            world: self.world.clone(),
            source_did: node_did.clone(),
            source_network_id: network_id.clone(),
            telemetry_tx: self.telemetry_tx.clone(),
        };

        // Local mesh adapter — channel bridge for test injection
        let (local_mesh_adapter, local_mesh_tx, _outbound_rx, _available) =
            LocalMeshAdapter::new(64);

        // Build the full MeshSentinel actor constellation
        let vault_key = derive_vault_key(&identity, &[0u8; 32]);
        let trust_registry = TrustRegistry::build(&node_config).await;

        let governor = Arc::new(SystemGovernor::new());
        self.governors.insert(node_did.clone(), governor.clone());

        let deps = SentinelDependencies {
            config: node_config,
            identity,
            ingress: sim_ingress,
            egress: sim_egress,
            journal: RecoveryJournal::new(vec![]),
            trust_registry,
            system_governor: governor,
            vault_key,
            local_mesh: Some(Box::new(local_mesh_adapter)),
        };

        let mut sentinel = MeshSentinel::new(deps).await.map_err(
            |e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("Failed to initialize MeshSentinel: {}", e).into()
            },
        )?;

        // Detach sentinel execution
        tokio::spawn(async move {
            if let Err(e) = sentinel.run().await {
                tracing::error!(error = %e, "Simulation node terminated unexpectedly");
            }
        });

        // Emit telemetry: PeerDiscovered
        let _ = self
            .telemetry_tx
            .send(SimEvent::PeerDiscovered {
                peer: network_id,
                source: DiscoverySource::Bootstrap,
                role,
            })
            .await;

        Ok((node_did, local_mesh_tx))
    }

    /// Retrieve the `SystemGovernor` for a spawned node.
    ///
    /// Returns `None` if the DID doesn't correspond to a node spawned by this harness.
    /// Used by scenario tests to observe integral state and inject pressure via the
    /// `Homeostasis` trait.
    pub fn governor_for(&self, did: &Did) -> Option<Arc<SystemGovernor>> {
        self.governors.get(did).cloned()
    }
}
