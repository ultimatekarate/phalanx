#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
// Shared integration-test fixtures for `phalanx-node` tests.
//
// Cargo compiles each file in `tests/` as its own binary, which means every
// consumer that wants `build_test_sentinel` must `mod common;` — this module
// is not published on the library's public surface.

use phalanx_node::actors::meshsentinel::{MeshSentinel, SentinelDependencies};
use phalanx_node::actors::storage::NoOpJournal;
use phalanx_node::config::NodeConfig;
use phalanx_node::persistence::vault::derive_vault_key;
use phalanx_node::trust::TrustRegistry;
use phalanx_node::vitals::SystemGovernor;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::identity::{MeshAddress, PhalanxIdentity, RecordingId};
use phalanx_proto::network::{EgressPort, IngressPort, NetworkEvent};
use phalanx_proto::prelude::{MeshTopic, RecordingResponse};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

pub struct TestIngress {
    ingress_rx: mpsc::Receiver<NetworkEvent>,
}

impl TestIngress {
    pub fn new(ingress_rx: mpsc::Receiver<NetworkEvent>) -> Self {
        Self { ingress_rx }
    }
}

#[async_trait::async_trait]
impl IngressPort for TestIngress {
    async fn next_event(&mut self) -> Option<NetworkEvent> {
        self.ingress_rx.recv().await
    }
}

#[derive(Clone)]
pub struct TestEgress;

#[async_trait::async_trait]
impl EgressPort for TestEgress {
    async fn publish(&self, _topic: &MeshTopic, _data: Vec<u8>) -> Result<(), String> {
        Ok(())
    }
    async fn ban_peer(&self, _peer: &MeshAddress) {}
    async fn send_response(
        &self,
        _channel_id: &str,
        _response: RecordingResponse,
    ) -> Result<(), String> {
        Ok(())
    }
    async fn announce_recording(&self, _recording_id: &RecordingId) -> Result<(), String> {
        Ok(())
    }
    async fn find_providers(&self, _recording_id: &RecordingId) -> Result<(), String> {
        Ok(())
    }
    async fn send_request(
        &self,
        _target: &MeshAddress,
        _request: phalanx_proto::retrieval::RecordingRequest,
    ) -> Result<(), String> {
        Ok(())
    }
}

/// Stateful `EgressPort` that simulates a peer on the mesh by synthesizing
/// `NetworkEvent` responses through the test's ingress channel.
///
/// Two interception points mirror the production wiring at
/// [meshsentinel.rs's discovery_rx select arm] and
/// [EgressActor::handle_find_providers / handle_request_shards]:
///
/// - `find_providers` → pushes `NetworkEvent::ProvidersDiscovered`
///   with a single synthetic peer (the `synthetic_peer` address).
/// - `send_request` → looks up the recording in `seeded_shards`; if
///   present, pushes `NetworkEvent::ShardResponseReceived` carrying the
///   seeded envelopes. If absent, no-op (lets tests assert "no shards
///   available" if they want).
///
/// Call-count probes (`find_providers_calls`, `send_request_calls`) let
/// tests assert the chain actually fired through mesh rather than
/// accidentally hitting some other code path.
#[derive(Clone)]
pub struct MeshTestEgress {
    pub(crate) ingress_tx: mpsc::Sender<NetworkEvent>,
    pub(crate) seeded_shards: Arc<Mutex<HashMap<RecordingId, Vec<WitnessEnvelope>>>>,
    pub(crate) synthetic_peer: MeshAddress,
    pub find_providers_calls: Arc<AtomicU32>,
    pub send_request_calls: Arc<AtomicU32>,
}

impl MeshTestEgress {
    pub fn new(
        ingress_tx: mpsc::Sender<NetworkEvent>,
        seeded_shards: HashMap<RecordingId, Vec<WitnessEnvelope>>,
        synthetic_peer: MeshAddress,
    ) -> Self {
        Self {
            ingress_tx,
            seeded_shards: Arc::new(Mutex::new(seeded_shards)),
            synthetic_peer,
            find_providers_calls: Arc::new(AtomicU32::new(0)),
            send_request_calls: Arc::new(AtomicU32::new(0)),
        }
    }
}

#[async_trait::async_trait]
impl EgressPort for MeshTestEgress {
    async fn publish(&self, _topic: &MeshTopic, _data: Vec<u8>) -> Result<(), String> {
        Ok(())
    }
    async fn ban_peer(&self, _peer: &MeshAddress) {}
    async fn send_response(
        &self,
        _channel_id: &str,
        _response: RecordingResponse,
    ) -> Result<(), String> {
        Ok(())
    }
    async fn announce_recording(&self, _recording_id: &RecordingId) -> Result<(), String> {
        Ok(())
    }
    async fn find_providers(&self, recording_id: &RecordingId) -> Result<(), String> {
        self.find_providers_calls.fetch_add(1, Ordering::Release);
        // Best-effort: ingress channel closing during teardown is benign.
        let _ = self
            .ingress_tx
            .send(NetworkEvent::ProvidersDiscovered {
                recording_id: recording_id.clone(),
                providers: vec![self.synthetic_peer.clone()],
            })
            .await;
        Ok(())
    }
    async fn send_request(
        &self,
        target: &MeshAddress,
        request: phalanx_proto::retrieval::RecordingRequest,
    ) -> Result<(), String> {
        self.send_request_calls.fetch_add(1, Ordering::Release);
        let envelopes = {
            let guard = self.seeded_shards.lock().unwrap_or_else(|e| e.into_inner());
            guard.get(&request.recording_id).cloned()
        };
        if let Some(envelopes) = envelopes {
            let _ = self
                .ingress_tx
                .send(NetworkEvent::ShardResponseReceived {
                    origin: target.clone(),
                    envelopes,
                })
                .await;
        }
        Ok(())
    }
}

/// Returned by `build_mesh_test_deps`. Bundles everything the test needs
/// to drive the engine: the deps for `UnspawnedEngine::build`, the
/// tempdir that backs the vault path (must outlive the engine), the
/// ingress sender for any extra synthesized events, and the
/// `MeshTestEgress`'s call counters for chain-fired assertions.
pub struct MeshTestDeps {
    pub deps: SentinelDependencies<TestIngress, MeshTestEgress, NoOpJournal>,
    pub temp: tempfile::TempDir,
    pub ingress_tx: mpsc::Sender<NetworkEvent>,
    pub find_providers_calls: Arc<AtomicU32>,
    pub send_request_calls: Arc<AtomicU32>,
}

/// Build `SentinelDependencies` wired up with `MeshTestEgress` for
/// mesh-fallback end-to-end tests. Mirrors `build_test_deps` from
/// `engine_facade.rs` but with three differences:
///   (a) `egress: MeshTestEgress` instead of `TestEgress`;
///   (b) accepts a `peer_identity` whose `MeshAddress` becomes the
///       synthetic provider (must be distinct from the local node's
///       identity so `handle_providers_discovered`'s self-filter
///       doesn't drop it);
///   (c) sizes the ingress channel at 8 (vs `build_test_deps`'s 1) so
///       back-to-back synthesized events from `find_providers` and
///       `send_request` don't block each other.
pub async fn build_mesh_test_deps(
    seeded_shards: HashMap<RecordingId, Vec<WitnessEnvelope>>,
    peer_identity: &PhalanxIdentity,
) -> MeshTestDeps {
    let temp = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::default();
    config.storage.vault_path = temp.path().to_string_lossy().to_string();

    let (ingress_tx, ingress_rx) = mpsc::channel(8);

    let identity = PhalanxIdentity::new_ephemeral();
    let vault_key = derive_vault_key(&identity, &[0u8; 32]);
    let dek_master = identity.dek_master.clone();
    let trust_registry = TrustRegistry::build(&config).await;

    let mesh_identity_address =
        phalanx_transport::identity_ext::Libp2pExt::to_mesh_address(&identity);
    let synthetic_peer = phalanx_transport::identity_ext::Libp2pExt::to_mesh_address(peer_identity);

    let mesh_egress = MeshTestEgress::new(ingress_tx.clone(), seeded_shards, synthetic_peer);
    let find_providers_calls = mesh_egress.find_providers_calls.clone();
    let send_request_calls = mesh_egress.send_request_calls.clone();

    let deps = SentinelDependencies {
        config,
        identity,
        ingress: TestIngress::new(ingress_rx),
        egress: mesh_egress,
        journal: NoOpJournal,
        trust_registry,
        system_governor: Arc::new(SystemGovernor::new()),
        vault_key,
        dek_master,
        prnu_posterior: Arc::new(std::sync::Mutex::new(
            phalanx_proto::evidence::PrnuPosterior::new_uninformed(),
        )),
        extra_community_ids: Vec::new(),
        mesh_identity_address,
    };

    MeshTestDeps {
        deps,
        temp,
        ingress_tx,
        find_providers_calls,
        send_request_calls,
    }
}

/// Build a fully-wired `MeshSentinel<TestIngress>` backed by `TestEgress` and
/// a `NoOpJournal`, rooted at a tempdir returned alongside the sentinel. The
/// tempdir is returned so callers can keep it alive for the sentinel's
/// lifetime — dropping it mid-test would pull the vault path out from under
/// the actor.
pub async fn build_test_sentinel(
    ingress_rx: mpsc::Receiver<NetworkEvent>,
) -> (MeshSentinel<TestIngress>, tempfile::TempDir) {
    build_test_sentinel_with_communities(ingress_rx, Vec::new()).await
}

/// Same as `build_test_sentinel`, but seeds the sentinel with static
/// community-id extras at construction time. Use this when a test needs the
/// receive-side decryption path (community heartbeats / canary alerts) to
/// recognise a community without standing up a full `TrustRegistry::Community`.
/// Constructor-time injection is required: the corresponding `Vec` is also
/// cloned into `CanarySupervisor` at spawn, so post-construction field
/// mutation would not reach the canary actor.
pub async fn build_test_sentinel_with_communities(
    ingress_rx: mpsc::Receiver<NetworkEvent>,
    extra_community_ids: Vec<phalanx_proto::community::CommunityId>,
) -> (MeshSentinel<TestIngress>, tempfile::TempDir) {
    let temp = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::default();
    config.storage.vault_path = temp.path().to_string_lossy().to_string();

    let identity = PhalanxIdentity::new_ephemeral();
    let vault_key = derive_vault_key(&identity, &[0u8; 32]);
    let dek_master = identity.dek_master.clone();
    let trust_registry = TrustRegistry::build(&config).await;

    let mesh_identity_address =
        phalanx_transport::identity_ext::Libp2pExt::to_mesh_address(&identity);
    let deps = SentinelDependencies {
        config,
        identity,
        ingress: TestIngress::new(ingress_rx),
        egress: TestEgress,
        journal: NoOpJournal,
        trust_registry,
        system_governor: Arc::new(SystemGovernor::new()),
        vault_key,
        dek_master,
        prnu_posterior: Arc::new(std::sync::Mutex::new(
            phalanx_proto::evidence::PrnuPosterior::new_uninformed(),
        )),
        extra_community_ids,
        mesh_identity_address,
    };

    (
        MeshSentinel::new(deps)
            .await
            .expect("Failed to build test sentinel"),
        temp,
    )
}
