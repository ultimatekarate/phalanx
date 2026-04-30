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
use phalanx_proto::identity::{MeshAddress, PhalanxIdentity, RecordingId};
use phalanx_proto::network::{EgressPort, IngressPort, NetworkEvent};
use phalanx_proto::prelude::{MeshTopic, RecordingResponse};
use std::sync::Arc;
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

/// Build a fully-wired `MeshSentinel<TestIngress>` backed by `TestEgress` and
/// a `NoOpJournal`, rooted at a tempdir returned alongside the sentinel. The
/// tempdir is returned so callers can keep it alive for the sentinel's
/// lifetime — dropping it mid-test would pull the vault path out from under
/// the actor.
pub async fn build_test_sentinel(
    ingress_rx: mpsc::Receiver<NetworkEvent>,
) -> (MeshSentinel<TestIngress>, tempfile::TempDir) {
    let temp = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::default();
    config.storage.vault_path = temp.path().to_string_lossy().to_string();

    let identity = PhalanxIdentity::new_ephemeral();
    let vault_key = derive_vault_key(&identity, &[0u8; 32]);
    let trust_registry = TrustRegistry::build(&config).await;

    let deps = SentinelDependencies {
        config,
        identity,
        ingress: TestIngress::new(ingress_rx),
        egress: TestEgress,
        journal: NoOpJournal,
        trust_registry,
        system_governor: Arc::new(SystemGovernor::new()),
        vault_key,
        local_mesh: None,
        prnu_posterior: Arc::new(std::sync::Mutex::new(
            phalanx_proto::evidence::PrnuPosterior::new_uninformed(),
        )),
    };

    (
        MeshSentinel::new(deps)
            .await
            .expect("Failed to build test sentinel"),
        temp,
    )
}
