use phalanx_forensics::prelude::TransientJournal;
use phalanx_proto::prelude::{PendingEgress, ShardChunk, ShardError};

/// Configuration for a simulation run.
/// TODO: Define test mesh topology parameters (node count, latency profile, chaos seeds).
pub struct SimConfig;

/// The author's API for writing simulation scripts.
/// TODO: Implement node spawning, chaos injection, and telemetry collection.
pub struct SimulationHarness;

impl SimulationHarness {
    pub fn init_mesh(
        _config: phalanx_node::config::NodeConfig,
        _physics: crate::physics::PhalanxPhysics,
    ) -> (
        Self,
        tokio::sync::mpsc::Receiver<phalanx_proto::telemetry::SimEvent>,
    ) {
        todo!("SimulationHarness::init_mesh")
    }

    pub async fn spawn_node(
        &mut self,
        _name: &str,
        _role: phalanx_proto::identity::NodeRole,
    ) -> Result<phalanx_proto::prelude::Did, Box<dyn std::error::Error + Send + Sync>> {
        todo!("SimulationHarness::spawn_node")
    }

    pub async fn resolve_did(
        &self,
        _did: &phalanx_proto::prelude::Did,
    ) -> Result<phalanx_proto::identity::NetworkId, Box<dyn std::error::Error + Send + Sync>> {
        todo!("SimulationHarness::resolve_did")
    }

    pub async fn inject_chaos(
        &mut self,
        _did: &phalanx_proto::prelude::Did,
        _mode: phalanx_proto::telemetry::ChaosMode,
    ) {
        todo!("SimulationHarness::inject_chaos")
    }
}

struct RecoveryJournal(Vec<PendingEgress>);

#[async_trait::async_trait]
impl TransientJournal for RecoveryJournal {
    async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError> {
        // Pillar 2: Return the "salvaged" state
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
}
