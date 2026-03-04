use phalanx_forensics::prelude::TransientJournal;
use phalanx_proto::prelude::{PendingEgress, ShardChunk, ShardError};

/// Configuration for a simulation run.
/// TODO: Define test mesh topology parameters (node count, latency profile, chaos seeds).
pub struct SimConfig;

/// The author's API for writing simulation scripts.
/// TODO: Implement node spawning, chaos injection, and telemetry collection.
pub struct SimulationHarness;

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
