// crates/phalanx-forensics/src/storage/journal.rs

use async_trait::async_trait;

use phalanx_proto::prelude::ShardError;
use phalanx_proto::prelude::*;

/// The Transient Journal: A high-speed, volatile storage interface.
/// Acts as the holding cell for fully assembled Recordings before they
/// are distributed to the broader Phalanx Mesh.
#[async_trait]
pub trait TransientJournal: Send + Sync + 'static {
    // --- WAL (Write-Ahead Log) Verbs ---
    async fn record_chunk(&mut self, chunk: &ShardChunk) -> Result<(), ShardError>;
    async fn sync(&mut self) -> Result<(), ShardError>;
    async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError>;
    async fn clear(&mut self) -> Result<(), ShardError>;

    // --- Egress Salvage Verbs ---
    async fn record_pending_egress(&mut self, pending: &[PendingEgress]) -> Result<(), ShardError>;
    async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError>;
}
