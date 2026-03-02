// crates/phalanx-forensics/src/storage/journal.rs

use async_trait::async_trait;
use phalanx_proto::identity::Volley;
use phalanx_proto::prelude::ShardError;
use phalanx_proto::prelude::*;
use std::time::Duration;

/// The Transient Journal: A high-speed, volatile storage interface.
/// Acts as the holding cell for fully assembled Volleys before they
/// are distributed to the broader Phalanx Mesh.
#[async_trait]
pub trait TransientJournal: Send + Sync + 'static {
    /// The Verb "To Persist": Writes a finalized Volley into short-term memory.
    async fn persist_volley(&self, volley: &Volley) -> Result<(), ShardError>;

    /// The Verb "To Retrieve": Fetches a Volley for an authorized Investigator.
    async fn retrieve_volley(&self, id: &VolleyId) -> Result<Option<Volley>, ShardError>;

    /// The Verb "To Prune": Drops Volleys that have exceeded the retention window,
    /// freeing up space for active forensic streams.
    async fn prune_stale(&self, older_than: Duration) -> Result<usize, ShardError>;

    // --- WAL (Write-Ahead Log) Verbs ---
    async fn record_chunk(&mut self, chunk: &ShardChunk) -> Result<(), ShardError>;
    async fn sync(&mut self) -> Result<(), ShardError>;
    async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError>;
    async fn clear(&mut self) -> Result<(), ShardError>;

    // --- Egress Salvage Verbs ---
    async fn record_pending_egress(&mut self, pending: &[PendingEgress]) -> Result<(), ShardError>;
    async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError>;
}
