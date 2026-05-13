use anyhow::Result;
use async_trait::async_trait;

use crate::evidence::StorageSequence;

/// The PlaybackSink trait defines the "Exit Gates" for Phalanx data.
/// Whether the data is going to a RAM buffer for the UI or a C2PA-wrapped file,
/// it must pass through this trait.
#[async_trait]
pub trait PlaybackSink: Send + Sync {
    /// Handles a decrypted chunk of forensic data.
    /// The implementation is responsible for the "Dual Exodus" logic.
    async fn handle_chunk(&mut self, sequence_id: StorageSequence, data: Vec<u8>) -> Result<()>;

    /// Called when the playback sequence is complete or terminated.
    async fn finalize(&mut self) -> Result<()>;
}

/// Blanket impl so `Box<dyn PlaybackSink + Send + Sync + 'static>` itself
/// satisfies `PlaybackSink`. Required when the sink crosses a command-channel
/// boundary (e.g., `SentinelCommand::SpawnPlayback`) and is then handed to a
/// `PlaybackCoordinator` whose generic bounds expect `V: PlaybackSink`.
///
/// Without this impl, generic callsites can't accept boxed trait objects
/// even though deref-coercion would let direct method calls go through.
/// Trait-bound resolution does not auto-deref.
#[async_trait]
impl<S: PlaybackSink + ?Sized> PlaybackSink for Box<S> {
    async fn handle_chunk(&mut self, sequence_id: StorageSequence, data: Vec<u8>) -> Result<()> {
        (**self).handle_chunk(sequence_id, data).await
    }

    async fn finalize(&mut self) -> Result<()> {
        (**self).finalize().await
    }
}
