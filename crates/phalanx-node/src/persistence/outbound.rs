// crates/phalanx-node/src/persistence/outbound.rs
//
// The Outbound WAL: A WAL-backed persistent queue for unsent media evidence.
// Evidence that fails to publish is enqueued here and drained when network
// conditions improve. FIFO ordering preserves the causal evidence chain.

use phalanx_proto::time::PhalanxTimestamp;
use phalanx_proto::topic::MeshTopic;
use phalanx_proto::types::ByteCapacity;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;

/// Monotonic WAL entry identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutboundEntryId(pub u64);

/// A single unsent evidence payload awaiting network transmission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundEntry {
    pub id: OutboundEntryId,
    pub topic: MeshTopic,
    pub envelope_bytes: Vec<u8>,
    pub captured_at: PhalanxTimestamp,
    pub attempts: u32,
    pub last_attempt: Option<PhalanxTimestamp>,
}

/// WAL-backed persistent queue for unsent media evidence.
///
/// Key properties:
/// - **Integral-regulated capacity:** `total_bytes` feeds into `record_storage_pressure()`
///   → drives `w_integral`. As the queue grows, storage pressure rises → composite stress
///   rises → FPS drops → queue growth self-regulates.
/// - **FIFO ordering:** Evidence drained in capture-timestamp order (causal chain).
/// - **Crash-safe:** Each entry is an append-only WAL record. On recovery, the queue is
///   reconstructed from disk.
/// - **Idempotent drain:** Each entry carries an `id`; re-publishing the same envelope
///   is safe (gossipsub deduplicates by message ID).
pub struct OutboundQueue {
    wal_dir: PathBuf,
    entries: VecDeque<OutboundEntry>,
    total_bytes: ByteCapacity,
    next_id: u64,
}

/// Maximum number of failed attempts before an entry is abandoned.
const MAX_ATTEMPTS: u32 = 10;

/// R2-3 FIX: Hard capacity limit for the outbound queue (16 MiB).
/// The integral regulator provides soft backpressure via storage_pressure,
/// but a burst of failed publishes can outpace the signal. This prevents
/// unbounded memory growth.
const MAX_QUEUE_BYTES: u64 = 16 * 1024 * 1024;

impl OutboundQueue {
    /// Create a new OutboundQueue, recovering any entries from disk.
    pub async fn new(wal_dir: PathBuf) -> std::io::Result<Self> {
        tokio::fs::create_dir_all(&wal_dir).await?;

        let mut queue = Self {
            wal_dir,
            entries: VecDeque::new(),
            total_bytes: ByteCapacity(0),
            next_id: 0,
        };
        queue.recover_from_disk().await?;
        Ok(queue)
    }

    /// Enqueue a failed-to-publish evidence payload for later retry.
    pub async fn enqueue(
        &mut self,
        topic: MeshTopic,
        envelope_bytes: Vec<u8>,
        captured_at: PhalanxTimestamp,
    ) -> std::io::Result<OutboundEntryId> {
        let byte_len = envelope_bytes.len() as u64;

        // R2-3 FIX: Reject if queue is at capacity.
        if self.total_bytes.0.saturating_add(byte_len) > MAX_QUEUE_BYTES {
            tracing::warn!(
                event = "outbound_queue_full",
                total_bytes = self.total_bytes.0,
                entry_bytes = byte_len,
                "OutboundQueue: capacity limit reached, dropping entry"
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Outbound queue capacity exceeded",
            ));
        }

        let id = OutboundEntryId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);

        let entry = OutboundEntry {
            id,
            topic,
            envelope_bytes,
            captured_at,
            attempts: 0,
            last_attempt: None,
        };

        // Persist to disk before acknowledging
        self.persist_entry(&entry).await?;

        self.entries.push_back(entry);
        self.total_bytes = ByteCapacity(self.total_bytes.0.saturating_add(byte_len));

        tracing::info!(
            event = "outbound_enqueued",
            entry_id = id.0,
            queue_depth = self.entries.len(),
            total_bytes = self.total_bytes.0,
        );

        Ok(id)
    }

    /// Drain up to `batch_size` entries from the front of the queue.
    /// Returns entries in FIFO (capture-timestamp) order for the caller to attempt publishing.
    pub fn drain_batch(&mut self, batch_size: usize) -> Vec<OutboundEntry> {
        let count = batch_size.min(self.entries.len());
        let batch: Vec<OutboundEntry> = self.entries.drain(..count).collect();

        for entry in &batch {
            let byte_len = entry.envelope_bytes.len() as u64;
            self.total_bytes = ByteCapacity(self.total_bytes.0.saturating_sub(byte_len));
        }

        batch
    }

    /// Re-enqueue an entry that failed to publish, incrementing its attempt counter.
    /// Returns `None` if the entry has exceeded MAX_ATTEMPTS (abandoned with forensic log).
    pub async fn requeue_failed(
        &mut self,
        mut entry: OutboundEntry,
        now: PhalanxTimestamp,
    ) -> std::io::Result<Option<OutboundEntryId>> {
        entry.attempts = entry.attempts.saturating_add(1);
        entry.last_attempt = Some(now);

        if entry.attempts >= MAX_ATTEMPTS {
            // Abandon with forensic audit trail — evidence loss is logged
            tracing::error!(
                event = "outbound_abandoned",
                entry_id = entry.id.0,
                attempts = entry.attempts,
                captured_at = entry.captured_at.as_u64(),
                "Evidence lost after max retry attempts"
            );
            self.remove_wal_entry(entry.id).await?;
            return Ok(None);
        }

        let byte_len = entry.envelope_bytes.len() as u64;
        let id = entry.id;

        // Update WAL record on disk
        self.persist_entry(&entry).await?;

        self.entries.push_back(entry);
        self.total_bytes = ByteCapacity(self.total_bytes.0.saturating_add(byte_len));

        Ok(Some(id))
    }

    /// Mark an entry as successfully published — remove from WAL.
    pub async fn acknowledge(&mut self, id: OutboundEntryId) -> std::io::Result<()> {
        self.remove_wal_entry(id).await?;

        tracing::debug!(
            event = "outbound_acknowledged",
            entry_id = id.0,
            queue_depth = self.entries.len(),
        );

        Ok(())
    }

    /// Re-enqueue an entry without incrementing attempts (backoff not yet elapsed).
    /// Pushes to front to preserve FIFO ordering. No WAL write needed — entry is
    /// already persisted on disk from the original `enqueue()` call.
    pub fn requeue_unchanged(&mut self, entry: OutboundEntry) {
        let byte_len = entry.envelope_bytes.len() as u64;
        self.entries.push_front(entry);
        self.total_bytes = ByteCapacity(self.total_bytes.0.saturating_add(byte_len));
    }

    /// Current queue depth (number of entries).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total bytes held in the queue. Feeds into `record_storage_pressure()`.
    pub fn total_bytes(&self) -> ByteCapacity {
        self.total_bytes
    }

    /// Exponential backoff delay for a given attempt count.
    /// Base: 5 seconds, capped at 5 minutes.
    pub fn backoff_delay(attempts: u32) -> std::time::Duration {
        let base_secs = 5u64;
        let max_secs = 300u64; // 5 minutes
        let delay = base_secs.saturating_mul(1u64 << attempts.min(6));
        std::time::Duration::from_secs(delay.min(max_secs))
    }

    // --- WAL Persistence ---

    fn entry_path(&self, id: OutboundEntryId) -> PathBuf {
        self.wal_dir.join(format!("{}.wal", id.0))
    }

    async fn persist_entry(&self, entry: &OutboundEntry) -> std::io::Result<()> {
        let bytes = postcard::to_allocvec(entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        let path = self.entry_path(entry.id);
        tokio::fs::write(&path, &bytes).await?;
        Ok(())
    }

    async fn remove_wal_entry(&self, id: OutboundEntryId) -> std::io::Result<()> {
        let path = self.entry_path(id);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn recover_from_disk(&mut self) -> std::io::Result<()> {
        let mut read_dir = tokio::fs::read_dir(&self.wal_dir).await?;
        let mut recovered: Vec<OutboundEntry> = Vec::new();

        while let Some(dir_entry) = read_dir.next_entry().await? {
            let path = dir_entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("wal") {
                continue;
            }

            match tokio::fs::read(&path).await {
                Ok(bytes) => match postcard::from_bytes::<OutboundEntry>(&bytes) {
                    Ok(entry) => {
                        recovered.push(entry);
                    }
                    Err(e) => {
                        tracing::warn!(
                            event = "outbound_wal_corrupt",
                            path = %path.display(),
                            error = %e,
                            "Skipping corrupt WAL entry"
                        );
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        event = "outbound_wal_read_error",
                        path = %path.display(),
                        error = %e,
                        "Skipping unreadable WAL entry"
                    );
                }
            }
        }

        // Sort by ID (monotonic) to preserve FIFO ordering
        recovered.sort_by_key(|e| e.id.0);

        // Reconstruct next_id from highest recovered entry
        if let Some(last) = recovered.last() {
            self.next_id = last.id.0.saturating_add(1);
        }

        let mut total: u64 = 0;
        for entry in &recovered {
            total = total.saturating_add(entry.envelope_bytes.len() as u64);
        }

        self.total_bytes = ByteCapacity(total);
        self.entries = VecDeque::from(recovered);

        if !self.entries.is_empty() {
            tracing::info!(
                event = "outbound_wal_recovered",
                entries = self.entries.len(),
                total_bytes = self.total_bytes.0,
            );
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_outbound_enqueue_drain_acknowledge() {
        let dir = tempdir().unwrap();
        let mut queue = OutboundQueue::new(dir.path().to_path_buf()).await.unwrap();

        let now = PhalanxTimestamp::from_millis(1_700_000_000_000);
        let topic = MeshTopic::new("test/video");

        // Enqueue 3 entries
        let id1 = queue
            .enqueue(topic.clone(), vec![0xAA; 100], now)
            .await
            .unwrap();
        let id2 = queue
            .enqueue(topic.clone(), vec![0xBB; 200], now)
            .await
            .unwrap();
        let id3 = queue
            .enqueue(topic.clone(), vec![0xCC; 50], now)
            .await
            .unwrap();

        assert_eq!(queue.len(), 3);
        assert_eq!(queue.total_bytes().0, 350);

        // Drain batch of 2
        let batch = queue.drain_batch(2);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].id, id1);
        assert_eq!(batch[1].id, id2);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.total_bytes().0, 50);

        // Acknowledge the first two
        queue.acknowledge(id1).await.unwrap();
        queue.acknowledge(id2).await.unwrap();

        // Drain the last one
        let batch2 = queue.drain_batch(10);
        assert_eq!(batch2.len(), 1);
        assert_eq!(batch2[0].id, id3);
        queue.acknowledge(id3).await.unwrap();

        assert!(queue.is_empty());
        assert_eq!(queue.total_bytes().0, 0);
    }

    #[tokio::test]
    async fn test_outbound_crash_recovery() {
        let dir = tempdir().unwrap();
        let now = PhalanxTimestamp::from_millis(1_700_000_000_000);
        let topic = MeshTopic::new("test/audio");

        // Enqueue entries, then drop the queue (simulating crash)
        {
            let mut queue = OutboundQueue::new(dir.path().to_path_buf()).await.unwrap();
            queue
                .enqueue(topic.clone(), vec![0x01; 64], now)
                .await
                .unwrap();
            queue
                .enqueue(topic.clone(), vec![0x02; 128], now)
                .await
                .unwrap();
            queue
                .enqueue(topic.clone(), vec![0x03; 32], now)
                .await
                .unwrap();
            assert_eq!(queue.len(), 3);
            // Queue dropped here — simulating crash
        }

        // Recover from disk
        let mut recovered = OutboundQueue::new(dir.path().to_path_buf()).await.unwrap();
        assert_eq!(recovered.len(), 3);
        assert_eq!(recovered.total_bytes().0, 64 + 128 + 32);

        // Drain and verify FIFO order
        let batch = recovered.drain_batch(3);
        assert_eq!(batch[0].envelope_bytes.len(), 64);
        assert_eq!(batch[1].envelope_bytes.len(), 128);
        assert_eq!(batch[2].envelope_bytes.len(), 32);
    }

    #[tokio::test]
    async fn test_outbound_requeue_and_abandon() {
        let dir = tempdir().unwrap();
        let mut queue = OutboundQueue::new(dir.path().to_path_buf()).await.unwrap();
        let now = PhalanxTimestamp::from_millis(1_700_000_000_000);
        let topic = MeshTopic::new("test/evidence");

        queue.enqueue(topic, vec![0xFF; 50], now).await.unwrap();

        // Drain the single entry
        let batch = queue.drain_batch(1);
        assert_eq!(batch.len(), 1);
        let mut entry = batch.into_iter().next().unwrap();

        // Requeue it 9 times (attempts 1-9), each should succeed
        for i in 1..=9 {
            let result = queue.requeue_failed(entry.clone(), now).await.unwrap();
            assert!(result.is_some(), "Attempt {} should succeed", i);
            entry.attempts = i;

            // Drain it again for the next iteration
            let b = queue.drain_batch(1);
            entry = b.into_iter().next().unwrap();
        }

        // The 10th requeue should abandon
        entry.attempts = 9; // Set to 9 so requeue_failed increments to 10
        let result = queue.requeue_failed(entry, now).await.unwrap();
        assert!(result.is_none(), "Should be abandoned after 10 attempts");
        assert!(queue.is_empty());
    }

    #[test]
    fn test_backoff_delay() {
        assert_eq!(OutboundQueue::backoff_delay(0).as_secs(), 5);
        assert_eq!(OutboundQueue::backoff_delay(1).as_secs(), 10);
        assert_eq!(OutboundQueue::backoff_delay(2).as_secs(), 20);
        assert_eq!(OutboundQueue::backoff_delay(3).as_secs(), 40);
        // Capped at 300 seconds
        assert_eq!(OutboundQueue::backoff_delay(10).as_secs(), 300);
    }
}
