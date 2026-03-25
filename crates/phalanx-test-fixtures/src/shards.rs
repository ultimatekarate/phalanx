//! VideoShard and AudioShard fixtures.
//!
//! Provides pre-constructed shards with LensGate-passing metrics
//! so that tests outside phalanx-forensics never need to know which
//! ForensicMetrics values are considered valid.

use phalanx_proto::evidence::{AudioShard, DataPayload, StorageSequence, VideoShard};
use phalanx_proto::identity::RecordingId;
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_proto::types::Fps;

use crate::metrics::forensic_metrics_synthetic;

/// VideoShard with LensGate-passing metrics, Fps(30), and a clear payload.
///
/// Uses `SystemClock.now()` would violate temporal agreement for tests that
/// don't pass through temporal Verbs. Uses a fixed timestamp instead —
/// callers that need temporal agreement should use `video_shard_for_recording`
/// with a live timestamp.
pub fn video_shard_synthetic(payload_bytes: usize) -> VideoShard {
    VideoShard {
        payload: DataPayload::Clear(vec![0xAB; payload_bytes]),
        timestamp: PhalanxTimestamp::from_millis(1_700_000_000_000),
        lens_metrics: forensic_metrics_synthetic(),
        ..Default::default()
    }
}

/// VideoShard for multi-shard and recording chain tests.
///
/// Caller provides `recording_id`, `seq`, and `timestamp` — the values
/// that vary between shards in a sequence. Everything else uses
/// LensGate-passing defaults.
pub fn video_shard_for_recording(
    recording_id: &RecordingId,
    seq: u32,
    timestamp: PhalanxTimestamp,
) -> VideoShard {
    VideoShard {
        timestamp,
        sequence_id: StorageSequence(seq),
        fps: Fps::new(30),
        recording_id: recording_id.clone(),
        payload: DataPayload::Clear(vec![0xDE, 0xAD]),
        lens_metrics: forensic_metrics_synthetic(),
    }
}

/// AudioShard with SampleRate(16000), ChannelCount(1), and a clear payload.
pub fn audio_shard_synthetic(payload_bytes: usize) -> AudioShard {
    AudioShard {
        payload: DataPayload::Clear(vec![0xCD; payload_bytes]),
        timestamp: PhalanxTimestamp::from_millis(1_700_000_000_000),
        ..Default::default()
    }
}
