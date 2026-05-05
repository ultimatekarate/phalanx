// crates/phalanx-proto/src/recovery.rs
//
// Recovery walk status — the polled snapshot the FFI exposes to the UI
// while a recovery is in progress.
//
// Dictionary layer: inert data. The state machine and orchestrator that
// produce these snapshots live in phalanx-node::actors::recovery.

use crate::identity::RecordingId;
use serde::{Deserialize, Serialize};

/// Stage of an in-progress recovery walk.
///
/// Lifecycle: `Idle` → `FetchingManifest` → `WalkingManifest` →
/// `FetchingChildren` → (`Complete` | `Cancelled`).
/// Terminal-failure shortcut: any stage → `NoManifestFound` if the
/// manifest can't be fetched within the budget.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryState {
    /// No recovery has been started, or the previous one finished.
    #[default]
    Idle,
    /// Sent FindProviders for the manifest; waiting for shards to arrive
    /// and the local recording_log to populate.
    FetchingManifest,
    /// Manifest is on disk; reading and parsing entries.
    WalkingManifest,
    /// Manifest parsed; children are being fetched in parallel.
    FetchingChildren,
    /// All expected children are present locally (or the timeout fired
    /// with partial progress). Recovery exits successfully even on
    /// partial recovery — `recovered < total` indicates a partial result.
    Complete,
    /// Manifest could not be fetched within the budget. No children
    /// attempted. Likely cause: no Strongholds online, or no manifest
    /// has ever been published for this identity.
    NoManifestFound,
    /// User-initiated cancel via `phalanx_cancel_recovery`. Partial
    /// state on disk is preserved; resume by calling start again.
    Cancelled,
}

/// Snapshot of an in-progress recovery walk.
///
/// Read by the FFI's `phalanx_recovery_status` command via a postcard
/// two-call protocol. Updated by the orchestrator at every stage
/// transition and on every poll iteration.
///
/// Adding fields later is a postcard-breaking change — bump a
/// `schema_version` field at the same time and gate decode on it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecoveryStatus {
    pub state: RecoveryState,
    /// Total cataloged recordings (= manifest entries seen). Zero
    /// until the manifest is parsed.
    pub total: u32,
    /// Children whose shards have all been pulled to disk (or were
    /// already on disk from a previous attempt).
    pub recovered: u32,
    /// Children that failed or timed out. `recovered + failed` may not
    /// equal `total` while the walk is in progress.
    pub failed: u32,
    /// The currently-fetching child, if any. `None` between stages and
    /// after the walk completes.
    pub current: Option<RecordingId>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Round-trip every `RecoveryState` variant through postcard. The FFI's
    /// `phalanx_recovery_status` is the consumer; a regression here would
    /// silently corrupt the UI's progress reporting.
    #[test]
    fn recovery_state_postcard_round_trip() {
        let states = [
            RecoveryState::Idle,
            RecoveryState::FetchingManifest,
            RecoveryState::WalkingManifest,
            RecoveryState::FetchingChildren,
            RecoveryState::Complete,
            RecoveryState::NoManifestFound,
            RecoveryState::Cancelled,
        ];
        for s in &states {
            let bytes = postcard::to_allocvec(s).expect("encode");
            let back: RecoveryState = postcard::from_bytes(&bytes).expect("decode");
            assert_eq!(*s, back, "round-trip mismatch for {s:?}");
        }
    }

    #[test]
    fn recovery_status_postcard_round_trip_with_payload() {
        let snap = RecoveryStatus {
            state: RecoveryState::FetchingChildren,
            total: 17,
            recovered: 4,
            failed: 1,
            current: Some(RecordingId::new("rec-walk-test")),
        };
        let bytes = postcard::to_allocvec(&snap).expect("encode");
        let back: RecoveryStatus = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(back.state, snap.state);
        assert_eq!(back.total, snap.total);
        assert_eq!(back.recovered, snap.recovered);
        assert_eq!(back.failed, snap.failed);
        assert_eq!(back.current, snap.current);
    }

    #[test]
    fn recovery_status_default_is_idle_zero() {
        let s = RecoveryStatus::default();
        assert_eq!(s.state, RecoveryState::Idle);
        assert_eq!(s.total, 0);
        assert_eq!(s.recovered, 0);
        assert_eq!(s.failed, 0);
        assert!(s.current.is_none());
    }
}
