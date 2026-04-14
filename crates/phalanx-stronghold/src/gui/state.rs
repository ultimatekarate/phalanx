// crates/phalanx-stronghold/src/gui/state.rs
//
// GUI state types: AppPhase typestate, PanelId, AsyncReply, per-panel states.
// Hands layer — presentation state only.

use std::path::PathBuf;

use phalanx_proto::community::{CommunityId, CommunityRoster};
use phalanx_proto::corroboration::CorroborationProof;
use phalanx_proto::identity::RecordingId;
use zeroize::Zeroizing;

use super::bridge::DaemonBridge;

// ── Panel Identifier ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelId {
    Dashboard,
    Communities,
    Recordings,
    Corroborate,
    Export,
}

// ── App Phase ──────────────────────────────────────────────────────────

pub enum AppPhase {
    Startup {
        passphrase_buf: Zeroizing<String>,
        config_path: String,
        error: Option<String>,
    },
    Running {
        bridge: DaemonBridge,
        active_panel: PanelId,
        panels: PanelStates,
    },
    Failed {
        message: String,
    },
}

// ── Async Reply ────────────────────────────────────────────────────────
//
// Non-blocking wrapper for oneshot replies from async tasks.
// Polled each frame via try_recv — never blocks the UI thread.

pub enum AsyncReply<T> {
    Idle,
    Pending(oneshot::Receiver<T>),
    Ready(T),
    Error(String),
}

impl<T> Default for AsyncReply<T> {
    fn default() -> Self {
        Self::Idle
    }
}

impl<T> AsyncReply<T> {
    pub fn poll(&mut self) {
        // Borrow the receiver immutably to try_recv
        let result = if let AsyncReply::Pending(rx) = &*self {
            Some(rx.try_recv())
        } else {
            None
        };

        // Apply state transition outside the borrow
        if let Some(result) = result {
            match result {
                Ok(val) => *self = AsyncReply::Ready(val),
                Err(oneshot::TryRecvError::Empty) => {}
                Err(oneshot::TryRecvError::Disconnected) => {
                    *self = AsyncReply::Error("Channel disconnected".into());
                }
            }
        }
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, AsyncReply::Pending(_))
    }

    pub fn as_ready(&self) -> Option<&T> {
        if let AsyncReply::Ready(val) = self {
            Some(val)
        } else {
            None
        }
    }

    pub fn as_error(&self) -> Option<&str> {
        if let AsyncReply::Error(msg) = self {
            Some(msg)
        } else {
            None
        }
    }
}

// ── Panel Data Types ───────────────────────────────────────────────────

/// Lightweight summary of a recording — avoids holding full WitnessEnvelope payloads.
pub struct RecordingSummary {
    pub id: RecordingId,
    pub owner_did: String,
    pub artifact_count: usize,
    pub is_complete: bool,
}

/// Community display data from disk.
pub struct CommunityInfo {
    pub id: CommunityId,
    pub name: String,
    pub member_count: usize,
}

// ── Per-Panel States ───────────────────────────────────────────────────

pub struct CommunitiesState {
    pub communities: AsyncReply<Result<Vec<CommunityInfo>, String>>,
    pub import_result: AsyncReply<Result<String, String>>,
    /// Currently selected community for the detail pane; `None` means
    /// the list view is shown. Selection survives across frames.
    pub selected: Option<CommunityId>,
    /// Roster for the selected community, fetched via
    /// `CommunityCommand::GetDetail`. `Ready(None)` means the actor did
    /// not recognise the id (e.g. dissolved in another tab).
    pub detail: AsyncReply<Option<CommunityRoster>>,
    /// Outcome of a Dissolve button click. Polled each frame; when
    /// `Ready(Ok(()))` the list refreshes automatically.
    pub dissolve_result: AsyncReply<Result<(), String>>,
}

impl Default for CommunitiesState {
    fn default() -> Self {
        Self {
            communities: AsyncReply::Idle,
            import_result: AsyncReply::Idle,
            selected: None,
            detail: AsyncReply::Idle,
            dissolve_result: AsyncReply::Idle,
        }
    }
}

pub struct RecordingsState {
    pub selected_community: Option<(CommunityId, String)>,
    pub recordings: AsyncReply<Result<Vec<RecordingSummary>, String>>,
}

impl Default for RecordingsState {
    fn default() -> Self {
        Self {
            selected_community: None,
            recordings: AsyncReply::Idle,
        }
    }
}

pub struct CorroborateState {
    pub selected_community: Option<(CommunityId, String)>,
    pub available_recordings: AsyncReply<Result<Vec<RecordingSummary>, String>>,
    pub selected_recording_indices: Vec<bool>,
    pub grant_paths: Vec<PathBuf>,
    pub result: AsyncReply<Result<CorroborationProof, String>>,
}

impl Default for CorroborateState {
    fn default() -> Self {
        Self {
            selected_community: None,
            available_recordings: AsyncReply::Idle,
            selected_recording_indices: Vec::new(),
            grant_paths: Vec::new(),
            result: AsyncReply::Idle,
        }
    }
}

pub struct ExportState {
    pub selected_community: Option<(CommunityId, String)>,
    pub proof_list: AsyncReply<Result<Vec<[u8; 32]>, String>>,
    pub selected_proof: Option<[u8; 32]>,
    pub grant_paths: Vec<PathBuf>,
    pub output_dir: Option<PathBuf>,
    pub result: AsyncReply<Result<Vec<PathBuf>, String>>,
}

impl Default for ExportState {
    fn default() -> Self {
        Self {
            selected_community: None,
            proof_list: AsyncReply::Idle,
            selected_proof: None,
            grant_paths: Vec::new(),
            output_dir: None,
            result: AsyncReply::Idle,
        }
    }
}

// ── Aggregate Panel State ──────────────────────────────────────────────

pub struct PanelStates {
    pub communities: CommunitiesState,
    pub recordings: RecordingsState,
    pub corroborate: CorroborateState,
    pub export: ExportState,
}

impl Default for PanelStates {
    fn default() -> Self {
        Self {
            communities: CommunitiesState::default(),
            recordings: RecordingsState::default(),
            corroborate: CorroborateState::default(),
            export: ExportState::default(),
        }
    }
}

impl PanelStates {
    /// Poll all pending async replies. Called once per frame.
    pub fn poll_all(&mut self) {
        self.communities.communities.poll();
        self.communities.import_result.poll();
        self.communities.detail.poll();
        self.communities.dissolve_result.poll();
        self.recordings.recordings.poll();
        self.corroborate.available_recordings.poll();
        self.corroborate.result.poll();
        self.export.proof_list.poll();
        self.export.result.poll();
    }
}
