// crates/phalanx-stronghold/src/gui/state.rs
//
// GUI state types: AppPhase typestate, PanelId, AsyncReply, per-panel states.
// Hands layer — presentation state only.

use std::collections::HashMap;
use std::path::PathBuf;

use phalanx_forensics::identity::CommunityAssemblyParams;
use phalanx_proto::community::{
    CeremonyNonce, Community, CommunityId, CommunityRoster, VouchRequest, VouchResponse,
};
use phalanx_proto::corroboration::CorroborationProof;
use phalanx_proto::identity::RecordingId;
use phalanx_proto::time::PhalanxTimestamp;
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
    /// Trusted-community ceremony coordinator (Phase 7.B). The Stronghold
    /// is initiator only — vouchers sign on their phones, send responses
    /// back, and the panel drives the assembly + final join-QR.
    Ceremony,
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
        // Boxed: PanelStates is ~1 KB; leaving it inline makes
        // AppPhase itself ~1 KB and blocks clippy::large_enum_variant.
        panels: Box<PanelStates>,
    },
    Failed {
        message: String,
    },
}

// ── Async Reply ────────────────────────────────────────────────────────
//
// Non-blocking wrapper for oneshot replies from async tasks.
// Polled each frame via try_recv — never blocks the UI thread.
//
// Every Pending has a 10 s deadline. If the reply does not arrive
// within the window the panel transitions to `Error` so a frozen
// spinner becomes a retryable error rather than a demo-breaking hang.
// The deadline uses `tokio::time::Instant` — in production it tracks
// real time; under `#[tokio::test(start_paused = true)]` it is
// controllable via `tokio::time::advance`.

/// Deadline for a Pending reply. Ten seconds is long enough to cover
/// argon2 key derivation on a Pi without being so long that a dead
/// actor leaves the UI spinning through a narrated demo.
pub const ASYNC_REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Default)]
pub enum AsyncReply<T> {
    #[default]
    Idle,
    Pending {
        rx: oneshot::Receiver<T>,
        deadline: tokio::time::Instant,
    },
    Ready(T),
    Error(String),
}

impl<T> AsyncReply<T> {
    /// Construct a `Pending` reply whose deadline is
    /// `ASYNC_REPLY_TIMEOUT` from now. Call sites use this rather than
    /// the raw variant so the deadline cannot be forgotten.
    #[allow(clippy::arithmetic_side_effects)] // Instant + 10s cannot overflow within any realistic process lifetime.
    pub fn pending(rx: oneshot::Receiver<T>) -> Self {
        Self::Pending {
            rx,
            deadline: tokio::time::Instant::now() + ASYNC_REPLY_TIMEOUT,
        }
    }

    pub fn poll(&mut self) {
        // Borrow the receiver immutably to try_recv + check deadline.
        let result = if let AsyncReply::Pending { rx, deadline } = &*self {
            let timed_out = tokio::time::Instant::now() >= *deadline;
            Some((rx.try_recv(), timed_out))
        } else {
            None
        };

        // Apply state transition outside the borrow.
        if let Some((try_result, timed_out)) = result {
            match try_result {
                Ok(val) => *self = AsyncReply::Ready(val),
                Err(oneshot::TryRecvError::Empty) => {
                    if timed_out {
                        *self = AsyncReply::Error("timeout waiting for response".into());
                    }
                }
                Err(oneshot::TryRecvError::Disconnected) => {
                    *self = AsyncReply::Error("Channel disconnected".into());
                }
            }
        }
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, AsyncReply::Pending { .. })
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

// ── Ceremony Panel State ───────────────────────────────────────────────
//
// The Ceremony panel runs the Stronghold-side ceremony: Configure the
// community roster → CollectingVouches (one request QR per voucher slot,
// responses imported from file) → Ready (final join QR) → optional
// Cancelled. See `gui/panels/ceremony.rs` for the rendering; this module
// owns only the data shape.

/// Editable form state for the Configure stage. Held on
/// `CeremonyPanelState` so text fields persist across stage transitions
/// (e.g. "Start over" from `Cancelled` restores the form from
/// `last_draft`). Strings are raw — validated into `PetName` / `Did` on
/// "Start ceremony" submit.
#[derive(Clone, Default)]
pub struct ConfigureForm {
    /// Community name. Validated via `PetName::new` on submit.
    pub name: String,
    /// Member DIDs, one per slot. Validated via `Did::new` + non-empty
    /// on submit.
    pub member_dids: Vec<String>,
    /// Single-line "Add member" buffer. Appended to `member_dids` on the
    /// "+" button click.
    pub new_did_buf: String,
    /// Quorum slider value. Clamped to `[2, member_dids.len() - 1]` on
    /// every edit — the v1 self-contained rule forbids self-vouching.
    pub quorum: u16,
    /// Validation error surfaced under the form. Cleared on next edit.
    pub error: Option<String>,
}

/// Ceremony state machine. See 7.B.4 of the plan: Configure →
/// CollectingVouches → Ready / Cancelled. Cancellation preserves the
/// last draft so "Start over" re-opens Configure pre-populated.
#[derive(Default)]
pub enum CeremonyStage {
    /// Organizer is filling the Configure form. Data lives on
    /// `CeremonyPanelState.form` — this variant is purely a tag.
    #[default]
    Configure,
    /// Requests have been issued; awaiting voucher responses. Transitions
    /// to `Ready` once every slot has a verified response and
    /// "Assemble community" succeeds.
    CollectingVouches {
        /// Assembly params under construction. `members[i].vouches`
        /// starts empty and is filled from verified responses at
        /// "Assemble community" time (via the marshaling helper in
        /// `gui/panels/ceremony.rs`). Boxed because the struct carries
        /// the full roster plus per-member `Vouch` vectors and would
        /// otherwise push this enum variant past clippy's
        /// `large_enum_variant` budget.
        params_draft: Box<CommunityAssemblyParams>,
        /// Precomputed fingerprint every voucher signs over. Displayed
        /// on request QRs so vouchers can confirm they're signing the
        /// same thing the organizer sees.
        tentative: CommunityId,
        /// Per-ceremony entropy mixed into every `request_id`. Disambiguates
        /// two ceremonies with otherwise identical `(name, quorum, members)` —
        /// e.g. after an aborted-and-restarted ceremony — so the initiator's
        /// dedup table never silently merges responses across runs. Freshly
        /// generated by `CeremonyNonce::random()` in `start_ceremony`; never
        /// persisted or reused.
        ceremony_nonce: CeremonyNonce,
        /// One request per (member, voucher) slot. Ordered the same way
        /// the Configure form listed members; voucher assignment follows
        /// the v1 roster-order-wrap rule.
        requests: Vec<VouchRequest>,
        /// Verified responses, keyed by `request_id` for O(1) dedup on
        /// re-import.
        responses: HashMap<[u8; 32], VouchResponse>,
        /// Unsigned issuance timestamp — drives the per-slot freshness
        /// countdown UX. The authoritative freshness gate is the
        /// `vouch.joined_at` verified by `verify_vouch_response`.
        issued_at: PhalanxTimestamp,
        /// `request_id` whose QR modal is currently open. `None` = no
        /// modal; exactly one visible at a time.
        showing_qr_for: Option<[u8; 32]>,
    },
    /// Community assembled and installed. The panel renders a join QR
    /// (or only the copyable URI when the payload exceeds the QR
    /// budget).
    Ready {
        /// The freshly-assembled community. Boxed to keep this variant
        /// lean (the enum's other variants are already ~bytes).
        community: Box<Community>,
        /// `None` when the wrapped payload exceeds `QR_PAYLOAD_BUDGET_BYTES`.
        /// The Universal-Link URI is rendered regardless.
        qr_image: Option<eframe::egui::ColorImage>,
        /// Cached texture handle for the QR image — lazy-initialized on
        /// the first render to avoid re-uploading the bitmap every frame.
        /// Rebuilt only if `qr_image` changes (it doesn't, in `Ready`).
        qr_texture: Option<eframe::egui::TextureHandle>,
        /// `phalanx://community?payload=<base64url>` join URI, shown
        /// under the QR and offered via a "Copy" button.
        join_uri: String,
    },
    /// Organizer cancelled or assembly failed. `last_draft` seeds
    /// "Start over" so the organizer does not retype the roster.
    Cancelled {
        reason: String,
        last_draft: Box<CommunityAssemblyParams>,
    },
}

/// Async replies and form state for the Ceremony panel. See 7.B.4.
pub struct CeremonyPanelState {
    pub stage: CeremonyStage,
    /// Form state for the Configure stage. Lives outside the stage
    /// variant so "Start over" from `Cancelled` can rehydrate it
    /// without moving data out of the enum.
    pub form: ConfigureForm,
    /// Outcome of `CommunityCommand::AssembleAndImport`. The Ok path
    /// carries the cloned community (boxed) so the panel can render the
    /// join QR on the next frame without a follow-up `GetCommunity`
    /// round-trip.
    pub assemble: AsyncReply<Result<(CommunityId, Box<Community>), String>>,
    /// Outcome of "Import response" — a pipelined AsyncFileDialog +
    /// file-read + `VerifyVouchResponse` task. The Ok path carries the
    /// verified `(request_id, VouchResponse)` pair so the panel can
    /// insert into `responses` on the next frame.
    pub import: AsyncReply<Result<([u8; 32], VouchResponse), String>>,
    /// Outcome of "Export request" — a pipelined AsyncFileDialog +
    /// file-write task. Path on success (for the confirmation toast),
    /// string on failure.
    pub export: AsyncReply<Result<PathBuf, String>>,
    /// Transient status line under the response list. Cleared when the
    /// operator takes the next action. Used for "Request exported to …",
    /// duplicate-voucher rejection, etc.
    pub toast: Option<String>,
}

impl Default for CeremonyPanelState {
    fn default() -> Self {
        Self {
            stage: CeremonyStage::default(),
            form: ConfigureForm::default(),
            assemble: AsyncReply::Idle,
            import: AsyncReply::Idle,
            export: AsyncReply::Idle,
            toast: None,
        }
    }
}

// ── Aggregate Panel State ──────────────────────────────────────────────

#[derive(Default)]
pub struct PanelStates {
    pub communities: CommunitiesState,
    pub recordings: RecordingsState,
    pub corroborate: CorroborateState,
    pub export: ExportState,
    pub ceremony: CeremonyPanelState,
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
        self.ceremony.assemble.poll();
        self.ceremony.import.poll();
        self.ceremony.export.poll();
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::{ASYNC_REPLY_TIMEOUT, AsyncReply};
    use std::time::Duration;

    /// A Pending reply whose sender never delivers must surface the
    /// timeout error once the deadline elapses — not spin forever.
    /// Keeps the sender in scope so `try_recv` returns `Empty` (not
    /// `Disconnected`), isolating the timeout path.
    #[tokio::test(start_paused = true)]
    async fn async_reply_times_out_after_deadline() {
        let (_tx, rx) = oneshot::channel::<u8>();
        let mut reply = AsyncReply::pending(rx);
        assert!(reply.is_pending(), "should start Pending");

        // Advance just short of the deadline — still pending.
        tokio::time::advance(ASYNC_REPLY_TIMEOUT - Duration::from_secs(1)).await;
        reply.poll();
        assert!(
            reply.is_pending(),
            "should still be Pending before deadline"
        );

        // Cross the deadline — next poll transitions to Error.
        tokio::time::advance(Duration::from_secs(2)).await;
        reply.poll();

        match &reply {
            AsyncReply::Error(msg) => assert!(
                msg.contains("timeout"),
                "expected timeout message, got {msg:?}",
            ),
            other => panic!(
                "expected Error after deadline, got {:?}",
                variant_name(other)
            ),
        }
    }

    /// A dropped sender still flips straight to Error (existing
    /// behaviour) — the timeout path must not mask this faster signal.
    #[tokio::test(start_paused = true)]
    async fn async_reply_detects_disconnect_before_deadline() {
        let (tx, rx) = oneshot::channel::<u8>();
        let mut reply = AsyncReply::pending(rx);
        drop(tx);

        reply.poll();
        match &reply {
            AsyncReply::Error(msg) => assert!(
                msg.contains("disconnected") || msg.contains("Disconnected"),
                "expected disconnect message, got {msg:?}",
            ),
            other => panic!(
                "expected Error after disconnect, got {:?}",
                variant_name(other)
            ),
        }
    }

    /// A sender that replies in time wins against the deadline.
    #[tokio::test(start_paused = true)]
    async fn async_reply_delivers_value_before_deadline() {
        let (tx, rx) = oneshot::channel::<u8>();
        let mut reply = AsyncReply::pending(rx);

        tokio::time::advance(Duration::from_secs(1)).await;
        tx.send(42).expect("receiver live");
        reply.poll();

        assert_eq!(reply.as_ready(), Some(&42));
    }

    fn variant_name<T>(reply: &AsyncReply<T>) -> &'static str {
        match reply {
            AsyncReply::Idle => "Idle",
            AsyncReply::Pending { .. } => "Pending",
            AsyncReply::Ready(_) => "Ready",
            AsyncReply::Error(_) => "Error",
        }
    }
}
