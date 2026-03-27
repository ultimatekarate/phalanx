// crates/phalanx-ffi/src/lib.rs
//
// ═══════════════════════════════════════════════════════════════════════
// THE LARYNX — C-ABI bridge for Flutter/mobile integration.
//
// This is where the linguistic model finds its voice. All Phalanx
// complexity — identity, trust, forensics, mesh networking, homeostatic
// self-regulation — is behind ~20 flat `extern "C"` functions.
//
// Flutter sees only `PhalanxHandle*` and a vocabulary of verbs:
//   create → start → push_frame / get_peers / start_playback → stop → destroy
//
// No JNI. No platform channels. Pure C-ABI. dart:ffi on both platforms.
// ═══════════════════════════════════════════════════════════════════════

pub mod ble_auth;
pub mod calibrate;
pub mod capture;
pub mod community;
pub mod error;
pub mod export;
pub mod forget;
pub mod handle;
pub mod local_mesh;
pub mod memory;
pub mod playback;
pub mod probe;
pub mod status;
pub mod trust;
