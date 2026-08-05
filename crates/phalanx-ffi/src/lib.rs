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

//! # Structural invariant: `MeshSentinel` is unreachable from this crate.
//!
//! The audit-driven refactor in `phalanx-node::engine` forces every
//! sentinel-mutating operation through the `SentinelCommand` mailbox,
//! and `UnspawnedEngine::spawn(self, …)` consumes the only handle to
//! the inner sentinel at start time. To keep that property CI-enforced,
//! the `MeshSentinel` type itself must remain *un-importable* from this
//! crate.
//!
//! ```compile_fail
//! use phalanx_node::MeshSentinel;
//! ```
//!
//! If the import above ever starts compiling — i.e. a future change
//! re-exports `MeshSentinel` at the `phalanx_node` crate root — this
//! doc-test fails and the H1/H2/H3 deadlock class becomes representable
//! again. Don't restore the re-export.
//!
//! # Structural invariant: `PlaybackCoordinator` is unreachable from this crate.
//!
//! The same audit removed the FFI's direct construction of
//! `PlaybackCoordinator` with dummy `discovery_tx` / `providers_rx`
//! channels — `phalanx_start_playback` now dispatches
//! `SentinelCommand::SpawnPlayback` and lets the sentinel build the
//! coordinator with its real DHT channels. The regression "FFI hands
//! the coordinator dummy channels" was the bug that silently disabled
//! mesh fallback for all peer-hosted recordings.
//!
//! ```compile_fail
//! use phalanx_node::PlaybackCoordinator;
//! ```
//!
//! If the import above ever starts compiling — i.e. someone restored
//! the crate-root re-export in `phalanx-node` — this doc-test fails
//! and the mesh-fallback-disabling regression becomes representable
//! again. Don't restore the re-export.

pub mod atrace;
pub mod logcat;
mod observability;

pub mod calibrate;
pub mod capture;
pub mod community;
pub mod error;
pub mod export;
pub mod forget;
pub mod handle;
pub mod memory;
pub mod mnemonic;
mod panic_safety;
pub mod playback;
pub mod probe;
pub mod profile;
pub mod recovery;
pub mod status;
pub mod swarm_key;
pub mod trust;
