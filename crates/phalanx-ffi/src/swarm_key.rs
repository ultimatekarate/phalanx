// crates/phalanx-ffi/src/swarm_key.rs
//
// Pre-create provisioning of the closed-swarm pre-shared key (`swarm.key`).
//
// An off-grid affinity group forms a closed swarm by sharing a single 32-byte
// key. These functions run BEFORE `phalanx_create*`, because the PSK must be
// present when the libp2p swarm is constructed during create (a post-create
// setter would be too late). The group founder calls
// `phalanx_generate_swarm_key` (writes the key and returns its bytes to display
// / share out-of-band, e.g. as a QR code); joiners call
// `phalanx_import_swarm_key` with the shared bytes. Both write
// `{storage_path}/swarm.key`, which the create path then loads via
// `phalanx_node::psk::load_swarm_key`.
//
// SECURITY NOTE: the swarm key gates only the TCP fallback transport; QUIC is
// not pnet-wrapped, so on a local link any device can still dial in over QUIC.
// This is defense-in-depth for the TCP path, NOT an access boundary. See
// docs/network.md §6. Real membership control needs a per-peer credential at
// the behaviour layer.

use crate::error::PhalanxError;
use phalanx_node::psk::{generate_swarm_key, load_swarm_key};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;

/// Length of a Phalanx swarm pre-shared key, in bytes.
pub const SWARM_KEY_LEN: usize = 32;

/// Generate a fresh 32-byte swarm key, persist it to `{storage_path}/swarm.key`,
/// and copy it into `out_key` for the founder to share out-of-band.
///
/// Call this once on the founder device before `phalanx_create*`. Joiners
/// receive the returned bytes (e.g. via QR) and pass them to
/// `phalanx_import_swarm_key`.
///
/// # Safety
/// * `storage_path` must be a valid NUL-terminated C string.
/// * `out_key` must point to at least `SWARM_KEY_LEN` (32) writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_generate_swarm_key(
    storage_path: *const c_char,
    out_key: *mut u8,
) -> i32 {
    // SAFETY: the caller upholds the `# Safety` contract on this parent
    // `unsafe extern "C" fn`. `storage_path`/`out_key` are null-checked before
    // use; `storage_path` is read only as a NUL-terminated C string, and
    // exactly `SWARM_KEY_LEN` bytes are written through `out_key`, which the
    // caller guarantees points to at least that many writable bytes.
    unsafe {
        if storage_path.is_null() || out_key.is_null() {
            return PhalanxError::NullPointer.code();
        }

        let storage = match CStr::from_ptr(storage_path).to_str() {
            Ok(s) => s,
            Err(_) => return PhalanxError::InvalidUtf8.code(),
        };

        // The app's storage directory normally already exists; ensure it so a
        // very-early provisioning call (before any create) cannot fail on a
        // missing parent.
        let _ = std::fs::create_dir_all(storage);
        let path = Path::new(storage).join("swarm.key");

        if generate_swarm_key(&path).is_err() {
            return PhalanxError::BootFailed.code();
        }

        match load_swarm_key(&path) {
            Some(key) => {
                std::ptr::copy_nonoverlapping(key.as_ptr(), out_key, SWARM_KEY_LEN);
                PhalanxError::Ok.code()
            }
            None => PhalanxError::BootFailed.code(),
        }
    }
}

/// Import a shared 32-byte swarm key (received from the group founder) and
/// persist it to `{storage_path}/swarm.key`, so the next `phalanx_create*`
/// joins the closed swarm.
///
/// # Safety
/// * `storage_path` must be a valid NUL-terminated C string.
/// * `key` must point to exactly `key_len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_import_swarm_key(
    storage_path: *const c_char,
    key: *const u8,
    key_len: usize,
) -> i32 {
    // SAFETY: the caller upholds the `# Safety` contract on this parent
    // `unsafe extern "C" fn`. `storage_path`/`key` are null-checked before use;
    // `storage_path` is read only as a NUL-terminated C string, and `key` is
    // read via `from_raw_parts` for exactly the caller-declared `key_len`
    // (further constrained to `SWARM_KEY_LEN`).
    unsafe {
        if storage_path.is_null() || key.is_null() {
            return PhalanxError::NullPointer.code();
        }
        if key_len != SWARM_KEY_LEN {
            return PhalanxError::ConfigError.code();
        }

        let storage = match CStr::from_ptr(storage_path).to_str() {
            Ok(s) => s,
            Err(_) => return PhalanxError::InvalidUtf8.code(),
        };

        let bytes = std::slice::from_raw_parts(key, key_len);
        let _ = std::fs::create_dir_all(storage);
        let path = Path::new(storage).join("swarm.key");

        match std::fs::write(&path, bytes) {
            Ok(()) => PhalanxError::Ok.code(),
            Err(_) => PhalanxError::BootFailed.code(),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::undocumented_unsafe_blocks
)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn temp_storage(tag: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("phalanx_swarmkey_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn generate_writes_file_and_returns_matching_bytes() {
        let dir = temp_storage("gen");
        let c_path = CString::new(dir.to_str().unwrap()).unwrap();
        let mut out = [0u8; SWARM_KEY_LEN];

        let rc = unsafe { phalanx_generate_swarm_key(c_path.as_ptr(), out.as_mut_ptr()) };
        assert_eq!(rc, PhalanxError::Ok.code());

        // The returned bytes must match what was persisted for the create path.
        let loaded = load_swarm_key(&dir.join("swarm.key")).expect("key file written");
        assert_eq!(loaded, out, "returned key must equal persisted key");
        // Generation must not produce an all-zero key.
        assert_ne!(out, [0u8; SWARM_KEY_LEN]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_persists_exact_bytes() {
        let dir = temp_storage("import");
        let c_path = CString::new(dir.to_str().unwrap()).unwrap();
        let key = [7u8; SWARM_KEY_LEN];

        let rc = unsafe { phalanx_import_swarm_key(c_path.as_ptr(), key.as_ptr(), key.len()) };
        assert_eq!(rc, PhalanxError::Ok.code());

        let loaded = load_swarm_key(&dir.join("swarm.key")).expect("key file written");
        assert_eq!(loaded, key);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_rejects_wrong_length() {
        let dir = temp_storage("badlen");
        let c_path = CString::new(dir.to_str().unwrap()).unwrap();
        let key = [0u8; 16];

        let rc = unsafe { phalanx_import_swarm_key(c_path.as_ptr(), key.as_ptr(), key.len()) };
        assert_eq!(rc, PhalanxError::ConfigError.code());
        assert!(!dir.join("swarm.key").exists(), "no file on bad length");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn null_pointers_rejected() {
        let mut out = [0u8; SWARM_KEY_LEN];
        let rc = unsafe { phalanx_generate_swarm_key(std::ptr::null(), out.as_mut_ptr()) };
        assert_eq!(rc, PhalanxError::NullPointer.code());

        let key = [0u8; SWARM_KEY_LEN];
        let rc2 =
            unsafe { phalanx_import_swarm_key(std::ptr::null(), key.as_ptr(), SWARM_KEY_LEN) };
        assert_eq!(rc2, PhalanxError::NullPointer.code());
    }
}
