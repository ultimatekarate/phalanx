// crates/phalanx-ffi/src/forget.rs
//
// Cryptographic Forgetting FFI: exposes `phalanx_forget_recording` across
// the C-ABI boundary. Accepts a recording ID and the user's BIP39 mnemonic,
// derives the revocation signing key, creates a RevocationToken, destroys
// local evidence via StorageActor, and propagates the revocation to the mesh.
//
// The mnemonic is zeroized immediately after key derivation.
// The signing key is dropped (not actively zeroized — ed25519-dalek's
// `zeroize` feature is not enabled in this workspace).

use crate::error::PhalanxError;
use crate::handle::PhalanxHandle;

use std::ffi::CStr;
use std::os::raw::c_char;

use phalanx_forensics::revocation::create_revocation_token;
use phalanx_node::actors::egress::EgressCommand;
use phalanx_node::actors::storage::StorageCommand;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_proto::identity::RecordingId;
use phalanx_proto::prelude::PhalanxIdentity;
use phalanx_proto::storage::GuardianError;
use phalanx_proto::time::{SystemClock, TrustedClock};
use zeroize::Zeroize;

/// Map a `GuardianError` from `handle_revoke` to a typed FFI error code.
///
/// `handle_revoke` (storage.rs) returns `VerificationFailed(String)` for two
/// distinct user-visible cases: key mismatch (wrong phrase for this recording)
/// and unknown recording. We classify by the message prefix the producer uses.
/// The prefixes are stable — if they change in storage.rs without updating this
/// match, the integration test for split error codes will catch it.
fn classify_revoke_error(e: &GuardianError) -> PhalanxError {
    if let GuardianError::VerificationFailed(msg) = e {
        if msg.contains("authorization failed") {
            return PhalanxError::RevocationKeyMismatch;
        }
        if msg.contains("unknown recording") {
            return PhalanxError::RecordingNotFound;
        }
    }
    PhalanxError::RevocationFailed
}

/// Cryptographically forget a recording. Destroys all local evidence and
/// propagates the revocation to the mesh via gossipsub and DHT.
///
/// Requires the user's 12-word BIP39 mnemonic — the revocation private key
/// is derived from `seed[32..64]` and never stored on the device.
///
/// Returns `PhalanxError::Ok` (0) on success, negative error code on failure.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `recording_id` must be a valid null-terminated C string.
/// * `mnemonic_phrase` must be a valid null-terminated C string (12 BIP39 words).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_forget_recording(
    handle: *const PhalanxHandle,
    recording_id: *const c_char,
    mnemonic_phrase: *const c_char,
) -> i32 {
    unsafe {
        // 1. Validate pointers
        let Some(h) = handle.as_ref() else {
            return PhalanxError::NullPointer.code();
        };

        if recording_id.is_null() || mnemonic_phrase.is_null() {
            return PhalanxError::NullPointer.code();
        }

        // 2. Convert C strings to Rust
        let rec_str = match CStr::from_ptr(recording_id).to_str() {
            Ok(s) => s,
            Err(_) => return PhalanxError::InvalidUtf8.code(),
        };

        let phrase_str = match CStr::from_ptr(mnemonic_phrase).to_str() {
            Ok(s) => s,
            Err(_) => return PhalanxError::InvalidUtf8.code(),
        };

        // 3. Copy mnemonic into a mutable String for zeroization after use
        let mut mnemonic_owned = phrase_str.to_string();

        // 4. Derive revocation signing key from mnemonic. Any failure here means
        //    the phrase couldn't produce a valid signing key — wordlist or
        //    checksum violation. Map to the dedicated MnemonicParseError so the
        //    UI can say "your phrase isn't a valid BIP-39 phrase" rather than the
        //    conflated "phrase invalid or recording not found".
        let signing_key = match PhalanxIdentity::revocation_signing_key(&mnemonic_owned) {
            Ok(key) => key,
            Err(_) => {
                mnemonic_owned.zeroize();
                return PhalanxError::MnemonicParseError.code();
            }
        };

        // 5. Zeroize mnemonic immediately — no longer needed
        mnemonic_owned.zeroize();

        // 6. Create the revocation token
        let rec_id = RecordingId::new(rec_str);
        let timestamp = SystemClock.now();
        let token = create_revocation_token(rec_id.clone(), &signing_key, timestamp);
        // signing_key drops here — not actively zeroized (see module doc)

        // 7. Use channels directly from the handle — no sentinel lock needed.
        let stx = h.storage_tx.clone();
        let etx = h.egress_tx.clone();

        // 8. Spawn async task: local destruction + network propagation
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();

        h.runtime.spawn(async move {
            // 9. Local destruction via StorageActor (critical path)
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            if stx
                .send(StorageCommand::Revoke {
                    token: token.clone(),
                    reply_to: reply_tx,
                })
                .await
                .is_err()
            {
                let _ = result_tx.send(Err(PhalanxError::ChannelClosed));
                return;
            }

            let storage_result = match reply_rx.await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(classify_revoke_error(&e)),
                Err(_) => Err(PhalanxError::ChannelClosed),
            };

            // 10. Network propagation (fire-and-forget, only on local success)
            if storage_result.is_ok() {
                // Gossipsub epidemic propagation
                let _ = etx.send(EgressCommand::PublishRevocation(token)).await;
                // DHT provider cleanup
                let _ = etx.send(EgressCommand::WithdrawProvider(rec_id)).await;
            }

            let _ = result_tx.send(storage_result);
        });

        // 11. Block on the result
        match result_rx.blocking_recv() {
            Ok(Ok(())) => PhalanxError::Ok.code(),
            Ok(Err(e)) => e.code(),
            Err(_) => PhalanxError::ChannelClosed.code(),
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

    #[test]
    fn null_handle_returns_error() {
        unsafe {
            let rec = CString::new("test-rec").expect("valid");
            let phrase = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").expect("valid");
            assert_eq!(
                phalanx_forget_recording(std::ptr::null(), rec.as_ptr(), phrase.as_ptr()),
                PhalanxError::NullPointer.code()
            );
        }
    }

    #[test]
    fn null_recording_id_returns_error() {
        unsafe {
            assert_eq!(
                phalanx_forget_recording(std::ptr::null(), std::ptr::null(), std::ptr::null()),
                PhalanxError::NullPointer.code()
            );
        }
    }
}
