// crates/phalanx-ffi/src/ble_auth.rs
//
// FFI bindings for BLE mutual authentication.
//
// Flutter drives the BLE handshake. Rust provides:
// 1. Signing: Flutter calls phalanx_sign_ble_challenge when a remote peer challenges us
// 2. Verification: Flutter calls phalanx_verify_ble_peer after completing the handshake
//
// Flow:
//   Flutter discovers BLE peer → generates nonce → sends BleChallenge over BLE
//   Remote Flutter receives challenge → calls phalanx_sign_ble_challenge → sends response
//   Local Flutter receives response → calls phalanx_verify_ble_peer
//   If verified → Flutter emits PeerDiscovered with authenticated DID

use crate::error::PhalanxError;
use crate::handle::PhalanxHandle;
use phalanx_proto::prelude::PhalanxIdentity;

/// Produce a BLE auth signature from already-validated inputs.
///
/// Past-tense work: the identity is immutable, the challenger DID is borrowed,
/// the nonce is a fixed-size buffer. No runtime, no lock, no async — Ed25519
/// signing (RFC 8032) is deterministic and synchronous.
///
/// Extracted from `phalanx_sign_ble_challenge` so the signing logic is
/// unit-testable without bootstrapping a full engine.
pub(crate) fn sign_ble_challenge_inner(
    identity: &PhalanxIdentity,
    challenger_did: &phalanx_proto::identity::Did,
    nonce: &[u8; 32],
) -> [u8; 64] {
    use ed25519_dalek::Signer;
    let msg = phalanx_forensics::identity::ble_auth_message(&identity.did, challenger_did, nonce);
    identity.keypair.sign(&msg).to_bytes()
}

/// Sign a BLE auth challenge from a remote peer.
///
/// Flutter calls this when it receives a BLE challenge. Rust signs with the node's
/// Ed25519 key. Flutter sends the resulting signature back over BLE.
///
/// # Parameters
/// * `handle` — valid PhalanxHandle pointer
/// * `challenger_did_ptr/len` — the remote peer's DID (UTF-8 bytes)
/// * `nonce_ptr` — pointer to exactly 32 bytes of challenge nonce
/// * `out_signature` — pointer to 64-byte buffer for the Ed25519 signature output
///
/// # Safety
/// All pointers must be valid. `out_signature` must point to at least 64 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_sign_ble_challenge(
    handle: *const PhalanxHandle,
    challenger_did_ptr: *const u8,
    challenger_did_len: usize,
    nonce_ptr: *const u8,
    out_signature: *mut u8,
) -> i32 {
    unsafe {
        if handle.is_null()
            || challenger_did_ptr.is_null()
            || nonce_ptr.is_null()
            || out_signature.is_null()
        {
            return PhalanxError::NullPointer.code();
        }

        let h = &*handle;

        // Parse challenger DID
        let challenger_did_bytes =
            std::slice::from_raw_parts(challenger_did_ptr, challenger_did_len);
        let challenger_did_str = match std::str::from_utf8(challenger_did_bytes) {
            Ok(s) => s,
            Err(_) => return PhalanxError::InvalidUtf8.code(),
        };
        let challenger_did = phalanx_proto::identity::Did::new(challenger_did_str);

        // Read 32-byte nonce
        let mut nonce = [0u8; 32];
        std::ptr::copy_nonoverlapping(nonce_ptr, nonce.as_mut_ptr(), 32);

        // Sign using the handle's identity (past-tense; immutable Arc clone of
        // the engine's identity). The engine's run loop holds a tokio Mutex on
        // the MeshSentinel for its full lifetime; an FFI `sentinel.lock().await`
        // would deadlock. Read identity from the handle directly instead.
        let sig_bytes = sign_ble_challenge_inner(&h.identity, &challenger_did, &nonce);

        std::ptr::copy_nonoverlapping(sig_bytes.as_ptr(), out_signature, 64);

        0 // Success
    }
}

/// Verify a BLE auth response from a remote peer.
///
/// Flutter calls this after receiving a BLE auth response. Rust verifies the
/// Ed25519 signature. Returns 0 if verified, negative error code if not.
///
/// # Parameters
/// * `handle` — valid PhalanxHandle pointer
/// * `responder_did_ptr/len` — the remote peer's DID (UTF-8 bytes)
/// * `our_nonce_ptr` — pointer to the 32-byte nonce we sent in our challenge
/// * `signature_ptr` — pointer to the 64-byte Ed25519 signature from the remote peer
///
/// # Safety
/// All pointers must be valid with the specified lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_verify_ble_peer(
    handle: *const PhalanxHandle,
    responder_did_ptr: *const u8,
    responder_did_len: usize,
    our_nonce_ptr: *const u8,
    signature_ptr: *const u8,
) -> i32 {
    unsafe {
        if handle.is_null()
            || responder_did_ptr.is_null()
            || our_nonce_ptr.is_null()
            || signature_ptr.is_null()
        {
            return PhalanxError::NullPointer.code();
        }

        let _h = &*handle;

        // Parse responder DID
        let responder_did_bytes = std::slice::from_raw_parts(responder_did_ptr, responder_did_len);
        let responder_did_str = match std::str::from_utf8(responder_did_bytes) {
            Ok(s) => s,
            Err(_) => return PhalanxError::InvalidUtf8.code(),
        };
        let responder_did = phalanx_proto::identity::Did::new(responder_did_str);

        // Read nonce and signature
        let mut nonce = [0u8; 32];
        std::ptr::copy_nonoverlapping(our_nonce_ptr, nonce.as_mut_ptr(), 32);
        let mut sig = [0u8; 64];
        std::ptr::copy_nonoverlapping(signature_ptr, sig.as_mut_ptr(), 64);

        // Build challenge and response structs for verification
        // The challenge sender is us — read our DID from the node_did field
        let our_did = phalanx_proto::identity::Did::new(&_h.node_did);

        let challenge = phalanx_proto::network::BleChallenge {
            sender_did: our_did,
            nonce,
        };
        let response = phalanx_proto::network::BleResponse {
            responder_did,
            signature: sig.to_vec(),
        };

        // Verify using the Laboratory's pure verification logic
        match phalanx_forensics::identity::verify_ble_response(&challenge, &response) {
            Ok(()) => {
                tracing::info!(
                    target: "phalanx::ffi",
                    peer_did = %response.responder_did,
                    "BLE auth: peer verified via FFI"
                );
                0 // Verified
            }
            Err(_) => {
                tracing::warn!(
                    target: "phalanx::ffi",
                    peer_did = %response.responder_did,
                    "BLE auth: verification failed via FFI"
                );
                PhalanxError::InvalidState.code() // Verification failed
            }
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
    use phalanx_proto::network::{BleChallenge, BleResponse};

    /// `sign_ble_challenge_inner` must produce a signature that
    /// `verify_ble_response` accepts when the same keypair signs and the
    /// same DID is recorded on both sides. This is the round-trip
    /// invariant the FFI relies on; testing it without bootstrapping a
    /// full engine is the whole reason we extracted the helper.
    #[test]
    fn sign_ble_challenge_inner_roundtrips_with_verify_ble_response() {
        let responder = PhalanxIdentity::new_ephemeral();
        let challenger = PhalanxIdentity::new_ephemeral();
        let nonce = [42u8; 32];

        // The challenge as the challenger sees it (sender_did = challenger).
        let challenge = BleChallenge {
            sender_did: challenger.did.clone(),
            nonce,
        };

        // The responder signs. Note `ble_auth_message`'s parameter names are
        // (responder_did, challenger_did, nonce) — the responder's DID first.
        let sig_bytes = sign_ble_challenge_inner(&responder, &challenger.did, &nonce);

        let response = BleResponse {
            responder_did: responder.did.clone(),
            signature: sig_bytes.to_vec(),
        };

        phalanx_forensics::identity::verify_ble_response(&challenge, &response)
            .expect("signature produced by sign_ble_challenge_inner must verify");
    }

    /// Tampered nonce must fail verification.
    #[test]
    fn tampered_nonce_fails_verification() {
        let responder = PhalanxIdentity::new_ephemeral();
        let challenger = PhalanxIdentity::new_ephemeral();
        let signed_nonce = [1u8; 32];
        let claimed_nonce = [2u8; 32];

        let challenge = BleChallenge {
            sender_did: challenger.did.clone(),
            nonce: claimed_nonce, // verifier sees a different nonce than was signed
        };
        let sig_bytes = sign_ble_challenge_inner(&responder, &challenger.did, &signed_nonce);
        let response = BleResponse {
            responder_did: responder.did.clone(),
            signature: sig_bytes.to_vec(),
        };

        assert!(
            phalanx_forensics::identity::verify_ble_response(&challenge, &response).is_err(),
            "verifier must reject signatures over a different nonce"
        );
    }
}
