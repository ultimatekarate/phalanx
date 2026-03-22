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
#[no_mangle]
pub unsafe extern "C" fn phalanx_sign_ble_challenge(
    handle: *const PhalanxHandle,
    challenger_did_ptr: *const u8,
    challenger_did_len: usize,
    nonce_ptr: *const u8,
    out_signature: *mut u8,
) -> i32 {
    if handle.is_null()
        || challenger_did_ptr.is_null()
        || nonce_ptr.is_null()
        || out_signature.is_null()
    {
        return PhalanxError::NullPointer.code();
    }

    let h = &*handle;

    // Parse challenger DID
    let challenger_did_bytes = std::slice::from_raw_parts(challenger_did_ptr, challenger_did_len);
    let challenger_did_str = match std::str::from_utf8(challenger_did_bytes) {
        Ok(s) => s,
        Err(_) => return PhalanxError::InvalidUtf8.code(),
    };
    let challenger_did = phalanx_proto::identity::Did::new(challenger_did_str);

    // Read 32-byte nonce
    let mut nonce = [0u8; 32];
    std::ptr::copy_nonoverlapping(nonce_ptr, nonce.as_mut_ptr(), 32);

    // Access the node identity for signing
    let sentinel_guard = match h.sentinel.lock() {
        Ok(g) => g,
        Err(_) => return PhalanxError::InvalidState.code(),
    };
    let sentinel_ref = match sentinel_guard.as_ref() {
        Some(s) => s.clone(),
        None => return PhalanxError::NotRunning.code(),
    };
    drop(sentinel_guard);

    // Sign: message = our_did || challenger_did || nonce
    let result = h.runtime.block_on(async {
        let sentinel = sentinel_ref.lock().await;
        let msg = phalanx_forensics::identity::ble_auth_message(
            &sentinel.identity.did,
            &challenger_did,
            &nonce,
        );
        use ed25519_dalek::Signer;
        sentinel.identity.keypair.sign(&msg)
    });

    // Write 64-byte signature to output buffer
    let sig_bytes = result.to_bytes();
    std::ptr::copy_nonoverlapping(sig_bytes.as_ptr(), out_signature, 64);

    0 // Success
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
#[no_mangle]
pub unsafe extern "C" fn phalanx_verify_ble_peer(
    handle: *const PhalanxHandle,
    responder_did_ptr: *const u8,
    responder_did_len: usize,
    our_nonce_ptr: *const u8,
    signature_ptr: *const u8,
) -> i32 {
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
