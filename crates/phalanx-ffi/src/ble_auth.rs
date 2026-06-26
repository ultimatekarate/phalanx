// crates/phalanx-ffi/src/ble_auth.rs
//
// FFI bindings for BLE mutual authentication.
//
// The handshake is driven by the platform BLE plugin, which shuttles two
// opaque, postcard-serialized blobs over GATT: a `BleChallenge` (built by the
// challenger, binding its DID, a fresh nonce, its active recording, and the
// issue time) and a `BleResponse` (the responder's Ed25519 signature). Rust
// owns the crypto; the blobs are OPAQUE to the plugin — it never constructs or
// parses them, only relays the bytes — so the signed fields cannot be tampered
// with at the FFI boundary.
//
//   1. `phalanx_sign_ble_challenge` — sign an incoming challenge blob with the
//      node's Ed25519 key. The signature covers
//      `responder_did || challenger_did || nonce || recording_id || issued_at`.
//   2. `phalanx_verify_ble_peer` — verify a response blob against the challenge
//      blob (pure signature check over the bound message).
//
// Freshness (challenge max-age), single-use nonces, and the actual admission +
// `ProximityWitness` capture are enforced by `phalanx_ble_verify_and_admit`
// (see `local_mesh.rs`), which is the Rust-side trust boundary: a verified DID
// is the ONLY thing that produces a `PeerDiscovered{LocalMesh}` event.

use crate::error::PhalanxError;
use crate::handle::PhalanxHandle;
use phalanx_proto::identity::RecordingId;
use phalanx_proto::network::{BleChallenge, BleResponse};
use phalanx_proto::prelude::PhalanxIdentity;
use phalanx_proto::time::PhalanxTimestamp;
use rand::RngCore;
use rand::rngs::OsRng;

/// Produce a BLE auth signature over the recording/time-bound message.
///
/// Past-tense work: the identity is immutable, the challenge is borrowed. No
/// runtime, no lock, no async — Ed25519 signing (RFC 8032) is deterministic and
/// synchronous. Extracted from `phalanx_sign_ble_challenge` so the signing
/// logic is unit-testable without bootstrapping a full engine.
pub(crate) fn sign_ble_challenge_inner(
    identity: &PhalanxIdentity,
    challenge: &BleChallenge,
) -> [u8; 64] {
    use ed25519_dalek::Signer;
    // We are the responder; the challenge carries the challenger's DID.
    let msg = phalanx_forensics::identity::ble_auth_message(
        &identity.did,
        &challenge.sender_did,
        &challenge.nonce,
        &challenge.recording_id,
        challenge.issued_at,
    );
    identity.keypair.sign(&msg).to_bytes()
}

/// Build a `BleChallenge` for the active recording. Pure: no IO, no lock.
/// Extracted from `phalanx_make_ble_challenge` so it is unit-testable.
pub(crate) fn make_ble_challenge_inner(
    identity: &PhalanxIdentity,
    recording_id: RecordingId,
    nonce: [u8; 32],
    issued_at: PhalanxTimestamp,
) -> BleChallenge {
    BleChallenge {
        sender_did: identity.did.clone(),
        nonce,
        recording_id,
        issued_at,
    }
}

/// Build a fresh BLE challenge bound to the node's *active recording*, for the
/// platform plugin to relay to a discovered peer (challenger initiation).
///
/// The `recording_id` is read from the engine — NOT supplied by the plugin — so
/// the recording the responder signs is exactly the one the resulting
/// `ProximityWitness` binds (both engine-sourced). Returns `InvalidState` if no
/// recording is active. The challenger keeps the returned blob to pair with the
/// peer's `BleResponse` in `phalanx_ble_verify_and_admit`.
///
/// The output is a postcard-serialized `BleChallenge`; the caller frees it with
/// `phalanx_free_bytes`.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `out_challenge`/`out_len` must be valid, writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_make_ble_challenge(
    handle: *const PhalanxHandle,
    out_challenge: *mut *mut u8,
    out_len: *mut u32,
) -> i32 {
    // SAFETY: caller upholds the # Safety contract on the parent
    // `unsafe extern "C" fn`. `handle` is null-checked via `as_ref`;
    // `out_challenge`/`out_len` are null-checked before the leaked buffer
    // pointer and length are written through them by `leak_bytes_to_c`.
    unsafe {
        let Some(h) = handle.as_ref() else {
            return PhalanxError::NullPointer.code();
        };
        if out_challenge.is_null() || out_len.is_null() {
            return PhalanxError::NullPointer.code();
        }

        // recording_id is engine-sourced: bind the same recording the witness
        // will bind. No active recording → no proximity challenge to make.
        let Some(recording_id) = h.recording_id_rx.borrow().clone() else {
            tracing::warn!(
                target: "phalanx::ffi",
                "make_ble_challenge rejected: no active recording to bind"
            );
            return PhalanxError::InvalidState.code();
        };

        let mut nonce = [0u8; 32];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce);
        let issued_at = PhalanxTimestamp::from_u64(crate::local_mesh::now_millis());

        let challenge = make_ble_challenge_inner(&h.identity, recording_id, nonce, issued_at);
        let bytes = match postcard::to_allocvec(&challenge) {
            Ok(b) => b,
            Err(_) => return PhalanxError::SerializationFailure.code(),
        };
        crate::memory::leak_bytes_to_c(bytes.into_boxed_slice(), out_challenge, out_len);
        PhalanxError::Ok.code()
    }
}

/// Sign a BLE auth challenge from a remote peer, returning a `BleResponse` blob.
///
/// Flutter calls this when it receives a `BleChallenge` blob over BLE. Rust
/// deserializes it, signs the recording/time-bound message with the node's
/// Ed25519 key, and returns a postcard-serialized `BleResponse` (the node's DID
/// + the signature) for Flutter to relay back. The blob is OPAQUE — the plugin
/// never assembles a response itself — and the challenger feeds it straight into
/// `phalanx_ble_verify_and_admit`.
///
/// # Parameters
/// * `handle` — valid `PhalanxHandle` pointer.
/// * `challenge_ptr`/`challenge_len` — postcard-serialized `BleChallenge`.
/// * `out_response`/`out_len` — receive the leaked `BleResponse` blob; the
///   caller frees it with `phalanx_free_bytes`.
///
/// # Safety
/// All pointers must be valid; `challenge_ptr` must point to `challenge_len`
/// readable bytes and `out_response`/`out_len` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_sign_ble_challenge(
    handle: *const PhalanxHandle,
    challenge_ptr: *const u8,
    challenge_len: usize,
    out_response: *mut *mut u8,
    out_len: *mut u32,
) -> i32 {
    // SAFETY: the caller upholds the `# Safety` contract. Every raw pointer is
    // null-checked before use; `handle` is read as `&*handle`, `challenge_ptr`
    // is read via `from_raw_parts` for the caller-declared `challenge_len`, and
    // the `BleResponse` blob is written through `out_response`/`out_len` by
    // `leak_bytes_to_c`.
    unsafe {
        if handle.is_null()
            || challenge_ptr.is_null()
            || out_response.is_null()
            || out_len.is_null()
        {
            return PhalanxError::NullPointer.code();
        }
        let h = &*handle;

        let challenge_bytes = std::slice::from_raw_parts(challenge_ptr, challenge_len);
        let challenge: BleChallenge = match postcard::from_bytes(challenge_bytes) {
            Ok(c) => c,
            Err(_) => return PhalanxError::SerializationFailure.code(),
        };

        // Sign using the handle's identity (immutable Arc clone of the engine's
        // identity). The engine's run loop holds the MeshSentinel for its full
        // lifetime, so an FFI `sentinel.lock().await` would deadlock — read the
        // identity from the handle directly instead.
        let sig_bytes = sign_ble_challenge_inner(&h.identity, &challenge);
        let response = BleResponse {
            responder_did: h.identity.did.clone(),
            signature: sig_bytes.to_vec(),
        };
        let bytes = match postcard::to_allocvec(&response) {
            Ok(b) => b,
            Err(_) => return PhalanxError::SerializationFailure.code(),
        };
        crate::memory::leak_bytes_to_c(bytes.into_boxed_slice(), out_response, out_len);

        PhalanxError::Ok.code()
    }
}

/// Verify a BLE auth response against the challenge it answers.
///
/// Pure signature check over the recording/time-bound message. Returns
/// `PhalanxError::Ok` (0) if the signature is valid, `InvalidState` if not.
/// This does NOT enforce freshness, single-use nonces, or admission — those
/// live in `phalanx_ble_verify_and_admit`. Use this only where a bare crypto
/// check is wanted (e.g. UI feedback before admission).
///
/// # Parameters
/// * `handle` — valid `PhalanxHandle` pointer.
/// * `challenge_ptr`/`challenge_len` — postcard-serialized `BleChallenge` we issued.
/// * `response_ptr`/`response_len` — postcard-serialized `BleResponse` received.
///
/// # Safety
/// All pointers must be valid with the specified lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_verify_ble_peer(
    handle: *const PhalanxHandle,
    challenge_ptr: *const u8,
    challenge_len: usize,
    response_ptr: *const u8,
    response_len: usize,
) -> i32 {
    // SAFETY: the caller upholds the `# Safety` contract. Every raw pointer is
    // null-checked before use; `handle` is read as `&*handle`, and
    // `challenge_ptr`/`response_ptr` are read via `from_raw_parts` for the
    // caller-declared lengths.
    unsafe {
        if handle.is_null() || challenge_ptr.is_null() || response_ptr.is_null() {
            return PhalanxError::NullPointer.code();
        }
        let _h = &*handle;

        let challenge_bytes = std::slice::from_raw_parts(challenge_ptr, challenge_len);
        let response_bytes = std::slice::from_raw_parts(response_ptr, response_len);

        let challenge: BleChallenge = match postcard::from_bytes(challenge_bytes) {
            Ok(c) => c,
            Err(_) => return PhalanxError::SerializationFailure.code(),
        };
        let response: BleResponse = match postcard::from_bytes(response_bytes) {
            Ok(r) => r,
            Err(_) => return PhalanxError::SerializationFailure.code(),
        };

        match phalanx_forensics::identity::verify_ble_response(&challenge, &response) {
            Ok(()) => {
                tracing::info!(
                    target: "phalanx::ffi",
                    peer_did = %response.responder_did,
                    "BLE auth: peer signature verified via FFI"
                );
                PhalanxError::Ok.code()
            }
            Err(_) => {
                tracing::warn!(
                    target: "phalanx::ffi",
                    peer_did = %response.responder_did,
                    "BLE auth: verification failed via FFI"
                );
                PhalanxError::InvalidState.code()
            }
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use phalanx_proto::identity::RecordingId;
    use phalanx_proto::network::{BleChallenge, BleResponse};
    use phalanx_proto::time::PhalanxTimestamp;

    fn challenge_from(challenger: &PhalanxIdentity) -> BleChallenge {
        BleChallenge {
            sender_did: challenger.did.clone(),
            nonce: [42u8; 32],
            recording_id: RecordingId::new("rec-test"),
            issued_at: PhalanxTimestamp(1_000),
        }
    }

    /// `sign_ble_challenge_inner` must produce a signature that
    /// `verify_ble_response` accepts when the same keypair signs and the same
    /// challenge is presented. This is the round-trip invariant the FFI relies
    /// on; testing it without bootstrapping a full engine is the whole reason
    /// we extracted the helper.
    #[test]
    fn sign_ble_challenge_inner_roundtrips_with_verify_ble_response() {
        let responder = PhalanxIdentity::new_ephemeral();
        let challenger = PhalanxIdentity::new_ephemeral();
        let challenge = challenge_from(&challenger);

        let sig_bytes = sign_ble_challenge_inner(&responder, &challenge);
        let response = BleResponse {
            responder_did: responder.did.clone(),
            signature: sig_bytes.to_vec(),
        };

        phalanx_forensics::identity::verify_ble_response(&challenge, &response)
            .expect("signature produced by sign_ble_challenge_inner must verify");
    }

    /// `make_ble_challenge_inner` builds a challenge a responder's signature
    /// verifies against — the full make → sign → verify round-trip the
    /// engine-sourced challenger path relies on. `sender_did` is the challenger.
    #[test]
    fn make_then_sign_roundtrips_with_verify_ble_response() {
        let challenger = PhalanxIdentity::new_ephemeral();
        let responder = PhalanxIdentity::new_ephemeral();

        let challenge = make_ble_challenge_inner(
            &challenger,
            RecordingId::new("rec-make"),
            [7u8; 32],
            PhalanxTimestamp(2_000),
        );
        assert_eq!(challenge.sender_did, challenger.did);

        let sig_bytes = sign_ble_challenge_inner(&responder, &challenge);
        let response = BleResponse {
            responder_did: responder.did.clone(),
            signature: sig_bytes.to_vec(),
        };

        phalanx_forensics::identity::verify_ble_response(&challenge, &response)
            .expect("make→sign→verify must round-trip");
    }

    /// Re-presenting a captured signature against a different recording id must
    /// fail — the recording binding (gap 2) is what stops a witness being
    /// forged for a recording the responder never attested to.
    #[test]
    fn tampered_recording_id_fails_verification() {
        let responder = PhalanxIdentity::new_ephemeral();
        let challenger = PhalanxIdentity::new_ephemeral();
        let challenge = challenge_from(&challenger);

        let sig_bytes = sign_ble_challenge_inner(&responder, &challenge);
        let response = BleResponse {
            responder_did: responder.did.clone(),
            signature: sig_bytes.to_vec(),
        };

        let tampered = BleChallenge {
            recording_id: RecordingId::new("other-recording"),
            ..challenge.clone()
        };
        assert!(phalanx_forensics::identity::verify_ble_response(&tampered, &response).is_err());
    }
}
