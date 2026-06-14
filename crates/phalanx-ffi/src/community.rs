// crates/phalanx-ffi/src/community.rs
//
// FFI bindings for Trusted Communities.
//
// Community membership is created, vouched, and imported via these functions.
// The Flutter app orchestrates the ceremony: compute fingerprint → sign vouches →
// collect vouches → assemble community → distribute via QR.

use crate::error::PhalanxError;
use crate::handle::PhalanxHandle;
use phalanx_node::actors::meshsentinel::SentinelCommand;
use std::ffi::CStr;
use std::os::raw::c_char;

// ── Ceremony: Creation & Vouching ──────────────────────────────────────

// Ceremony constants live in phalanx-forensics — re-exported here only for
// the `phalanx_compute_community_id` DID-count guard. All ceremony
// invariants (freshness, expiration bounds, QR budget, quorum) are enforced
// by `phalanx_forensics::identity::assemble_community`.
use phalanx_forensics::identity::MAX_CEREMONY_MEMBERS;

/// Compute a deterministic community fingerprint from founding parameters.
///
/// Pure computation — no handle needed. Any device with the same inputs
/// produces the same 32-byte fingerprint.
///
/// # Safety
/// * `name_ptr` must be a valid null-terminated C string.
/// * `dids_ptr` and `dids_len` must describe a valid postcard-serialized `Vec<String>`.
/// * `out_id` must point to a caller-allocated 32-byte buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_compute_community_id(
    name_ptr: *const c_char,
    quorum: u8,
    dids_ptr: *const u8,
    dids_len: usize,
    out_id: *mut u8,
) -> i32 {
    unsafe {
        if name_ptr.is_null() || dids_ptr.is_null() || out_id.is_null() || dids_len == 0 {
            return PhalanxError::NullPointer.code();
        }

        // Parse name
        let name_str = match CStr::from_ptr(name_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return PhalanxError::InvalidUtf8.code(),
        };
        let name = match phalanx_proto::trust::PetName::new(name_str) {
            Ok(n) => n,
            Err(_) => return PhalanxError::CeremonyFailed.code(),
        };

        // Parse quorum
        let quorum = match phalanx_proto::community::Quorum::new(quorum) {
            Some(q) => q,
            None => return PhalanxError::CeremonyFailed.code(),
        };

        // Deserialize DID list via unmarshal gate
        let dids_bytes = std::slice::from_raw_parts(dids_ptr, dids_len);
        let did_strings: Vec<String> =
            match phalanx_forensics::gate::unmarshal(dids_bytes, "ceremony_dids") {
                Ok(v) => v,
                Err(_) => return PhalanxError::CeremonyFailed.code(),
            };

        if did_strings.len() > MAX_CEREMONY_MEMBERS {
            return PhalanxError::CeremonyFailed.code();
        }

        // Validate DID format and convert
        let mut dids = Vec::with_capacity(did_strings.len());
        for s in &did_strings {
            let did = phalanx_proto::identity::Did::new(s);
            if phalanx_forensics::identity::resolve_did_public_key(&did).is_err() {
                tracing::warn!(target: "phalanx::ffi", did = %s, "Invalid DID format in ceremony");
                return PhalanxError::CeremonyFailed.code();
            }
            dids.push(did);
        }

        let id = phalanx_proto::community::CommunityId::compute(&name, quorum, &dids);
        std::ptr::copy_nonoverlapping(id.0.as_ptr(), out_id, 32);

        0
    }
}

/// Sign a vouch for a member using this node's identity.
///
/// Returns a Rust-allocated postcard-serialized `Vouch` that the caller
/// must free with `phalanx_free_bytes`.
///
/// # Safety
/// * `handle` must be a valid `PhalanxHandle` pointer.
/// * `member_did_ptr` must be a valid null-terminated C string.
/// * `community_id_ptr` must point to exactly 32 bytes.
/// * `out_ptr` and `out_len` must be valid writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_sign_vouch(
    handle: *const PhalanxHandle,
    member_did_ptr: *const c_char,
    community_id_ptr: *const u8,
    joined_at: i64,
    out_ptr: *mut *mut u8,
    out_len: *mut u32,
) -> i32 {
    unsafe {
        if handle.is_null()
            || member_did_ptr.is_null()
            || community_id_ptr.is_null()
            || out_ptr.is_null()
            || out_len.is_null()
        {
            return PhalanxError::NullPointer.code();
        }

        if joined_at < 0 {
            return PhalanxError::CeremonyFailed.code();
        }

        let h = &*handle;

        let member_did_str = match CStr::from_ptr(member_did_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return PhalanxError::InvalidUtf8.code(),
        };
        let member_did = phalanx_proto::identity::Did::new(member_did_str);

        let mut id_bytes = [0u8; 32];
        std::ptr::copy_nonoverlapping(community_id_ptr, id_bytes.as_mut_ptr(), 32);
        let community_id = phalanx_proto::community::CommunityId(id_bytes);

        // Sign-loss is guarded: the `joined_at < 0` check above rejects negative
        // values before this cast runs. FFI boundary receives i64 because Swift/Kotlin
        // expose milliseconds-since-epoch as a signed integer; PhalanxTimestamp is u64.
        #[allow(clippy::cast_sign_loss)]
        let timestamp = phalanx_proto::time::PhalanxTimestamp(joined_at as u64);

        let vouch = phalanx_forensics::identity::sign_vouch(
            &h.identity.keypair,
            &h.identity.did,
            &member_did,
            &community_id,
            timestamp,
        );

        let serialized = match phalanx_forensics::gate::marshal(&vouch, "sign_vouch") {
            Ok(bytes) => bytes,
            Err(_) => return PhalanxError::CeremonyFailed.code(),
        };

        crate::memory::leak_bytes_to_c(serialized.into_boxed_slice(), out_ptr, out_len);

        tracing::info!(
            target: "phalanx::ffi",
            member = %member_did_str,
            "Vouch signed for community member"
        );

        0
    }
}

/// Assemble a complete community from ceremony inputs.
///
/// Verifies all vouch signatures, enforces quorum with dedup and
/// self-vouch exclusion, and returns a Rust-allocated postcard-serialized
/// `Community` token ready for QR distribution.
///
/// Caller must free the output with `phalanx_free_bytes`.
///
/// # Safety
/// * `name_ptr` must be a valid null-terminated C string.
/// * `stronghold_did_ptr` may be null (community without Stronghold).
/// * `members_ptr`/`members_len` must describe a valid postcard-serialized `Vec<CeremonyMember>`.
/// * `out_ptr` and `out_len` must be valid writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_create_community(
    name_ptr: *const c_char,
    quorum: u8,
    joined_at: i64,
    expires_at: i64,
    stronghold_did_ptr: *const c_char,
    members_ptr: *const u8,
    members_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut u32,
) -> i32 {
    unsafe {
        if name_ptr.is_null() || members_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
            return PhalanxError::NullPointer.code();
        }

        // Validate timestamps
        if joined_at < 0 || expires_at < 0 {
            return PhalanxError::CeremonyFailed.code();
        }

        #[allow(clippy::cast_sign_loss)]
        let joined_ts = phalanx_proto::time::PhalanxTimestamp(joined_at as u64);
        #[allow(clippy::cast_sign_loss)]
        let expires_ts = phalanx_proto::time::PhalanxTimestamp(expires_at as u64);

        use phalanx_proto::time::TrustedClock;
        let now = phalanx_proto::time::SystemClock.now();

        // Parse name
        let name_str = match CStr::from_ptr(name_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return PhalanxError::InvalidUtf8.code(),
        };
        let name = match phalanx_proto::trust::PetName::new(name_str) {
            Ok(n) => n,
            Err(_) => return PhalanxError::CeremonyFailed.code(),
        };

        // Parse quorum
        let quorum_val = match phalanx_proto::community::Quorum::new(quorum) {
            Some(q) => q,
            None => return PhalanxError::CeremonyFailed.code(),
        };

        // Parse optional Stronghold DID
        let stronghold_did = if stronghold_did_ptr.is_null() {
            None
        } else {
            match CStr::from_ptr(stronghold_did_ptr).to_str() {
                Ok(s) => Some(phalanx_proto::identity::Did::new(s)),
                Err(_) => return PhalanxError::InvalidUtf8.code(),
            }
        };

        // Deserialize ceremony members
        let members_bytes = std::slice::from_raw_parts(members_ptr, members_len);
        let ceremony_members: Vec<phalanx_proto::community::CeremonyMember> =
            match phalanx_forensics::gate::unmarshal(members_bytes, "ceremony_members") {
                Ok(v) => v,
                Err(_) => return PhalanxError::CeremonyFailed.code(),
            };

        // Delegate every ceremony invariant to the shared forensics verb:
        // freshness, expiration bounds, member count, vouch count, quorum,
        // cryptographic vouch verification, and QR payload budget.
        let params = phalanx_forensics::identity::CommunityAssemblyParams {
            name: name.clone(),
            quorum: quorum_val,
            joined_at: joined_ts,
            expires_at: expires_ts,
            stronghold_did,
            baseline_trust: phalanx_proto::trust::TrustLevel::Verified,
            grants: phalanx_proto::community::CommunityGrants::default(),
            members: ceremony_members,
        };

        let community = match phalanx_forensics::identity::assemble_community(params, now) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    target: "phalanx::ffi",
                    error = %e,
                    community = %name_str,
                    "Community assembly rejected"
                );
                return PhalanxError::CeremonyFailed.code();
            }
        };

        // Serialize with the versioned envelope (R6) so the emitted token
        // roundtrips through `phalanx_preview_community` / `phalanx_import_community`.
        let body = match phalanx_forensics::gate::marshal(&community, "create_community") {
            Ok(bytes) => bytes,
            Err(_) => return PhalanxError::CeremonyFailed.code(),
        };
        let payload = phalanx_forensics::identity::wrap_payload_version(&body);

        crate::memory::leak_bytes_to_c(payload.into_boxed_slice(), out_ptr, out_len);

        tracing::info!(
            target: "phalanx::ffi",
            community = %name_str,
            member_count = community.members.len(),
            "Community created and serialized"
        );

        0
    }
}

// ── Ceremony: Vouch Request / Response (mobile side) ──────────────────
//
// These two FFIs let a voucher's phone handle a `VouchRequest` it
// scanned off a Stronghold QR. Neither goes through the `TrustActor`
// — the handle carries the signing key directly, same pattern as
// `phalanx_sign_vouch` at line 99. The Stronghold Ceremony panel is
// the coordinator; the phone is a pure signer, so keeping these
// calls actor-free avoids wiring a signing key into `TrustActor`
// just to relay it.
//
// Both follow the two-call buffer protocol (null-probe → allocate →
// re-invoke) and return postcard bytes of `Result<T, CeremonyError>`.
// A missing envelope version, an FFI-layer voucher-identity mismatch,
// or a signing failure rides in the inner `Result::Err` — FFI
// transport errors are reserved for null pointers and SerializationFailure.

/// Preview a scanned `VouchRequest` for the Review screen.
///
/// Strips the `[VOUCH_REQUEST_VERSION]` envelope, deserializes the
/// request, checks that `request.voucher_did` matches the handle's
/// DID (returning `CeremonyError::VoucherMismatch` if not), then
/// projects to a `VouchRequestPreview` that omits the voucher DID so
/// the preview type cannot be fed back into
/// [`phalanx_sign_vouch_request`] by accident.
///
/// Pure call with respect to protocol state — no side effects, no
/// actor message, no signature produced. Safe to run on every QR
/// frame if that matches the UI.
///
/// # Safety
/// * `handle` must be a valid `PhalanxHandle` pointer.
/// * `bytes_ptr`/`bytes_len` must describe a valid wrapped-envelope
///   byte slice.
/// * `out_len` must be a valid writable pointer.
/// * `out_buf` may be null (sizing call) or point to `*out_len`
///   writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_preview_vouch_request(
    handle: *const PhalanxHandle,
    bytes_ptr: *const u8,
    bytes_len: usize,
    out_buf: *mut u8,
    out_len: *mut usize,
) -> i32 {
    unsafe {
        if handle.is_null() || bytes_ptr.is_null() || bytes_len == 0 || out_len.is_null() {
            return PhalanxError::NullPointer.code();
        }
        let h = &*handle;
        let wire = std::slice::from_raw_parts(bytes_ptr, bytes_len);

        // 1. Strip the envelope. Version mismatch → domain error.
        let body = match phalanx_forensics::identity::strip_vouch_request(wire) {
            Ok(b) => b,
            Err(e) => {
                let outcome: Result<
                    phalanx_proto::community::VouchRequestPreview,
                    phalanx_proto::community::CeremonyError,
                > = Err(e);
                return write_postcard_outcome(&outcome, "vouch_request_preview", out_buf, out_len);
            }
        };

        // 2. Decode the VouchRequest. Transport-level failure on decode.
        let request: phalanx_proto::community::VouchRequest =
            match phalanx_forensics::gate::unmarshal(body, "vouch_request_preview") {
                Ok(r) => r,
                Err(_) => return PhalanxError::InvalidState.code(),
            };

        // 3. Voucher-identity check: does this device hold the expected key?
        if request.voucher_did != h.identity.did {
            let outcome: Result<
                phalanx_proto::community::VouchRequestPreview,
                phalanx_proto::community::CeremonyError,
            > = Err(phalanx_proto::community::CeremonyError::VoucherMismatch {
                expected: request.voucher_did,
                actual: h.identity.did.clone(),
            });
            return write_postcard_outcome(&outcome, "vouch_request_preview", out_buf, out_len);
        }

        // 4. Project to the review-safe shape.
        let preview = phalanx_forensics::identity::preview_vouch_request(&request);
        let outcome: Result<
            phalanx_proto::community::VouchRequestPreview,
            phalanx_proto::community::CeremonyError,
        > = Ok(preview);
        write_postcard_outcome(&outcome, "vouch_request_preview", out_buf, out_len)
    }
}

/// Sign a scanned `VouchRequest` and return the wrapped `VouchResponse`.
///
/// Strips the request envelope, decodes the `VouchRequest`, calls
/// `sign_vouch_response(&handle.keypair, &request, SystemClock.now())`
/// directly (no actor round-trip — matches `phalanx_sign_vouch`),
/// then produces a `VouchResponse` wrapped with
/// `[VOUCH_RESPONSE_VERSION]` inside the outer `Result::Ok`.
///
/// The Dart side reads `Result<VouchResponse, CeremonyError>`, checks
/// the variant, and on `Ok(response)` serializes the wrapped bytes
/// directly to a QR / file.
///
/// Failure modes encoded in `Result::Err`:
/// - `UnsupportedVersion { version }` — bad request envelope.
/// - `VoucherMismatch { expected, actual }` — request targets another
///   device's DID.
/// - `ResponseStale { age_seconds }` — request is already past the
///   freshness window.
///
/// # Safety
/// * `handle` must be a valid `PhalanxHandle` pointer.
/// * `bytes_ptr`/`bytes_len` must describe a valid wrapped-envelope
///   byte slice.
/// * `out_len` must be a valid writable pointer.
/// * `out_buf` may be null (sizing call) or point to `*out_len`
///   writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_sign_vouch_request(
    handle: *const PhalanxHandle,
    bytes_ptr: *const u8,
    bytes_len: usize,
    out_buf: *mut u8,
    out_len: *mut usize,
) -> i32 {
    unsafe {
        if handle.is_null() || bytes_ptr.is_null() || bytes_len == 0 || out_len.is_null() {
            return PhalanxError::NullPointer.code();
        }
        let h = &*handle;
        let wire = std::slice::from_raw_parts(bytes_ptr, bytes_len);

        // 1. Strip the request envelope.
        let body = match phalanx_forensics::identity::strip_vouch_request(wire) {
            Ok(b) => b,
            Err(e) => {
                // Produce `Result<Vec<u8>, CeremonyError>::Err`.
                let outcome: Result<Vec<u8>, phalanx_proto::community::CeremonyError> = Err(e);
                return write_postcard_outcome(&outcome, "vouch_response_signed", out_buf, out_len);
            }
        };

        // 2. Decode the VouchRequest.
        let request: phalanx_proto::community::VouchRequest =
            match phalanx_forensics::gate::unmarshal(body, "vouch_request_sign") {
                Ok(r) => r,
                Err(_) => return PhalanxError::InvalidState.code(),
            };

        // 3. Sign via the Laboratory verb. Uses SystemClock — the phone's
        //    local wall clock. Same time source as `phalanx_create_community`.
        use phalanx_proto::time::TrustedClock;
        let now = phalanx_proto::time::SystemClock.now();
        let response = match phalanx_forensics::identity::sign_vouch_response(
            &h.identity.keypair,
            &request,
            now,
        ) {
            Ok(r) => r,
            Err(e) => {
                let outcome: Result<Vec<u8>, phalanx_proto::community::CeremonyError> = Err(e);
                return write_postcard_outcome(&outcome, "vouch_response_signed", out_buf, out_len);
            }
        };

        // 4. Serialize and wrap with the response envelope — the Dart side
        //    surfaces these bytes directly to a QR payload.
        let body = match phalanx_forensics::gate::marshal(&response, "vouch_response_signed") {
            Ok(bytes) => bytes,
            Err(_) => return PhalanxError::SerializationFailure.code(),
        };
        let wrapped = phalanx_forensics::identity::wrap_vouch_response(&body);
        let outcome: Result<Vec<u8>, phalanx_proto::community::CeremonyError> = Ok(wrapped);

        tracing::info!(
            target: "phalanx::ffi",
            member = %request.member_did.as_str(),
            "VouchResponse signed"
        );

        write_postcard_outcome(&outcome, "vouch_response_signed", out_buf, out_len)
    }
}

// ── Import & Lifecycle ────────────────────────────────────────────────

/// Write a postcard-encoded value into a caller-provided output buffer using
/// the two-call buffer-size protocol (plan §Phase 2).
///
/// On first call with `out_buf = null` or insufficient `*out_len`, writes the
/// required size to `*out_len` and returns `BufferTooSmall`. On second call
/// with an adequately sized buffer, writes the payload, updates `*out_len`
/// to the bytes actually written, and returns `Ok`.
///
/// # Safety
/// * `out_len` must be a valid writable pointer.
/// * When `out_buf` is non-null, it must point to at least the initial
///   value of `*out_len` writable bytes.
unsafe fn write_postcard_outcome<T: serde::Serialize>(
    value: &T,
    context: &str,
    out_buf: *mut u8,
    out_len: *mut usize,
) -> i32 {
    unsafe {
        if out_len.is_null() {
            return PhalanxError::NullPointer.code();
        }
        let encoded = match phalanx_forensics::gate::marshal(value, context) {
            Ok(bytes) => bytes,
            Err(_) => return PhalanxError::SerializationFailure.code(),
        };
        let available = if out_buf.is_null() { 0 } else { *out_len };
        if available < encoded.len() {
            *out_len = encoded.len();
            return PhalanxError::BufferTooSmall.code();
        }
        std::ptr::copy_nonoverlapping(encoded.as_ptr(), out_buf, encoded.len());
        *out_len = encoded.len();
        PhalanxError::Ok.code()
    }
}

/// Import a community membership from a serialized token (deep link payload).
///
/// The token is a postcard-serialized `Community` struct, typically received
/// via QR code or deep link during the pre-event vouching ceremony.
///
/// Returns an `ImportOutcome` (postcard-encoded) in the caller-provided output
/// buffer using the two-call protocol: first call with `out_buf = null` to
/// learn the required size, second call with an adequately sized buffer.
///
/// # Safety
/// * `handle` must be a valid `PhalanxHandle` pointer.
/// * `token_ptr` and `token_len` must describe a valid byte slice.
/// * `out_len` must be a valid writable pointer.
/// * `out_buf` may be null (sizing call) or point to `*out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_import_community(
    handle: *const PhalanxHandle,
    token_ptr: *const u8,
    token_len: usize,
    out_buf: *mut u8,
    out_len: *mut usize,
) -> i32 {
    unsafe {
        if handle.is_null() || token_ptr.is_null() || token_len == 0 || out_len.is_null() {
            return PhalanxError::NullPointer.code();
        }

        let h = &*handle;
        let token_bytes = std::slice::from_raw_parts(token_ptr, token_len);

        // R6: strip the versioned envelope first. An unknown version is a *domain*
        // error, so it rides in the `ImportOutcome` payload — not the FFI status.
        let body = match phalanx_forensics::identity::strip_payload_version(token_bytes) {
            Ok(b) => b,
            Err(e) => {
                let outcome = phalanx_proto::community::ImportOutcome::Err(e);
                return write_postcard_outcome(&outcome, "import_outcome", out_buf, out_len);
            }
        };

        // Deserialize the community via the Laboratory's unmarshal gate.
        let community: phalanx_proto::community::Community =
            match phalanx_forensics::gate::unmarshal(body, "community_import") {
                Ok(c) => c,
                Err(_) => return PhalanxError::InvalidState.code(),
            };

        tracing::info!(
            target: "phalanx::ffi",
            community = %community.name,
            members = community.members.len(),
            "Importing community from deep link"
        );

        // Dispatch to TrustActor and await the import outcome.
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if h.runtime
            .block_on(h.trust_tx.send(
                phalanx_node::actors::trust_actor::TrustCommand::ImportCommunity {
                    community,
                    reply_to: reply_tx,
                },
            ))
            .is_err()
        {
            return PhalanxError::ChannelClosed.code();
        }
        let outcome = match h.runtime.block_on(reply_rx) {
            Ok(o) => o,
            Err(_) => return PhalanxError::ChannelClosed.code(),
        };

        write_postcard_outcome(&outcome, "import_outcome", out_buf, out_len)
    }
}

/// Set the active recording state on the MeshSentinel.
///
/// Called by Flutter when recording starts (recording_id not null) or stops (null).
/// When active, MeshSentinel captures ProximityWitness entries and auto-seals
/// grants to the community Stronghold.
///
/// # Safety
/// * `handle` must be a valid `PhalanxHandle` pointer.
/// * `recording_id` must be a valid null-terminated C string, or null to stop.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_set_recording_state(
    handle: *const PhalanxHandle,
    recording_id: *const c_char,
) -> i32 {
    unsafe {
        if handle.is_null() {
            return PhalanxError::NullPointer.code();
        }

        let h = &*handle;

        // Parse the recording id. `to_str` (not `to_string_lossy`) so a
        // non-UTF8 byte sequence surfaces as `InvalidUtf8` rather than
        // silently U+FFFD-ing into a recording id that won't match anything
        // on disk. (Fixes audit finding L2.)
        let rec_id = if recording_id.is_null() {
            None
        } else {
            let c_str = CStr::from_ptr(recording_id);
            match c_str.to_str() {
                Ok(s) => {
                    tracing::info!(
                        target: "phalanx::ffi",
                        recording = %s,
                        "Recording state change requested — dispatching to engine"
                    );
                    Some(phalanx_proto::identity::RecordingId::new(s.to_string()))
                }
                Err(_) => return PhalanxError::InvalidUtf8.code(),
            }
        };

        // Dispatch to the engine via the SentinelCommand mailbox. The engine
        // services the command inside its own `select!` arm — the FFI never
        // locks the sentinel, so the deadlock pattern this function had
        // against `engine.run()`'s long-held lock is structurally
        // impossible now. (Fixes audit finding H2.)
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if h.sentinel_cmd_tx
            .blocking_send(SentinelCommand::SetRecordingState {
                id: rec_id,
                reply_to: reply_tx,
            })
            .is_err()
        {
            return PhalanxError::ChannelClosed.code();
        }
        match reply_rx.blocking_recv() {
            Ok(()) => 0,
            Err(_) => PhalanxError::ChannelClosed.code(),
        }
    }
}

/// Manually dissolve a community (panic button).
///
/// Zeroes all membership data for the specified community. Does not affect
/// other members — each phone holds only its own credential. Returns a
/// `DissolveOutcome` (postcard-encoded) in the caller-provided output
/// buffer using the two-call protocol.
///
/// # Safety
/// * `handle` must be a valid `PhalanxHandle` pointer.
/// * `community_id_ptr` must point to exactly 32 bytes.
/// * `out_len` must be a valid writable pointer.
/// * `out_buf` may be null (sizing call) or point to `*out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_dissolve_community(
    handle: *const PhalanxHandle,
    community_id_ptr: *const u8,
    out_buf: *mut u8,
    out_len: *mut usize,
) -> i32 {
    unsafe {
        if handle.is_null() || community_id_ptr.is_null() || out_len.is_null() {
            return PhalanxError::NullPointer.code();
        }

        let h = &*handle;
        let mut id_bytes = [0u8; 32];
        std::ptr::copy_nonoverlapping(community_id_ptr, id_bytes.as_mut_ptr(), 32);
        let community_id = phalanx_proto::community::CommunityId(id_bytes);

        tracing::info!(
            target: "phalanx::ffi",
            "Manual community dissolution requested"
        );

        // Dispatch to TrustActor and await the dissolve outcome.
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if h.runtime
            .block_on(h.trust_tx.send(
                phalanx_node::actors::trust_actor::TrustCommand::DissolveCommunity {
                    community_id,
                    reply_to: reply_tx,
                },
            ))
            .is_err()
        {
            return PhalanxError::ChannelClosed.code();
        }
        let outcome = match h.runtime.block_on(reply_rx) {
            Ok(o) => o,
            Err(_) => return PhalanxError::ChannelClosed.code(),
        };

        write_postcard_outcome(&outcome, "dissolve_outcome", out_buf, out_len)
    }
}

/// List all communities currently in the TrustRegistry.
///
/// Returns postcard-encoded `Vec<CommunitySummary>` in the output buffer
/// using the two-call protocol.
///
/// # Safety
/// * `handle` must be a valid `PhalanxHandle` pointer.
/// * `out_len` must be a valid writable pointer.
/// * `out_buf` may be null (sizing call) or point to `*out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_list_communities(
    handle: *const PhalanxHandle,
    out_buf: *mut u8,
    out_len: *mut usize,
) -> i32 {
    unsafe {
        if handle.is_null() || out_len.is_null() {
            return PhalanxError::NullPointer.code();
        }
        let h = &*handle;
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if h.runtime
            .block_on(h.trust_tx.send(
                phalanx_node::actors::trust_actor::TrustCommand::ListCommunities {
                    reply_to: reply_tx,
                },
            ))
            .is_err()
        {
            return PhalanxError::ChannelClosed.code();
        }
        let summaries = match h.runtime.block_on(reply_rx) {
            Ok(v) => v,
            Err(_) => return PhalanxError::ChannelClosed.code(),
        };
        write_postcard_outcome(&summaries, "community_summaries", out_buf, out_len)
    }
}

/// Fetch the full roster for a single community.
///
/// Returns postcard-encoded `Option<CommunityRoster>` — `None` if the id is
/// unknown — using the two-call protocol.
///
/// # Safety
/// * `handle` must be a valid `PhalanxHandle` pointer.
/// * `community_id_ptr` must point to exactly 32 bytes.
/// * `out_len` must be a valid writable pointer.
/// * `out_buf` may be null (sizing call) or point to `*out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_get_community(
    handle: *const PhalanxHandle,
    community_id_ptr: *const u8,
    out_buf: *mut u8,
    out_len: *mut usize,
) -> i32 {
    unsafe {
        if handle.is_null() || community_id_ptr.is_null() || out_len.is_null() {
            return PhalanxError::NullPointer.code();
        }
        let h = &*handle;
        let mut id_bytes = [0u8; 32];
        std::ptr::copy_nonoverlapping(community_id_ptr, id_bytes.as_mut_ptr(), 32);
        let community_id = phalanx_proto::community::CommunityId(id_bytes);

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if h.runtime
            .block_on(h.trust_tx.send(
                phalanx_node::actors::trust_actor::TrustCommand::GetCommunity {
                    community_id,
                    reply_to: reply_tx,
                },
            ))
            .is_err()
        {
            return PhalanxError::ChannelClosed.code();
        }
        let roster = match h.runtime.block_on(reply_rx) {
            Ok(r) => r,
            Err(_) => return PhalanxError::ChannelClosed.code(),
        };
        write_postcard_outcome(&roster, "community_roster", out_buf, out_len)
    }
}

/// Preview a community token WITHOUT registering it.
///
/// Runs the same verification pipeline as import (expiration + vouch
/// signatures) and projects the roster for the confirmation screen. Pure
/// call — no handle or registry dependency, safe to invoke before the user
/// commits to joining. Returns postcard-encoded
/// `Result<CommunityRoster, CommunityVerifyError>` using the two-call protocol.
///
/// # Safety
/// * `token_ptr` and `token_len` must describe a valid byte slice.
/// * `out_len` must be a valid writable pointer.
/// * `out_buf` may be null (sizing call) or point to `*out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_preview_community(
    token_ptr: *const u8,
    token_len: usize,
    now_millis: u64,
    out_buf: *mut u8,
    out_len: *mut usize,
) -> i32 {
    unsafe {
        if token_ptr.is_null() || token_len == 0 || out_len.is_null() {
            return PhalanxError::NullPointer.code();
        }
        let token_bytes = std::slice::from_raw_parts(token_ptr, token_len);

        // R6: strip the versioned envelope first. An unknown version is a *domain*
        // error, so it rides in the preview outcome — not the FFI status.
        let body = match phalanx_forensics::identity::strip_payload_version(token_bytes) {
            Ok(b) => b,
            Err(e) => {
                let outcome: Result<
                    phalanx_proto::community::CommunityRoster,
                    phalanx_proto::community::CommunityVerifyError,
                > = Err(e);
                return write_postcard_outcome(&outcome, "preview_outcome", out_buf, out_len);
            }
        };

        let community: phalanx_proto::community::Community =
            match phalanx_forensics::gate::unmarshal(body, "community_preview") {
                Ok(c) => c,
                Err(_) => return PhalanxError::InvalidState.code(),
            };

        let now = phalanx_proto::time::PhalanxTimestamp(now_millis);
        let outcome: Result<
            phalanx_proto::community::CommunityRoster,
            phalanx_proto::community::CommunityVerifyError,
        > = match phalanx_forensics::identity::verify_community_vouches(&community, now) {
            Ok(()) => Ok(project_preview_roster(&community)),
            Err(e) => Err(e),
        };

        write_postcard_outcome(&outcome, "preview_outcome", out_buf, out_len)
    }
}

/// Project a `Community` into a roster for preview (pre-registration).
/// Pet names are unknown at this stage, so every member has `pet_name: None`.
fn project_preview_roster(
    community: &phalanx_proto::community::Community,
) -> phalanx_proto::community::CommunityRoster {
    let member_count = u16::try_from(community.members.len()).unwrap_or(u16::MAX);
    let summary = phalanx_proto::community::CommunitySummary {
        id: community.fingerprint,
        name: community.name.clone(),
        member_count,
        expires_at: community.expires_at,
        quorum: community.quorum,
    };
    let members = community
        .members
        .iter()
        .map(|m| {
            let vouch_count = u16::try_from(m.vouches().len()).unwrap_or(u16::MAX);
            phalanx_proto::community::MemberSummary {
                did: m.did().clone(),
                joined_at: m.joined(),
                vouch_count,
                pet_name: None,
            }
        })
        .collect();
    phalanx_proto::community::CommunityRoster {
        summary,
        members,
        grants: community.grants,
        stronghold_did: community.stronghold_did.clone(),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::undocumented_unsafe_blocks
)]
mod tests {
    //! Phase 6 coverage for the FFI-only concerns:
    //!
    //! * **Version envelope** (`strip_payload_version` / `wrap_payload_version`) —
    //!   mismatched version returns `CommunityVerifyError::UnsupportedVersion`
    //!   embedded in the postcard outcome, not an FFI transport error.
    //! * **Two-call buffer protocol** — null probe returns
    //!   `BUFFER_TOO_SMALL` with the required size; second call with an
    //!   adequate buffer succeeds.
    //! * **Null-pointer guards** on the unsafe entry points.
    //!
    //! The import/dissolve/list/get family require a full `PhalanxHandle`
    //! (engine bootstrap) and are therefore covered by the actor-level
    //! integration tests in `phalanx-node/tests/community_integration.rs`.
    //! `phalanx_preview_community` stands alone — no handle — so it is the
    //! ideal vehicle for exercising the envelope and buffer protocol here.

    use super::*;
    use ed25519_dalek::SigningKey;
    use phalanx_forensics::identity::{
        assemble_community, sign_vouch, wrap_payload_version, CommunityAssemblyParams,
    };
    use phalanx_proto::community::{
        CeremonyMember, Community, CommunityGrants, CommunityId, CommunityRoster,
        CommunityVerifyError, Quorum,
    };
    use phalanx_proto::identity::Did;
    use phalanx_proto::time::PhalanxTimestamp;
    use phalanx_proto::trust::{PetName, TrustLevel};
    use rand::rngs::OsRng;

    fn make_identity() -> (Did, SigningKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let did = Did::derive_did_key(&sk.verifying_key().to_bytes());
        (did, sk)
    }

    /// Build an unwrapped `Community` valid at `now`.
    fn build_valid_community(name: &str, now: PhalanxTimestamp) -> Community {
        let (voucher_a_did, voucher_a_sk) = make_identity();
        let (voucher_b_did, voucher_b_sk) = make_identity();
        let (member_did, _) = make_identity();

        let pet = PetName::new(name).unwrap();
        let quorum = Quorum::new(2).unwrap();
        let expires_at = PhalanxTimestamp(now.0 + 10 * 60_000);

        let tentative = CommunityId::compute(&pet, quorum, std::slice::from_ref(&member_did));
        let vouch_a = sign_vouch(&voucher_a_sk, &voucher_a_did, &member_did, &tentative, now);
        let vouch_b = sign_vouch(&voucher_b_sk, &voucher_b_did, &member_did, &tentative, now);

        let params = CommunityAssemblyParams {
            name: pet,
            quorum,
            joined_at: now,
            expires_at,
            stronghold_did: None,
            baseline_trust: TrustLevel::Verified,
            grants: CommunityGrants::default(),
            members: vec![CeremonyMember {
                did: member_did,
                vouches: vec![vouch_a, vouch_b],
            }],
        };
        assemble_community(params, now).unwrap()
    }

    /// Emit the canonical on-wire payload: `[0x01] || postcard(Community)`.
    fn wire_bytes(community: &Community) -> Vec<u8> {
        let body = postcard::to_allocvec(community).unwrap();
        wrap_payload_version(&body)
    }

    /// Invoke `phalanx_preview_community` via the two-call protocol and
    /// return the raw postcard payload on success, or the FFI status on
    /// unrecoverable transport failure.
    fn preview_via_two_call(wire: &[u8], now: PhalanxTimestamp) -> Result<Vec<u8>, i32> {
        // Phase 1: null probe.
        let mut probed_len: usize = 0;
        let probe_status = unsafe {
            phalanx_preview_community(
                wire.as_ptr(),
                wire.len(),
                now.0,
                std::ptr::null_mut(),
                &mut probed_len as *mut usize,
            )
        };
        if probe_status != crate::error::PhalanxError::BufferTooSmall.code() {
            return Err(probe_status);
        }
        assert!(probed_len > 0, "probe should report non-zero size");

        // Phase 2: allocate and re-invoke.
        let mut buf = vec![0u8; probed_len];
        let mut actual_len: usize = buf.len();
        let status = unsafe {
            phalanx_preview_community(
                wire.as_ptr(),
                wire.len(),
                now.0,
                buf.as_mut_ptr(),
                &mut actual_len as *mut usize,
            )
        };
        if status != crate::error::PhalanxError::Ok.code() {
            return Err(status);
        }
        buf.truncate(actual_len);
        Ok(buf)
    }

    #[test]
    fn preview_happy_path_returns_ok_roster() {
        let now = PhalanxTimestamp(1_000_000);
        let community = build_valid_community("ACLU-Portland", now);
        let expected_id = community.fingerprint;
        let wire = wire_bytes(&community);

        let payload = preview_via_two_call(&wire, now).expect("transport ok");
        let outcome: Result<CommunityRoster, CommunityVerifyError> =
            postcard::from_bytes(&payload).expect("postcard decode");
        match outcome {
            Ok(roster) => {
                assert_eq!(roster.summary.id, expected_id);
                assert_eq!(roster.members.len(), 1);
                // Pet names are unknown at preview time — roster is pre-registration.
                assert!(roster.members.iter().all(|m| m.pet_name.is_none()));
            }
            Err(e) => panic!("expected Ok roster, got {e:?}"),
        }
    }

    #[test]
    fn preview_rejects_unknown_version_byte() {
        let now = PhalanxTimestamp(1_000_000);
        let community = build_valid_community("WrongVersion", now);
        let body = postcard::to_allocvec(&community).unwrap();

        // Swap the canonical 0x01 prefix for an unsupported 0x02.
        let mut wire = Vec::with_capacity(body.len() + 1);
        wire.push(0x02);
        wire.extend_from_slice(&body);

        let payload = preview_via_two_call(&wire, now).expect("transport ok");
        let outcome: Result<CommunityRoster, CommunityVerifyError> =
            postcard::from_bytes(&payload).unwrap();
        match outcome {
            Err(CommunityVerifyError::UnsupportedVersion { version }) => assert_eq!(version, 0x02),
            other => panic!("expected UnsupportedVersion(2), got {other:?}"),
        }
    }

    #[test]
    fn preview_rejects_zero_length_version() {
        // A one-byte 0x00 payload: non-empty (so the NullPointer guard passes)
        // but the version byte is unknown, so it must fail the envelope check.
        let now = PhalanxTimestamp(1_000_000);
        let wire = [0x00u8];

        let payload = preview_via_two_call(&wire, now).expect("transport ok");
        let outcome: Result<CommunityRoster, CommunityVerifyError> =
            postcard::from_bytes(&payload).unwrap();
        match outcome {
            Err(CommunityVerifyError::UnsupportedVersion { version }) => assert_eq!(version, 0x00),
            other => panic!("expected UnsupportedVersion(0), got {other:?}"),
        }
    }

    #[test]
    fn preview_rejects_expired_community() {
        // Produce a wire payload that's valid by signature but already expired
        // by the `now` the caller supplies. Mutating `expires_at` post-assembly
        // keeps the vouch signatures intact (they bind fingerprint, not expiry).
        let assembled_at = PhalanxTimestamp(1_000_000);
        let mut community = build_valid_community("Stale", assembled_at);
        let wire_now = PhalanxTimestamp(assembled_at.0 + 20 * 60_000);
        community.expires_at = PhalanxTimestamp(wire_now.0.saturating_sub(1));
        let wire = wire_bytes(&community);

        let payload = preview_via_two_call(&wire, wire_now).expect("transport ok");
        let outcome: Result<CommunityRoster, CommunityVerifyError> =
            postcard::from_bytes(&payload).unwrap();
        match outcome {
            Err(CommunityVerifyError::Expired { .. }) => {}
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn preview_two_call_probe_matches_actual_size() {
        // Not every path through the two-call helper is equal — the probe
        // must report the *exact* bytes needed, and the second call must
        // write exactly that many bytes.
        let now = PhalanxTimestamp(1_000_000);
        let community = build_valid_community("ProbeSize", now);
        let wire = wire_bytes(&community);

        let mut probed_len: usize = 0;
        let probe_status = unsafe {
            phalanx_preview_community(
                wire.as_ptr(),
                wire.len(),
                now.0,
                std::ptr::null_mut(),
                &mut probed_len as *mut usize,
            )
        };
        assert_eq!(
            probe_status,
            crate::error::PhalanxError::BufferTooSmall.code(),
            "null-probe must report BufferTooSmall"
        );
        assert!(probed_len > 0);

        // A buffer that's one byte short must still return BufferTooSmall.
        let mut short_buf = vec![0u8; probed_len - 1];
        let mut short_len = short_buf.len();
        let short_status = unsafe {
            phalanx_preview_community(
                wire.as_ptr(),
                wire.len(),
                now.0,
                short_buf.as_mut_ptr(),
                &mut short_len as *mut usize,
            )
        };
        assert_eq!(
            short_status,
            crate::error::PhalanxError::BufferTooSmall.code()
        );
        assert_eq!(short_len, probed_len);

        // Exact-size buffer must succeed.
        let mut fit_buf = vec![0u8; probed_len];
        let mut fit_len = fit_buf.len();
        let fit_status = unsafe {
            phalanx_preview_community(
                wire.as_ptr(),
                wire.len(),
                now.0,
                fit_buf.as_mut_ptr(),
                &mut fit_len as *mut usize,
            )
        };
        assert_eq!(fit_status, crate::error::PhalanxError::Ok.code());
        assert_eq!(fit_len, probed_len);
    }

    #[test]
    fn preview_null_token_returns_null_pointer() {
        let mut out_len: usize = 0;
        let status = unsafe {
            phalanx_preview_community(
                std::ptr::null(),
                16,
                0,
                std::ptr::null_mut(),
                &mut out_len as *mut usize,
            )
        };
        assert_eq!(status, PhalanxError::NullPointer.code());
    }

    #[test]
    fn preview_zero_length_token_returns_null_pointer() {
        let wire = [0x01u8];
        let mut out_len: usize = 0;
        let status = unsafe {
            phalanx_preview_community(
                wire.as_ptr(),
                0,
                0,
                std::ptr::null_mut(),
                &mut out_len as *mut usize,
            )
        };
        assert_eq!(status, PhalanxError::NullPointer.code());
    }

    #[test]
    fn preview_null_out_len_returns_null_pointer() {
        let wire = [0x01u8];
        let status = unsafe {
            phalanx_preview_community(
                wire.as_ptr(),
                wire.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(status, PhalanxError::NullPointer.code());
    }

    // ── Vouch Request / Response FFI null-guard tests ───────────────
    //
    // The two `vouch_request` FFIs take a `*const PhalanxHandle` and
    // invoke the SystemClock + handle's signing key. Happy-path
    // coverage requires a fully bootstrapped engine and therefore
    // lives in Phase 7.D's `ceremony_e2e.rs` integration test. Here
    // we only exercise the null-pointer guards that fire before any
    // handle dereference — same split as the other handle-requiring
    // FFIs (see `mod tests` preamble above).

    #[test]
    fn preview_vouch_request_null_handle_returns_null_pointer() {
        let wire = [0x01u8, 0xAA];
        let mut out_len: usize = 0;
        let status = unsafe {
            phalanx_preview_vouch_request(
                std::ptr::null(),
                wire.as_ptr(),
                wire.len(),
                std::ptr::null_mut(),
                &mut out_len as *mut usize,
            )
        };
        assert_eq!(status, PhalanxError::NullPointer.code());
    }

    #[test]
    fn preview_vouch_request_null_bytes_returns_null_pointer() {
        let mut out_len: usize = 0;
        // Use a non-null dummy handle ptr — the guard checks bytes_ptr
        // before dereferencing anything else.
        let dummy_handle = 0x1usize as *const PhalanxHandle;
        let status = unsafe {
            phalanx_preview_vouch_request(
                dummy_handle,
                std::ptr::null(),
                16,
                std::ptr::null_mut(),
                &mut out_len as *mut usize,
            )
        };
        assert_eq!(status, PhalanxError::NullPointer.code());
    }

    #[test]
    fn preview_vouch_request_zero_length_returns_null_pointer() {
        let wire = [0x01u8];
        let mut out_len: usize = 0;
        let dummy_handle = 0x1usize as *const PhalanxHandle;
        let status = unsafe {
            phalanx_preview_vouch_request(
                dummy_handle,
                wire.as_ptr(),
                0,
                std::ptr::null_mut(),
                &mut out_len as *mut usize,
            )
        };
        assert_eq!(status, PhalanxError::NullPointer.code());
    }

    #[test]
    fn preview_vouch_request_null_out_len_returns_null_pointer() {
        let wire = [0x01u8, 0xAA];
        let dummy_handle = 0x1usize as *const PhalanxHandle;
        let status = unsafe {
            phalanx_preview_vouch_request(
                dummy_handle,
                wire.as_ptr(),
                wire.len(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(status, PhalanxError::NullPointer.code());
    }

    #[test]
    fn sign_vouch_request_null_handle_returns_null_pointer() {
        let wire = [0x01u8, 0xAA];
        let mut out_len: usize = 0;
        let status = unsafe {
            phalanx_sign_vouch_request(
                std::ptr::null(),
                wire.as_ptr(),
                wire.len(),
                std::ptr::null_mut(),
                &mut out_len as *mut usize,
            )
        };
        assert_eq!(status, PhalanxError::NullPointer.code());
    }

    #[test]
    fn sign_vouch_request_null_bytes_returns_null_pointer() {
        let mut out_len: usize = 0;
        let dummy_handle = 0x1usize as *const PhalanxHandle;
        let status = unsafe {
            phalanx_sign_vouch_request(
                dummy_handle,
                std::ptr::null(),
                16,
                std::ptr::null_mut(),
                &mut out_len as *mut usize,
            )
        };
        assert_eq!(status, PhalanxError::NullPointer.code());
    }

    #[test]
    fn sign_vouch_request_zero_length_returns_null_pointer() {
        let wire = [0x01u8];
        let mut out_len: usize = 0;
        let dummy_handle = 0x1usize as *const PhalanxHandle;
        let status = unsafe {
            phalanx_sign_vouch_request(
                dummy_handle,
                wire.as_ptr(),
                0,
                std::ptr::null_mut(),
                &mut out_len as *mut usize,
            )
        };
        assert_eq!(status, PhalanxError::NullPointer.code());
    }

    #[test]
    fn sign_vouch_request_null_out_len_returns_null_pointer() {
        let wire = [0x01u8, 0xAA];
        let dummy_handle = 0x1usize as *const PhalanxHandle;
        let status = unsafe {
            phalanx_sign_vouch_request(
                dummy_handle,
                wire.as_ptr(),
                wire.len(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(status, PhalanxError::NullPointer.code());
    }

    #[test]
    fn create_emits_wrapped_envelope() {
        // `phalanx_create_community` must emit `[0x01] || postcard(Community)`
        // so that its output roundtrips through `phalanx_preview_community`.
        use std::ffi::CString;

        let name = CString::new("RoundTrip").unwrap();
        let now = PhalanxTimestamp(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        );

        let (voucher_a_did, voucher_a_sk) = make_identity();
        let (voucher_b_did, voucher_b_sk) = make_identity();
        let (member_did, _) = make_identity();

        let pet = PetName::new("RoundTrip").unwrap();
        let quorum = Quorum::new(2).unwrap();
        let tentative = CommunityId::compute(&pet, quorum, std::slice::from_ref(&member_did));
        let vouch_a = sign_vouch(&voucher_a_sk, &voucher_a_did, &member_did, &tentative, now);
        let vouch_b = sign_vouch(&voucher_b_sk, &voucher_b_did, &member_did, &tentative, now);

        let members = vec![CeremonyMember {
            did: member_did,
            vouches: vec![vouch_a, vouch_b],
        }];
        let members_bytes = postcard::to_allocvec(&members).unwrap();

        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: u32 = 0;
        let status = unsafe {
            phalanx_create_community(
                name.as_ptr(),
                2,
                now.0 as i64,
                (now.0 + 10 * 60_000) as i64,
                std::ptr::null(),
                members_bytes.as_ptr(),
                members_bytes.len(),
                &mut out_ptr as *mut *mut u8,
                &mut out_len as *mut u32,
            )
        };
        assert_eq!(status, 0, "create must succeed");
        assert!(!out_ptr.is_null());
        assert!(out_len > 1, "payload must include version + body");

        let payload = unsafe { std::slice::from_raw_parts(out_ptr, out_len as usize) };
        assert_eq!(
            payload[0], 0x01,
            "first byte must be the canonical envelope version"
        );

        // Clean up Rust-allocated buffer.
        unsafe {
            crate::memory::phalanx_free_bytes(out_ptr, out_len);
        }
    }
}
