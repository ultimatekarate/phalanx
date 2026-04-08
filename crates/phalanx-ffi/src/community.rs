// crates/phalanx-ffi/src/community.rs
//
// FFI bindings for Trusted Communities.
//
// Community membership is created, vouched, and imported via these functions.
// The Flutter app orchestrates the ceremony: compute fingerprint → sign vouches →
// collect vouches → assemble community → distribute via QR.

use crate::error::PhalanxError;
use crate::handle::PhalanxHandle;
use std::ffi::CStr;
use std::os::raw::c_char;

// ── Ceremony: Creation & Vouching ──────────────────────────────────────

/// Maximum founding members in a community ceremony.
const MAX_CEREMONY_MEMBERS: usize = 256;
/// Maximum vouches per member.
const MAX_VOUCHES_PER_MEMBER: usize = 256;
/// Minimum community lifetime (seconds).
const MIN_EXPIRES_SECS: u64 = 300; // 5 minutes
/// Maximum vouch age (seconds).
const MAX_VOUCH_AGE_SECS: u64 = 3600; // 1 hour

/// Compute a deterministic community fingerprint from founding parameters.
///
/// Pure computation — no handle needed. Any device with the same inputs
/// produces the same 32-byte fingerprint.
///
/// # Safety
/// * `name_ptr` must be a valid null-terminated C string.
/// * `dids_ptr` and `dids_len` must describe a valid postcard-serialized `Vec<String>`.
/// * `out_id` must point to a caller-allocated 32-byte buffer.
#[no_mangle]
pub unsafe extern "C" fn phalanx_compute_community_id(
    name_ptr: *const c_char,
    quorum: u8,
    dids_ptr: *const u8,
    dids_len: usize,
    out_id: *mut u8,
) -> i32 {
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
#[no_mangle]
pub unsafe extern "C" fn phalanx_sign_vouch(
    handle: *const PhalanxHandle,
    member_did_ptr: *const c_char,
    community_id_ptr: *const u8,
    joined_at: i64,
    out_ptr: *mut *mut u8,
    out_len: *mut u32,
) -> i32 {
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

    #[allow(clippy::cast_possible_truncation)]
    let len = serialized.len() as u32;
    let mut boxed = serialized.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    std::mem::forget(boxed);

    *out_ptr = ptr;
    *out_len = len;

    tracing::info!(
        target: "phalanx::ffi",
        member = %member_did_str,
        "Vouch signed for community member"
    );

    0
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
#[no_mangle]
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

    // Validate expiration: must be at least 5 minutes in the future
    use phalanx_proto::time::TrustedClock;
    let now = phalanx_proto::time::SystemClock.now();
    if expires_ts.0.saturating_sub(now.0) < MIN_EXPIRES_SECS.saturating_mul(1000) {
        tracing::warn!(target: "phalanx::ffi", "Community expires too soon");
        return PhalanxError::CeremonyFailed.code();
    }

    // Validate vouch freshness: joined_at within 1 hour of now
    let age_ms = now.0.abs_diff(joined_ts.0);
    if age_ms > MAX_VOUCH_AGE_SECS.saturating_mul(1000) {
        tracing::warn!(target: "phalanx::ffi", "Ceremony joined_at is too old or too far in future");
        return PhalanxError::CeremonyFailed.code();
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

    if ceremony_members.is_empty() || ceremony_members.len() > MAX_CEREMONY_MEMBERS {
        return PhalanxError::CeremonyFailed.code();
    }

    // Validate per-member vouch counts
    for cm in &ceremony_members {
        if cm.vouches.len() > MAX_VOUCHES_PER_MEMBER {
            return PhalanxError::CeremonyFailed.code();
        }
    }

    // Compute fingerprint from member DIDs
    let member_dids: Vec<phalanx_proto::identity::Did> =
        ceremony_members.iter().map(|cm| cm.did.clone()).collect();
    let community_id =
        phalanx_proto::community::CommunityId::compute(&name, quorum_val, &member_dids);

    // Verify all vouch signatures and build MemberEntries
    let mut members = Vec::with_capacity(ceremony_members.len());
    for cm in ceremony_members {
        // Verify every vouch signature
        for vouch in &cm.vouches {
            if phalanx_forensics::identity::verify_vouch(vouch, &cm.did, &community_id, joined_ts)
                .is_err()
            {
                tracing::warn!(
                    target: "phalanx::ffi",
                    member = %cm.did,
                    voucher = %vouch.voucher_did,
                    "Vouch signature verification failed"
                );
                return PhalanxError::CeremonyFailed.code();
            }
        }

        // Build MemberEntry with quorum + dedup + self-vouch exclusion
        match phalanx_proto::community::MemberEntry::new_validated(
            cm.did.clone(),
            joined_ts,
            cm.vouches,
            quorum_val,
        ) {
            Some(entry) => members.push(entry),
            None => {
                tracing::warn!(
                    target: "phalanx::ffi",
                    member = %cm.did,
                    "Quorum not met for member"
                );
                return PhalanxError::CeremonyFailed.code();
            }
        }
    }

    // Assemble the community
    let community = phalanx_proto::community::Community {
        fingerprint: community_id,
        name,
        quorum: quorum_val,
        members,
        stronghold_did,
        baseline_trust: phalanx_proto::trust::TrustLevel::Verified,
        grants: phalanx_proto::community::CommunityGrants::default(),
        expires_at: expires_ts,
    };

    // Serialize
    let serialized = match phalanx_forensics::gate::marshal(&community, "create_community") {
        Ok(bytes) => bytes,
        Err(_) => return PhalanxError::CeremonyFailed.code(),
    };

    if serialized.len() > 2800 {
        tracing::warn!(
            target: "phalanx::ffi",
            size = serialized.len(),
            "Community token may exceed QR code capacity (2800 bytes)"
        );
    }

    #[allow(clippy::cast_possible_truncation)]
    let len = serialized.len() as u32;
    let mut boxed = serialized.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    std::mem::forget(boxed);

    *out_ptr = ptr;
    *out_len = len;

    tracing::info!(
        target: "phalanx::ffi",
        community = %name_str,
        member_count = community.members.len(),
        "Community created and serialized"
    );

    0
}

// ── Import & Lifecycle ────────────────────────────────────────────────

/// Import a community membership from a serialized token (deep link payload).
///
/// The token is a postcard-serialized `Community` struct, typically received
/// via QR code or deep link during the pre-event vouching ceremony.
///
/// # Safety
/// * `handle` must be a valid `PhalanxHandle` pointer.
/// * `token_ptr` and `token_len` must describe a valid byte slice.
#[no_mangle]
pub unsafe extern "C" fn phalanx_import_community(
    handle: *const PhalanxHandle,
    token_ptr: *const u8,
    token_len: usize,
) -> i32 {
    if handle.is_null() || token_ptr.is_null() || token_len == 0 {
        return PhalanxError::NullPointer.code();
    }

    let _h = &*handle;
    let token_bytes = std::slice::from_raw_parts(token_ptr, token_len);

    // Deserialize the community via the Laboratory's unmarshal gate.
    let community: phalanx_proto::community::Community =
        match phalanx_forensics::gate::unmarshal(token_bytes, "community_import") {
            Ok(c) => c,
            Err(_) => return PhalanxError::InvalidState.code(),
        };

    tracing::info!(
        target: "phalanx::ffi",
        community = %community.name,
        members = community.members.len(),
        "Importing community from deep link"
    );

    // Dispatch to TrustActor for storage and projection sync.
    let h = &*handle;
    if h.runtime
        .block_on(
            h.trust_tx.send(
                phalanx_node::actors::trust_actor::TrustCommand::ImportCommunity { community },
            ),
        )
        .is_err()
    {
        return PhalanxError::ChannelClosed.code();
    }

    0 // Success
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
#[no_mangle]
pub unsafe extern "C" fn phalanx_set_recording_state(
    handle: *const PhalanxHandle,
    recording_id: *const c_char,
) -> i32 {
    if handle.is_null() {
        return PhalanxError::NullPointer.code();
    }

    let h = &*handle;
    let sentinel_guard = match h.sentinel.lock() {
        Ok(g) => g,
        Err(_) => return PhalanxError::InvalidState.code(),
    };
    let sentinel_ref = match sentinel_guard.as_ref() {
        Some(s) => s.clone(),
        None => return PhalanxError::NotRunning.code(),
    };
    drop(sentinel_guard);

    let rec_id = if recording_id.is_null() {
        None
    } else {
        let c_str = CStr::from_ptr(recording_id);
        Some(phalanx_proto::identity::RecordingId::new(
            c_str.to_string_lossy().to_string(),
        ))
    };

    h.runtime.block_on(async {
        let mut sentinel = sentinel_ref.lock().await;
        if let Some(ref id) = rec_id {
            tracing::info!(target: "phalanx::ffi", recording = %id, "Recording started — enabling proximity capture");
        } else {
            // Flush proximity witnesses captured during this recording.
            let witnesses = std::mem::take(&mut sentinel.proximity_witnesses);
            if !witnesses.is_empty() {
                tracing::info!(
                    target: "phalanx::ffi",
                    count = witnesses.len(),
                    "Recording stopped — flushed {} proximity witnesses", witnesses.len()
                );
                // Proximity witnesses are stored locally for later export to Stronghold.
                // They'll be included in the C2PA export or sent via grant to the Stronghold.
                // For now, they're logged. The Stronghold aggregation path will consume them.
            }
        }
        if rec_id.is_none() {
            // Silent Canary: clear watched state when recording stops.
            sentinel.canary.clear();
        }
        sentinel.active_recording_id = rec_id;
    });

    0 // Success
}

/// Manually dissolve a community (panic button).
///
/// Zeroes all membership data for the specified community. Does not affect
/// other members — each phone holds only its own credential.
///
/// # Safety
/// * `handle` must be a valid `PhalanxHandle` pointer.
/// * `community_id_ptr` must point to exactly 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn phalanx_dissolve_community(
    handle: *const PhalanxHandle,
    community_id_ptr: *const u8,
) -> i32 {
    if handle.is_null() || community_id_ptr.is_null() {
        return PhalanxError::NullPointer.code();
    }

    let _h = &*handle;
    let mut id_bytes = [0u8; 32];
    std::ptr::copy_nonoverlapping(community_id_ptr, id_bytes.as_mut_ptr(), 32);
    let community_id = phalanx_proto::community::CommunityId(id_bytes);

    tracing::info!(
        target: "phalanx::ffi",
        "Manual community dissolution requested"
    );

    // Dispatch to TrustActor for dissolution and projection re-sync.
    let h = &*handle;
    if h.runtime
        .block_on(h.trust_tx.send(
            phalanx_node::actors::trust_actor::TrustCommand::DissolveCommunity { community_id },
        ))
        .is_err()
    {
        return PhalanxError::ChannelClosed.code();
    }

    0 // Success
}
