// crates/phalanx-ffi/src/community.rs
//
// FFI bindings for Trusted Communities.
//
// Community membership is imported via deep link / QR code.
// The Flutter app deserializes the membership token and calls
// these functions to store it in the TrustRegistry.

use crate::error::PhalanxError;
use crate::handle::PhalanxHandle;
use std::ffi::CStr;
use std::os::raw::c_char;

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
