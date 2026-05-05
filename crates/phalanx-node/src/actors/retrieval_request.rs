// crates/phalanx-node/src/actors/retrieval_request.rs
//
// Shared helper for constructing a signed RecordingRequest for the
// "I am asking a Stronghold for a recording I own" flow.
//
// Used by both PlaybackCoordinator (fetching missing shards mid-playback)
// and RecoveryCoordinator (fetching everything on a fresh device).
//
// Inverse of `PhalanxNodeIdentityExt::verify_retrieval_auth` in
// `identity.rs` — the request this builder produces is exactly what the
// peer's gate verifies.

use ed25519_dalek::Signer;
use phalanx_forensics::cryptography::grant::GrantAuthority;
use phalanx_proto::crypto::{GrantPermissions, SealedLocator, SymmetricKey};
use phalanx_proto::identity::{PhalanxIdentity, RecordingId};
use phalanx_proto::retrieval::RecordingRequest;

/// Failure cases for `build_recording_request`. Each is rare but distinct
/// enough that callers may want to log/attribute differently.
#[derive(Debug)]
pub enum BuildRequestError {
    /// `SealedLocator::seal` failed — typically a curve25519 / ECDH issue.
    SealFailed(String),
    /// Couldn't serialize the signed-data tuple. Indicates a bug in the
    /// envelope shape, not caller error.
    SerializeFailed(String),
}

impl std::fmt::Display for BuildRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SealFailed(s) => write!(f, "SealedLocator seal failed: {s}"),
            Self::SerializeFailed(s) => write!(f, "Request serialization failed: {s}"),
        }
    }
}

impl std::error::Error for BuildRequestError {}

/// Build a signed `RecordingRequest` that asks a Stronghold for the
/// recording owned by `identity`. The recipient of the SealedLocator
/// is `identity.did` itself — this is a self-recovery / self-fetch
/// pattern, where the requester is also the recording's owner.
///
/// The `dek` is the per-recording encryption key — for own derived
/// recordings, callers compute it via
/// `phalanx_forensics::derive_recording_dek(master, rid)`.
pub fn build_recording_request(
    rid: &RecordingId,
    dek: &SymmetricKey,
    identity: &PhalanxIdentity,
) -> Result<RecordingRequest, BuildRequestError> {
    // 1. Seal the locator. Recipient = self → only the holder of this
    //    identity's keypair can unseal.
    let locator = SealedLocator::seal(
        rid.clone(),
        dek.as_bytes(),
        identity,
        identity.did.clone(),
        GrantPermissions::default(),
    )
    .map_err(|e| BuildRequestError::SealFailed(format!("{e:?}")))?;

    // 2. Sign (target_did, recording_id, locator) with the owner key.
    //    Inverse of verify_retrieval_auth in identity.rs.
    let signed_data = (&identity.did, rid, &locator);
    let msg = postcard::to_allocvec(&signed_data)
        .map_err(|e| BuildRequestError::SerializeFailed(e.to_string()))?;
    let signature = identity.keypair.sign(&msg).to_bytes().to_vec();

    Ok(RecordingRequest {
        target_did: identity.did.clone(),
        recording_id: rid.clone(),
        locator,
        signature,
    })
}
