// crates/phalanx-node/src/actors/archive_grant.rs
//
// Publisher-side export-grant minting (M2.4). When a node pushes a recording to
// a Stronghold configured with a DID, it seals that recording's DEK to the
// Stronghold as an *export grant* — escrow-for-export: the Stronghold can
// decrypt and autonomously export to durable storage, but only this recording,
// and only because the publisher chose to.
//
// Hands-adjacent glue: it composes the forensics Verbs (`derive_recording_dek`,
// `SealedLocator::seal`). Kept as a free function (not a `MeshSentinel` method)
// so the sealing contract is unit-testable in isolation.

use phalanx_forensics::cryptography::grant::GrantAuthority;
use phalanx_proto::crypto::{GrantPermissions, SealedLocator};
use phalanx_proto::identity::{Did, PhalanxIdentity, RecordingId};

/// Mint an export grant for `recording_id` sealed to `stronghold_did`.
///
/// Re-derives the recording's per-recording DEK deterministically from the
/// publisher's own `dek_master` (no key is stored or transmitted in the clear),
/// then seals it to the Stronghold's DID with `export` permission. Sealing is
/// offline — the Stronghold's public key is decoded from its self-describing
/// `did:key`, so no contact is required. The `export` permission is bound into
/// the AEAD AAD, so a MITM cannot flip it.
///
/// Returns `None` if sealing fails (e.g. a malformed/unresolvable DID); the
/// caller then falls back to a custody-only push so the recording is still
/// staged for durability.
#[must_use]
pub fn mint_export_grant(
    identity: &PhalanxIdentity,
    recording_id: &RecordingId,
    stronghold_did: &Did,
) -> Option<SealedLocator> {
    let dek = phalanx_forensics::derive_recording_dek(&identity.dek_master, recording_id);
    match SealedLocator::seal(
        recording_id.clone(),
        dek.as_bytes(),
        identity,
        stronghold_did.clone(),
        GrantPermissions {
            playback: false,
            export: true,
        },
    ) {
        Ok(grant) => Some(grant),
        Err(e) => {
            tracing::warn!(
                recording = %recording_id,
                stronghold = %stronghold_did,
                error = ?e,
                "Archive: export grant seal failed; pushing custody-only"
            );
            None
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use phalanx_forensics::derive_recording_dek;

    #[test]
    fn minted_grant_unlocks_to_the_recording_dek_on_the_stronghold() {
        let publisher = PhalanxIdentity::new_ephemeral();
        let stronghold = PhalanxIdentity::new_ephemeral();
        let rid = RecordingId::new("rec-grant");

        let grant = mint_export_grant(&publisher, &rid, &stronghold.did)
            .expect("seal to a valid did:key succeeds");

        // Sealed to the Stronghold, for this recording, with export authority.
        assert!(
            grant.permissions.export,
            "export permission must be granted"
        );
        assert!(!grant.permissions.playback);
        assert_eq!(grant.recipient, stronghold.did);
        assert_eq!(grant.target, rid);

        // The Stronghold unlocks it to exactly the publisher's per-recording DEK
        // (the same key the publisher used to encrypt the recording), closing
        // the M2.4 → M2.3 contract: mint here, unlock-and-export there.
        let unlocked = grant
            .unlock(&stronghold)
            .expect("the target Stronghold unlocks the grant");
        let expected = derive_recording_dek(&publisher.dek_master, &rid);
        assert_eq!(
            &unlocked,
            expected.as_bytes(),
            "unlocked key must equal the recording DEK"
        );

        // A different identity (wrong recipient) cannot unlock it.
        let attacker = PhalanxIdentity::new_ephemeral();
        assert!(
            grant.unlock(&attacker).is_err(),
            "only the target Stronghold may unlock the grant"
        );
    }

    #[test]
    fn distinct_recordings_seal_distinct_keys() {
        let publisher = PhalanxIdentity::new_ephemeral();
        let stronghold = PhalanxIdentity::new_ephemeral();
        let a = mint_export_grant(&publisher, &RecordingId::new("rec-a"), &stronghold.did).unwrap();
        let b = mint_export_grant(&publisher, &RecordingId::new("rec-b"), &stronghold.did).unwrap();
        let ka = a.unlock(&stronghold).unwrap();
        let kb = b.unlock(&stronghold).unwrap();
        assert_ne!(ka, kb, "per-recording DEKs must differ");
    }
}
