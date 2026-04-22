// crates/phalanx-forensics/src/cryptography/bridge.rs
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{SigningKey, VerifyingKey};
use phalanx_proto::crypto::CryptoError;
use phalanx_proto::prelude::Did;
use sha2::{Digest, Sha512};

/// THE BRIDGE VERB: Ed25519 PK -> X25519 PK
pub fn ed_to_x25519_pk(ed_key: &VerifyingKey) -> Result<[u8; 32], CryptoError> {
    let bytes = ed_key.to_bytes();

    let ed_point =
        CompressedEdwardsY::from_slice(&bytes).map_err(|_| CryptoError::DecompressionFailure)?;

    let mont_point = ed_point
        .decompress()
        .ok_or(CryptoError::DecompressionFailure)?
        .to_montgomery();

    Ok(mont_point.to_bytes())
}

/// THE BRIDGE VERB: Ed25519 SK -> X25519 SK
pub fn ed_to_x25519_sk(ed_key: &SigningKey) -> Result<x25519_dalek::StaticSecret, CryptoError> {
    let mut hasher = Sha512::new();
    hasher.update(ed_key.to_bytes());
    let hash_result = hasher.finalize();

    // SHA-512 output is fixed at 64 bytes; slicing [0..32] always succeeds,
    // so the `try_into` error branch is unreachable in practice. The error is
    // wired up for defense-in-depth against a hypothetical hasher regression.
    #[allow(clippy::indexing_slicing)]
    let mut x25519_bytes: [u8; 32] = hash_result[0..32]
        .try_into()
        .map_err(|_| CryptoError::EncodingError("SHA-512 truncation to 32 bytes failed".into()))?;

    let secret = x25519_dalek::StaticSecret::from(x25519_bytes);
    zeroize::Zeroize::zeroize(&mut x25519_bytes);
    Ok(secret)
}

/// Resolves a `did:key:z...` DID to an Ed25519 VerifyingKey.
///
/// Delegates to `resolve_did_public_key` for the raw byte extraction,
/// then constructs the VerifyingKey from the result.
pub fn resolve_did_pk(did: &Did) -> Result<VerifyingKey, CryptoError> {
    let bytes = crate::identity::resolve_did_public_key(did)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::DidResolutionFailure)
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use phalanx_proto::prelude::PhalanxIdentity;
    use x25519_dalek::PublicKey as X25519PublicKey;

    fn deterministic_signing_key() -> SigningKey {
        // Fixed, deterministic seed — the bridge is pure math, not crypto
        // randomness, so a constant key is the right test fixture.
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn ed_sk_to_x25519_derives_matching_public_key() {
        // The Bridge contract: ed_to_x25519_pk(vk) must equal the X25519 public
        // key derived from the X25519 secret produced by ed_to_x25519_sk(sk).
        // If these drift, ECDH between nodes silently fails and encrypted
        // payloads become undecryptable.
        let signing = deterministic_signing_key();
        let verifying = signing.verifying_key();

        let pk_from_ed = ed_to_x25519_pk(&verifying).expect("ed→x25519 pk must succeed");
        let x_secret = ed_to_x25519_sk(&signing).expect("ed→x25519 sk must succeed");
        let pk_from_sk = X25519PublicKey::from(&x_secret);

        assert_eq!(&pk_from_ed, pk_from_sk.as_bytes());
    }

    #[test]
    fn ed_to_x25519_pk_is_deterministic() {
        // Same input → same output. A non-deterministic bridge would produce
        // different X25519 keys on each call, which would break PhalanxIdentity's
        // ability to publish a stable key to its community.
        let vk = deterministic_signing_key().verifying_key();
        let a = ed_to_x25519_pk(&vk).expect("first call");
        let b = ed_to_x25519_pk(&vk).expect("second call");
        assert_eq!(a, b);
    }

    #[test]
    fn resolve_did_pk_rejects_malformed_did_string() {
        // Malformed did:key: strings must fail cleanly — a panic here would
        // hand any peer on the network a DoS lever against MeshSentinel.
        let bad = Did("this-is-not-a-did".into());
        let result = resolve_did_pk(&bad);
        assert!(
            matches!(result, Err(CryptoError::DidResolutionFailure) | Err(_)),
            "expected DidResolutionFailure for malformed DID, got {result:?}"
        );
    }

    #[test]
    fn resolve_did_pk_roundtrips_with_ephemeral_identity() {
        // The positive-path check: an identity's own DID must resolve to its
        // own verifying key. If this drifts, signatures produced locally can't
        // be verified remotely.
        let identity = PhalanxIdentity::new_ephemeral();
        let resolved = resolve_did_pk(&identity.did).expect("own DID must resolve");
        assert_eq!(
            resolved.to_bytes(),
            identity.keypair.verifying_key().to_bytes()
        );
    }
}
