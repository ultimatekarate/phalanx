use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use phalanx_proto::community::{CommunityId, Vouch, VouchSignature};
use phalanx_proto::crypto::CryptoError;
use phalanx_proto::network::{BleChallenge, BleResponse};
use phalanx_proto::prelude::*;
use phalanx_proto::time::PhalanxTimestamp;

pub fn resolve_did_public_key(did: &Did) -> Result<[u8; 32], CryptoError> {
    // Safe Prefix Handling (Zero-Panic)
    // Replaces: let multibase_str = &s["did:key:".len()..];
    let multibase_str = did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or(CryptoError::DidResolutionFailure)?;

    // Safe Multibase Detection
    // Replaces: if !multibase_str.starts_with('z') ... decode(&multibase_str[1..])
    let encoded_key = multibase_str
        .strip_prefix('z')
        .ok_or(CryptoError::DidResolutionFailure)?;

    let bytes = bs58::decode(encoded_key)
        .into_vec()
        .map_err(|_| CryptoError::DidResolutionFailure)?;

    // Safe Multicodec Extraction (Zero-Panic)
    // Replaces: if bytes.len() == 34 && bytes[0] == 0xed ... copy_from_slice(&bytes[2..])
    match bytes.as_slice() {
        [0xed, 0x01, key_bytes @ ..] if key_bytes.len() == 32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(key_bytes);
            Ok(key)
        }
        _ => Err(CryptoError::DidResolutionFailure),
    }
}

// ── Vouch Signature Verification ────────────────────────────────────────

/// Verify a single vouch: Ed25519 signature over (member_did || community_fingerprint || joined_at).
/// Pure logic — no IO.
pub fn verify_vouch(
    vouch: &Vouch,
    member_did: &Did,
    community_id: &CommunityId,
    joined_at: PhalanxTimestamp,
) -> Result<(), CryptoError> {
    let pk_bytes = resolve_did_public_key(&vouch.voucher_did)?;
    let verifying_key =
        VerifyingKey::from_bytes(&pk_bytes).map_err(|_| CryptoError::DidResolutionFailure)?;

    let sig_bytes: [u8; 64] = vouch
        .signature
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    let signature = Signature::from_bytes(&sig_bytes);

    // Reconstruct the signed message: member_did || community_fingerprint || joined_at
    let mut message = Vec::new();
    message.extend_from_slice(member_did.as_ref().as_bytes());
    message.extend_from_slice(&community_id.0);
    message.extend_from_slice(&joined_at.0.to_le_bytes());

    verifying_key
        .verify(&message, &signature)
        .map_err(|_| CryptoError::DecryptionFailure)
}

// ── Vouch Signing ──────────────────────────────────────────────────────

/// Sign a vouch: Ed25519 signature over (member_did || community_fingerprint || joined_at).
/// Pure logic — no IO. The inverse of [`verify_vouch`].
pub fn sign_vouch(
    signer: &SigningKey,
    signer_did: &Did,
    member_did: &Did,
    community_id: &CommunityId,
    joined_at: PhalanxTimestamp,
) -> Vouch {
    let mut message = Vec::new();
    message.extend_from_slice(member_did.as_ref().as_bytes());
    message.extend_from_slice(&community_id.0);
    message.extend_from_slice(&joined_at.0.to_le_bytes());

    let signature = signer.sign(&message);
    Vouch {
        voucher_did: signer_did.clone(),
        signature: VouchSignature::new(signature.to_bytes()),
    }
}

// ── BLE Challenge-Response Verification ─────────────────────────────────

/// Build the message that must be signed for a BLE auth response.
/// message = responder_did || challenger_did || challenge_nonce
pub fn ble_auth_message(
    responder_did: &Did,
    challenger_did: &Did,
    challenge_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(responder_did.as_ref().as_bytes());
    msg.extend_from_slice(challenger_did.as_ref().as_bytes());
    msg.extend_from_slice(challenge_nonce);
    msg
}

/// Verify a BLE auth response: check that the responder's signature is valid.
/// Pure logic — no IO.
pub fn verify_ble_response(
    challenge: &BleChallenge,
    response: &BleResponse,
) -> Result<(), CryptoError> {
    let pk_bytes = resolve_did_public_key(&response.responder_did)?;
    let verifying_key =
        VerifyingKey::from_bytes(&pk_bytes).map_err(|_| CryptoError::DidResolutionFailure)?;

    let sig_bytes: [u8; 64] = response
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    let signature = Signature::from_bytes(&sig_bytes);

    let message = ble_auth_message(
        &response.responder_did,
        &challenge.sender_did,
        &challenge.nonce,
    );

    verifying_key
        .verify(&message, &signature)
        .map_err(|_| CryptoError::DecryptionFailure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use phalanx_proto::identity::Did;
    use rand_core::OsRng;

    fn make_identity() -> (Did, SigningKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pk_bytes = signing_key.verifying_key().to_bytes();
        let did = Did::derive_did_key(&pk_bytes);
        (did, signing_key)
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let (voucher_did, voucher_sk) = make_identity();
        let (member_did, _) = make_identity();
        let community_id = CommunityId([42u8; 32]);
        let joined_at = PhalanxTimestamp(1000);

        let vouch = sign_vouch(
            &voucher_sk,
            &voucher_did,
            &member_did,
            &community_id,
            joined_at,
        );
        assert!(verify_vouch(&vouch, &member_did, &community_id, joined_at).is_ok());
    }

    #[test]
    fn sign_vouch_wrong_community_fails() {
        let (voucher_did, voucher_sk) = make_identity();
        let (member_did, _) = make_identity();
        let community_id = CommunityId([42u8; 32]);
        let wrong_id = CommunityId([99u8; 32]);
        let joined_at = PhalanxTimestamp(1000);

        let vouch = sign_vouch(
            &voucher_sk,
            &voucher_did,
            &member_did,
            &community_id,
            joined_at,
        );
        // Verify against wrong community — should fail
        assert!(verify_vouch(&vouch, &member_did, &wrong_id, joined_at).is_err());
    }

    #[test]
    fn vouch_verification_valid() {
        let (voucher_did, voucher_sk) = make_identity();
        let (member_did, _) = make_identity();
        let community_id = CommunityId([42u8; 32]);
        let joined_at = PhalanxTimestamp(1000);

        // Build the message and sign it
        let mut msg = Vec::new();
        msg.extend_from_slice(member_did.as_ref().as_bytes());
        msg.extend_from_slice(&community_id.0);
        msg.extend_from_slice(&joined_at.0.to_le_bytes());

        let sig = voucher_sk.sign(&msg);

        let vouch = Vouch {
            voucher_did: voucher_did.clone(),
            signature: VouchSignature::new(sig.to_bytes()),
        };

        assert!(verify_vouch(&vouch, &member_did, &community_id, joined_at).is_ok());
    }

    #[test]
    fn vouch_verification_wrong_member_fails() {
        let (voucher_did, voucher_sk) = make_identity();
        let (member_did, _) = make_identity();
        let (wrong_did, _) = make_identity();
        let community_id = CommunityId([42u8; 32]);
        let joined_at = PhalanxTimestamp(1000);

        let mut msg = Vec::new();
        msg.extend_from_slice(member_did.as_ref().as_bytes());
        msg.extend_from_slice(&community_id.0);
        msg.extend_from_slice(&joined_at.0.to_le_bytes());

        let sig = voucher_sk.sign(&msg);

        let vouch = Vouch {
            voucher_did,
            signature: VouchSignature::new(sig.to_bytes()),
        };

        // Verify against wrong member DID — should fail
        assert!(verify_vouch(&vouch, &wrong_did, &community_id, joined_at).is_err());
    }

    #[test]
    fn ble_auth_valid_response() {
        let (challenger_did, _) = make_identity();
        let (responder_did, responder_sk) = make_identity();

        let challenge = BleChallenge {
            sender_did: challenger_did.clone(),
            nonce: [99u8; 32],
        };

        let msg = ble_auth_message(&responder_did, &challenger_did, &challenge.nonce);
        let sig = responder_sk.sign(&msg);

        let response = BleResponse {
            responder_did: responder_did.clone(),
            signature: sig.to_bytes().to_vec(),
        };

        assert!(verify_ble_response(&challenge, &response).is_ok());
    }

    #[test]
    fn ble_auth_wrong_key_fails() {
        let (challenger_did, _) = make_identity();
        let (responder_did, _) = make_identity();
        let (_, wrong_sk) = make_identity(); // different key!

        let challenge = BleChallenge {
            sender_did: challenger_did.clone(),
            nonce: [99u8; 32],
        };

        let msg = ble_auth_message(&responder_did, &challenger_did, &challenge.nonce);
        let sig = wrong_sk.sign(&msg); // signed with wrong key

        let response = BleResponse {
            responder_did: responder_did.clone(),
            signature: sig.to_bytes().to_vec(),
        };

        assert!(verify_ble_response(&challenge, &response).is_err());
    }
}
