use bip39::Mnemonic;
use ed25519_dalek::SigningKey;

use phalanx_proto::prelude::Did;
use phalanx_proto::prelude::IdentityError;
use phalanx_proto::prelude::NetworkId;
use phalanx_proto::prelude::PhalanxIdentity;
use phalanx_proto::prelude::VolleyId;
use phalanx_proto::VolleyRequest;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::Path;
use std::str::FromStr;

pub const IDENTITY_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureHash(pub [u8; 32]);

pub trait PhalanxNodeIdentityExt: Sized {
    fn generate() -> Result<(Self, String), IdentityError>;
    fn restore(phrase: &str) -> Result<Self, IdentityError>;
    fn save_to_disk<P: AsRef<Path>>(&self, path: P) -> Result<(), IdentityError>;
    fn load_from_disk<P: AsRef<Path>>(path: P) -> Result<Self, IdentityError>;
    fn verify_retrieval_auth(&self, request: &VolleyRequest) -> Result<(), IdentityError>;
    fn init<P: AsRef<Path>>(path: P) -> Result<Self, IdentityError>;
}

impl PhalanxNodeIdentityExt for PhalanxIdentity {
    fn generate() -> Result<(Self, String), IdentityError> {
        let mut rng = rand::rng();
        let mut entropy = [0u8; 16];
        rng.fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|e: bip39::Error| IdentityError::EntropyError(e.to_string()))?;
        let phrase = mnemonic.to_string();
        let seed = mnemonic.to_seed("");

        let secret_bytes: [u8; 32] = seed[0..32]
            .try_into()
            .map_err(|_| IdentityError::CryptoError("Seed fail".into()))?;

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_bytes();

        // Derive did:key using Ed25519 multicodec prefix (0xed, 0x01)
        let mut multicodec_payload = vec![0xed, 0x01];
        multicodec_payload.extend_from_slice(&public_key_bytes);
        let multibase_pubkey = bs58::encode(multicodec_payload).into_string();

        Ok((
            PhalanxIdentity {
                network_id: NetworkId::random(),
                version: IDENTITY_VERSION,
                did: Did::from(format!("did:key:z{}", multibase_pubkey)),
                keypair: signing_key,
            },
            phrase,
        ))
    }

    fn restore(phrase: &str) -> Result<Self, IdentityError> {
        let mnemonic = Mnemonic::parse(phrase)
            .map_err(|e: bip39::Error| IdentityError::MnemonicError(e.to_string()))?;
        let seed = mnemonic.to_seed("");
        let secret_bytes: [u8; 32] = seed[0..32]
            .try_into()
            .map_err(|_| IdentityError::CryptoError("Seed fail".into()))?;

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_bytes();

        let mut multicodec_payload = vec![0xed, 0x01];
        multicodec_payload.extend_from_slice(&public_key_bytes);
        let multibase_pubkey = bs58::encode(multicodec_payload).into_string();

        Ok(PhalanxIdentity {
            network_id: NetworkId::random(),
            version: IDENTITY_VERSION,
            did: Did::from(format!("did:key:z{}", multibase_pubkey)),
            keypair: signing_key,
        })
    }

    fn save_to_disk<P: AsRef<Path>>(&self, path: P) -> Result<(), IdentityError> {
        let bytes = postcard::to_allocvec(self)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;
        fs::write(path, bytes).map_err(|e| IdentityError::Corruption(e.to_string()))
    }

    fn load_from_disk<P: AsRef<Path>>(path: P) -> Result<Self, IdentityError> {
        let bytes = fs::read(path).map_err(|e| IdentityError::Corruption(e.to_string()))?;
        postcard::from_bytes(&bytes).map_err(|e| IdentityError::SerializationError(e.to_string()))
    }

    fn verify_retrieval_auth(&self, request: &VolleyRequest) -> Result<(), IdentityError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // 1. Resolve the public key of the claimed recipient (the requester)
        let pk_bytes =
            phalanx_forensics::identity::resolve_did_public_key(&request.locator.recipient)
                .map_err(|_| IdentityError::CryptoError("DID Resolution Failed".into()))?;

        let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| IdentityError::CryptoError(format!("Invalid Public Key: {}", e)))?;

        // 2. Reconstruct the signed message payload
        let signed_data = (&request.target_did, &request.volley_id, &request.locator);
        let msg = postcard::to_allocvec(&signed_data)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

        // 3. Verify the signature
        let signature = Signature::from_slice(&request.signature)
            .map_err(|e| IdentityError::CryptoError(format!("Invalid Signature: {}", e)))?;

        verifying_key
            .verify(&msg, &signature)
            .map_err(|_| IdentityError::CryptoError("Signature Verification Failed".into()))
    }

    fn init<P: AsRef<Path>>(path: P) -> Result<Self, IdentityError> {
        // FIX: Replaced IoError match with an explicit path check
        if !path.as_ref().exists() {
            tracing::warn!("Sovereign root: NOT FOUND. Initiating Genesis...");

            let (new_identity, mnemonic) = Self::generate()?;
            tracing::info!("!!! GENESIS SUCCESSFUL !!!");
            tracing::info!("RESTORE PHRASE: {}", mnemonic);

            new_identity.save_to_disk(&path)?;
            return Ok(new_identity);
        }

        match Self::load_from_disk(&path) {
            Ok(identity) => {
                tracing::info!(path = ?path.as_ref(), "Sovereign root: RESTORED");
                Ok(identity)
            }
            Err(err) => {
                tracing::error!(error = %err, "Sovereign root: CORRUPTED or UNREADABLE");
                Err(err)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum NodeRole {
    Guardian,
    Stronghold,
}

#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum LocatorError {
    #[error("Locator input is malformed or incorrectly delimited")]
    MalformedInput,
    #[error("Locator is missing the required author/signer field")]
    MissingAuthor,
    #[error("Locator scheme is unsupported or invalid: {0}")]
    InvalidScheme(String),
    #[error("Locator payload exceeds maximum forensic length: {0}")]
    PayloadTooLarge(usize),
    #[error("Cryptographic signature in locator failed verification")]
    SignatureMismatch,
    #[error("Internal encoding error: {0}")]
    Encoding(String),
    #[error("Missing fragment (Decryption Key)")]
    MissingKey,
    #[error("Malformatted component")]
    ParseError,
    #[error("Locator is missing a recipient.")]
    MissingRecipient,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhalanxLocator {
    pub id: VolleyId,
    pub secret: String,
    pub author: crate::identity::Did,
    pub recipient_did: crate::identity::Did,
}

impl fmt::Display for PhalanxLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // phx://[id]#[secret]@[author]>[recipient]
        write!(
            f,
            "phx://{}#{}@{} > {}",
            self.id, self.secret, self.author.0, self.recipient_did.0
        )
    }
}

impl FromStr for PhalanxLocator {
    type Err = LocatorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let remainder = s
            .strip_prefix("phx://")
            .ok_or_else(|| LocatorError::InvalidScheme(s.to_string()))?;

        let parts: Vec<&str> = remainder.split('#').collect();
        let id_str = parts.first().ok_or(LocatorError::MalformedInput)?.trim();
        let metadata = parts.get(1).ok_or(LocatorError::MissingKey)?.trim();

        let meta_parts: Vec<&str> = metadata.split('@').collect();
        let secret_str = meta_parts
            .first()
            .ok_or(LocatorError::MalformedInput)?
            .trim();
        let identities = meta_parts.get(1).ok_or(LocatorError::MissingAuthor)?.trim();

        let id_parts: Vec<&str> = identities.split('>').collect();
        let author_str = id_parts.first().ok_or(LocatorError::MalformedInput)?.trim();
        let recipient_str = id_parts
            .get(1)
            .ok_or(LocatorError::MissingRecipient)?
            .trim();

        Ok(PhalanxLocator {
            id: VolleyId::from_str(id_str).map_err(|_| LocatorError::ParseError)?,
            secret: secret_str.to_string(),
            author: crate::identity::Did(author_str.to_string()),
            recipient_did: crate::identity::Did(recipient_str.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locator_roundtrip() {
        let author_did = "did:key:z6MkqAWvMbaN66VtXfBTMu7XGvGWW3i8GfV9f8f8f8f8f";
        let recipient_did = "did:key:z6MkpTHR8VNsBxY9jnLpqfPLz6NfSu2yt";
        let original_uri = format!(
            "phx://volley-hash-123#secret-key-456@{} > {}",
            author_did, recipient_did
        );

        let locator = PhalanxLocator::from_str(&original_uri).expect("Should parse");
        assert_eq!(locator.secret, "secret-key-456");
        assert_eq!(locator.to_string(), original_uri);
    }
}
