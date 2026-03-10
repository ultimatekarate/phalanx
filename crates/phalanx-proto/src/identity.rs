use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

pub const IDENTITY_VERSION: u32 = 1;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize, Default,
)]
pub struct ShardId(pub u32);

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct VolleyId(pub String);

impl VolleyId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for VolleyId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.trim().is_empty() {
            Err("VolleyId cannot be empty".to_string())
        } else {
            Ok(Self(s.to_string()))
        }
    }
}

impl From<String> for VolleyId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for VolleyId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Did(pub String);

impl Did {
    pub fn new<S: Into<String>>(val: S) -> Self {
        Self(val.into())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Sanitizes the DID string for use in file paths or unsafe contexts.
    /// Replaces colons `:` with underscores `_`.
    #[must_use]
    pub fn to_safe_name(&self) -> String {
        self.0.replace(":", "_")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for Did {
    fn default() -> Self {
        Self("did:key:anonymous".to_string())
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for Did {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for Did {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<str> for Did {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkId(pub String);

impl NetworkId {
    /// Returns the forensic identifier as a Base58 string.
    /// In the Dictionary layer, this is an identity operation as the
    /// representation is already encoded.
    #[inline]
    pub fn to_base58(&self) -> &str {
        &self.0
    }

    /// Generates a random NetworkId for testing.
    pub fn random() -> Self {
        use rand::Rng;
        let bytes: [u8; 32] = rand::rng().random();
        Self(bs58::encode(bytes).into_string())
    }
}

impl From<String> for NetworkId {
    fn from(id_string: String) -> Self {
        Self(id_string)
    }
}

impl From<&str> for NetworkId {
    fn from(id_str: &str) -> Self {
        Self(id_str.to_string())
    }
}

impl FromStr for NetworkId {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureHash(pub [u8; 32]);

/// The sovereign cryptographic root for a Phalanx Node.
#[derive(Clone, Serialize, Deserialize)]
pub struct PhalanxIdentity {
    pub version: u32,
    pub did: Did,
    pub network_id: NetworkId,
    pub keypair: SigningKey,
}

impl PhalanxIdentity {
    /// Generates a new, non-persistent identity.
    ///
    /// This is a "Verb" performed within the Dictionary to initialize the "Noun."
    /// It utilizes OsRng for entropy, ensuring the identity is cryptographically unique.
    pub fn new_ephemeral() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        // 1. Derive Forensic NetworkId
        // We use the Base58 encoding of the public key. In the Phalanx mesh,
        // this string is used by the Hands layer to reconstruct a libp2p PeerId.
        let public_key_bytes = verifying_key.to_bytes();
        let network_id_string = bs58::encode(public_key_bytes).into_string();
        let network_id = NetworkId(network_id_string);

        // 2. Derive Decentralized Identifier (DID)
        // Follows the did:key format using the Ed25519 multicodec prefix (0xed01)
        let mut multicodec_payload = vec![0xed, 0x01];
        multicodec_payload.extend_from_slice(&public_key_bytes);
        let multibase_pubkey = bs58::encode(multicodec_payload).into_string();
        let did = Did(format!("did:key:z{}", multibase_pubkey));

        Self {
            version: IDENTITY_VERSION,
            did,
            network_id,
            keypair: signing_key,
        }
    }
}

impl Default for PhalanxIdentity {
    fn default() -> Self {
        Self::new_ephemeral()
    }
}

impl std::fmt::Debug for PhalanxIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhalanxIdentity")
            .field("version", &self.version)
            .field("did", &self.did)
            .field("network_id", &self.network_id)
            .field("keypair", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
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
