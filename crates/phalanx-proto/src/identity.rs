use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize, Default,
)]
pub struct ShardId(pub u32);

impl fmt::Display for ShardId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "shard:{}", self.0)
    }
}



#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct VolleyId(String);

impl VolleyId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VolleyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
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

#[derive(Serialize, Deserialize)]
pub struct Volley {
    pub id: VolleyId,
    pub owner_did: Did,
    pub artifacts: Vec<WitnessEnvelope>,
    pub gaps: Vec<ForensicGap>,
    pub is_complete: bool,
}


#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Did(pub String);

impl Did {
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
pub struct NetworkId(pub libp2p::PeerId);

impl NetworkId {
    /// Generates a random NetworkId (wrapping a random PeerId).
    /// I wrote this purely for testing purposes. This stupid thing
    /// has saved me so much trouble.
}

impl Serialize for NetworkId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_base58())
    }
}

impl<'de> Deserialize<'de> for NetworkId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let peer_id = s.parse().map_err(serde::de::Error::custom)?;
        Ok(NetworkId(peer_id))
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_base58())
    }
}

impl From<PeerId> for NetworkId {
    fn from(peer_id: PeerId) -> Self {
        Self(peer_id)
    }
}

impl From<&PeerId> for NetworkId {
    fn from(peer_id: &PeerId) -> Self {
        Self(*peer_id)
    }
}

impl FromStr for NetworkId {
    type Err = libp2p::identity::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let peer_id = PeerId::from_str(s)?;
        Ok(Self(peer_id))
    }
}

// Ensure the inner PeerId is accessible if needed
impl AsRef<PeerId> for NetworkId {
    fn as_ref(&self) -> &PeerId {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureHash(pub [u8; 32]);

use serde::{Deserialize, Serialize};
use ed25519_dalek::SigningKey;
use std::fmt;

/// The sovereign cryptographic root for a Phalanx Node.
#[derive(Serialize, Deserialize, Clone)]
pub struct PhalanxIdentity {
    pub version: u32,
    pub did: Did,
    pub keypair: SigningKey,
}

impl fmt::Debug for PhalanxIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhalanxIdentity")
            .field("version", &self.version)
            .field("did", &self.did)
            .field("keypair", &"[REDACTED]")
            .finish()
    }
}

impl Default for PhalanxIdentity {
    fn default() -> Self {
        // Defined here structurally, implemented in Node crate
        Self::new_ephemeral() 
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum NodeRole {
    Guardian,
    Stronghold,
}


#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum LocatorError {
    #[error("Locator input is malformed or incorrectly delimited")] MalformedInput,
    #[error("Locator is missing the required author/signer field")] MissingAuthor,
    #[error("Locator scheme is unsupported or invalid: {0}")] InvalidScheme(String),
    #[error("Locator payload exceeds maximum forensic length: {0}")] PayloadTooLarge(usize),
    #[error("Cryptographic signature in locator failed verification")] SignatureMismatch,
    #[error("Internal encoding error: {0}")] Encoding(String),
    #[error("Missing fragment (Decryption Key)")] MissingKey,
    #[error("Malformatted component")] ParseError,
    #[error("Locator is missing a recipient.")] MissingRecipient,
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
        write!(f, "phx://{}#{}@{} > {}", self.id, self.secret, self.author.0, self.recipient_did.0)
    }
}

impl FromStr for PhalanxLocator {
    type Err = LocatorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let remainder = s.strip_prefix("phx://").ok_or_else(|| LocatorError::InvalidScheme(s.to_string()))?;

        let parts: Vec<&str> = remainder.split('#').collect();
        let id_str = parts.first().ok_or(LocatorError::MalformedInput)?.trim();
        let metadata = parts.get(1).ok_or(LocatorError::MissingKey)?.trim();

        let meta_parts: Vec<&str> = metadata.split('@').collect();
        let secret_str = meta_parts.first().ok_or(LocatorError::MalformedInput)?.trim();
        let identities = meta_parts.get(1).ok_or(LocatorError::MissingAuthor)?.trim();

        let id_parts: Vec<&str> = identities.split('>').collect();
        let author_str = id_parts.first().ok_or(LocatorError::MalformedInput)?.trim();
        let recipient_str = id_parts.get(1).ok_or(LocatorError::MissingRecipient)?.trim();

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
        let original_uri = format!("phx://volley-hash-123#secret-key-456@{} > {}", author_did, recipient_did);

        let locator = PhalanxLocator::from_str(&original_uri).expect("Should parse");
        assert_eq!(locator.secret, "secret-key-456");
        assert_eq!(locator.to_string(), original_uri);
    }
}