use crate::primitives::identity::Did;
use crate::primitives::shards::VolleyId;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
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

    #[error("I/O error during locator resolution: {0}")]
    Io(#[from] std::io::Error),

    #[error("Internal encoding error: {0}")]
    Encoding(String),
    #[error("Missing fragment (Decryption Key)")]
    MissingKey,
    #[error("Malformatted component")]
    ParseError,
    #[error("Invalid NetworkId {0}")]
    InvalidNetworkId(String),
}

// Result type alias for locator operations
pub type LocatorResult<T> = Result<T, LocatorError>;

/// A self-contained, shareable locator for a specific forensic event (Volley).
///
/// This struct encapsulates all information required for a remote peer to:
/// 1. Locate the data on the DHT (via `id`).
/// 2. Decrypt the content (via `secret`).
/// 3. Verify the provenance (via `author`).
///
/// # Security Warning
/// This locator contains the **Decryption Key**. Possession of this string
/// grants full visibility of the evidence. It must be transmitted over secure channels.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhalanxLocator {
    /// The content-addressable hash of the Volley (Video).
    pub id: VolleyId,
    /// The symmetric key (base64 encoded) to decrypt the WitnessEnvelope.
    pub secret: String,
    /// The Decentralized Identifier of the original witness (Author).
    pub author: Did,
}

impl fmt::Display for PhalanxLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format: phx://<ID>#<KEY>@<AUTHOR>
        write!(f, "phx://{}#{}@{}", self.id, self.secret, self.author)
    }
}

impl FromStr for PhalanxLocator {
    type Err = LocatorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // 1. Check Protocol Scheme
        let remainder = s
            .strip_prefix("phx://")
            .ok_or_else(||LocatorError::InvalidScheme(s.to_string()))?;

        // 2. Split ID and Rest (Key + Author)
        let parts: Vec<&str> = remainder.split('#').collect();
        if parts.len() != 2 {
            return Err(LocatorError::MissingKey);
        }
        let id_str = parts[0];
        let rest = parts[1];

        // 3. Split Key and Author
        let secret_parts: Vec<&str> = rest.split('@').collect();
        if secret_parts.len() != 2 {
            return Err(LocatorError::MissingAuthor);
        }
        let secret_str = secret_parts.get(0).ok_or(LocatorError::MalformedInput)?; // Ensure this error variant exists

        let author_str = secret_parts.get(1).ok_or(LocatorError::MissingAuthor)?;

        // 4. Construct
        Ok(PhalanxLocator {
            id: VolleyId::from_str(id_str).map_err(|_| LocatorError::ParseError)?,
            secret: secret_str.to_string(),
            author: Did(author_str.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locator_roundtrip() {
        // Hardcoded id for testing purposes
        let valid_peer_id = "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";

        let original_uri = format!("phx://volley-hash-123#secret-key-456@{}", valid_peer_id);
        let locator = PhalanxLocator::from_str(&original_uri).expect("Should parse");

        assert_eq!(locator.secret, "secret-key-456");
        assert_eq!(locator.id.to_string(), "volley-hash-123");
        assert_eq!(locator.author.to_string(), valid_peer_id);
        assert_eq!(locator.to_string(), original_uri);
    }
}
