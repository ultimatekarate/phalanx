use crate::primitives::identity::NetworkId;
use crate::storage::strategies::VolleyId;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

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
    pub author: NetworkId,
}

#[derive(Debug, Error)]
pub enum LocatorError {
    #[error("Invalid URI format: missing 'phx://' prefix")]
    InvalidScheme,
    #[error("Missing fragment (Decryption Key)")]
    MissingKey,
    #[error("Missing author DID")]
    MissingAuthor,
    #[error("Malformatted component")]
    ParseError,
    #[error("Invalid NetworkId {0}")]
    InvalidNetworkId(String),
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
        let remainder = s.strip_prefix("phx://").ok_or(LocatorError::InvalidScheme)?;

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
        let secret_str = secret_parts[0];
        let author_str = secret_parts[1];

        // 4. Construct
        Ok(PhalanxLocator {
            id: VolleyId::from_str(id_str).map_err(|_| LocatorError::ParseError)?,
            secret: secret_str.to_string(),
            author: NetworkId::from_str(author_str)
                .map_err(|e| LocatorError::InvalidNetworkId(e.to_string()))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locator_roundtrip() {
        let original_uri = "phx://volley-hash-123#secret-key-456@did:phx:user-789";
        let locator = PhalanxLocator::from_str(original_uri).expect("Should parse");
        
        assert_eq!(locator.secret, "secret-key-456");
        assert_eq!(locator.to_string(), original_uri);
    }
}