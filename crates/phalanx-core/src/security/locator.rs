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
    #[error("Locator is missing a recipient.")]
    MissingRecipient,
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
    // only person allowed to use this grant
    pub recipient_did: Did,
}

impl fmt::Display for PhalanxLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Canonical format must match the parser's logic:
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
        // 1. Check Protocol Scheme
        let remainder = s
            .strip_prefix("phx://")
            .ok_or_else(|| LocatorError::InvalidScheme(s.to_string()))?;

        // 2. Split Volley ID and the Metadata block
        // Format: id#metadata
        let parts: Vec<&str> = remainder.split('#').collect();
        let id_str = parts.first().ok_or(LocatorError::MalformedInput)?.trim();
        let metadata = parts.get(1).ok_or(LocatorError::MissingKey)?.trim();

        // 3. Split the Metadata block into Secret and Identities
        // Format: secret@identities
        let meta_parts: Vec<&str> = metadata.split('@').collect();
        let secret_str = meta_parts
            .first()
            .ok_or(LocatorError::MalformedInput)?
            .trim();
        let identities = meta_parts.get(1).ok_or(LocatorError::MissingAuthor)?.trim();

        // 4. Split Identities into Author and Recipient
        // Format: author>recipient
        let id_parts: Vec<&str> = identities.split('>').collect();
        let author_str = id_parts.first().ok_or(LocatorError::MalformedInput)?.trim();
        let recipient_str = id_parts
            .get(1)
            .ok_or(LocatorError::MissingRecipient)?
            .trim();

        // 5. Construct with Forensic Validation
        // This ensures the locator is "sealed" to the intended recipient from the moment of parsing
        Ok(PhalanxLocator {
            id: VolleyId::from_str(id_str).map_err(|_| LocatorError::ParseError)?,
            secret: secret_str.to_string(),
            author: Did(author_str.to_string()),
            recipient_did: Did(recipient_str.to_string()), // RESOLVED: Parsed from string
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::identity::PhalanxIdentity;

    use tracing::info;
    #[test]
    fn test_locator_roundtrip() {
        // 1. Define the identities involved in the forensic grant
        let author_did = "did:key:z6MkqAWvMbaN66VtXfBTMu7XGvGWW3i8GfV9f8f8f8f8f";
        let recipient_did = "did:key:z6MkpTHR8VNsBxY9jnLpqfPLz6NfSu2yt"; // The "Who"

        // 2. Update URI to the authorized format: phx://[id]#[secret]@[author]>[recipient]
        let original_uri = format!(
            "phx://volley-hash-123#secret-key-456@{} > {}",
            author_did, recipient_did
        );

        // 3. Parse and Validate
        let locator = PhalanxLocator::from_str(&original_uri)
            .expect("Should parse with authorized recipient");

        // 4. Assertions
        assert_eq!(locator.secret, "secret-key-456");
        assert_eq!(locator.id.to_string(), "volley-hash-123");
        assert_eq!(locator.author.0, author_did);
        assert_eq!(locator.recipient_did.0, recipient_did); // Verify privacy target

        // 5. Verify Roundtrip (to_string must match from_str input)
        assert_eq!(locator.to_string(), original_uri);
    }

    #[test]
    fn test_unauthorized_retrieval_rejection() {
        // 1. Setup Identities
        let author = PhalanxIdentity::generate().unwrap().0;
        let authorized_investigator = PhalanxIdentity::generate().unwrap().0;
        let malicious_attacker = PhalanxIdentity::generate().unwrap().0;

        // 2. Author creates a locator intended EXCLUSIVELY for the authorized investigator
        let volley_id = VolleyId::new("forensic-event-001");
        let original_uri = format!(
            "phx://{}#top-secret-key@{} > {}",
            volley_id,
            author.did.0,
            authorized_investigator.did.0 // Sealing the grant to the investigator
        );

        // 3. Malicious Attacker intercepts the URI and attempts to parse it
        let locator = PhalanxLocator::from_str(&original_uri)
            .expect("Parser should successfully extract the recipient DID");

        // 4. Attacker attempts to forge a signature using THEIR identity
        // Challenge: The signature must be over the VolleyId bytes
        let challenge = volley_id.as_str().as_bytes();
        let malicious_signature = malicious_attacker.sign(challenge);

        // 5. Simulation: The PhalanxEngine (Sentinel) runs verify_retrieval_auth
        // We construct a mock VolleyRequest as the engine would receive it over the wire
        let malicious_request = crate::transport::protocol::VolleyRequest {
            target_did: author.did.clone(),
            volley_id: volley_id.clone(),
            locator: locator.clone(),
            signature: malicious_signature.to_bytes().to_vec(),
        };

        // 6. ASSERTION: The Identity Gate MUST fail
        // Even though the attacker has the URI and a valid self-signed signature,
        // the signature will not validate against the 'recipient_did' inside the locator.
        let result = authorized_investigator.verify_retrieval_auth(&malicious_request);

        assert!(
            result.is_err(),
            "Privacy Breach: The engine allowed an attacker to pass the Identity Gate."
        );

        info!("Privacy Gate confirmed: Blocked unauthorized retrieval from identity mismatch.");
    }
}
