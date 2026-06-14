use crate::crypto::DekMaster;
use crate::error::IdentityError;
use crate::revocation::RevocationKey;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Schema version of the on-disk identity format.
///
/// v1: legacy random-DEK regime; per-recording DEKs lived only in the
///     content keyring on the local device.
/// v2: deterministic DEK derivation; `dek_master_bytes` is persisted so a
///     cold-booted node can derive per-recording keys without re-typing the
///     BIP39 phrase. v1 files require re-restore from phrase to upgrade.
pub const IDENTITY_VERSION: u32 = 2;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize, Default,
)]
pub struct ShardId(pub u64);

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct RecordingId(pub String);

impl RecordingId {
    /// H1: Maximum byte length for a RecordingId on the wire.
    pub const MAX_WIRE_LEN: usize = 256;

    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Sanitizes the recording-id string for use in file paths. Mirrors
    /// `Did::to_safe_name` — non-`[a-zA-Z0-9_-]` chars become `_`, any
    /// surviving non-`Component::Normal` path falls back to a DJB2 hash,
    /// and an empty result becomes `"_empty_"`.
    ///
    /// Wire form is preserved by `as_str()` / `Display`; this method is
    /// strictly for fs-path construction.
    #[must_use]
    pub fn to_safe_name(&self) -> String {
        let sanitized: String = self
            .0
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();

        if std::path::Path::new(&sanitized)
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return format!("_hash_{:08x}", {
                let mut h: u32 = 5381;
                for b in self.0.as_bytes() {
                    h = h.wrapping_mul(33).wrapping_add(u32::from(*b));
                }
                h
            });
        }

        if sanitized.is_empty() {
            "_empty_".to_string()
        } else {
            sanitized
        }
    }
}

impl std::str::FromStr for RecordingId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.trim().is_empty() {
            Err("RecordingId cannot be empty".to_string())
        } else {
            Ok(Self(s.to_string()))
        }
    }
}

impl From<String> for RecordingId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for RecordingId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Did(pub String);

impl Did {
    /// H1: Maximum byte length for a DID on the wire.
    /// A valid `did:key:z...` with Ed25519 is ~60 bytes; 512 is generous.
    pub const MAX_WIRE_LEN: usize = 512;

    pub fn new<S: Into<String>>(val: S) -> Self {
        Self(val.into())
    }

    /// Derives a `did:key` identifier from a raw Ed25519 public key.
    /// Uses the Ed25519 multicodec prefix (0xed, 0x01) and multibase 'z' (base58btc).
    pub fn derive_did_key(public_key: &[u8; 32]) -> Self {
        let mut multicodec_payload = vec![0xed, 0x01];
        multicodec_payload.extend_from_slice(public_key);
        let multibase_pubkey = bs58::encode(multicodec_payload).into_string();
        Self(format!("did:key:z{}", multibase_pubkey))
    }

    /// Converts a `did:key:` DID to a `WitnessId` by stripping the `did:key:` prefix.
    /// The resulting `WitnessId` is the canonical multibase form (`z6Mk...`).
    #[must_use]
    pub fn to_witness_id(&self) -> WitnessId {
        WitnessId(
            self.0
                .strip_prefix("did:key:")
                .unwrap_or(&self.0)
                .to_string(),
        )
    }

    /// Reconstructs a `did:key:` DID from a `WitnessId` (canonical multibase form).
    #[must_use]
    pub fn from_witness_id(id: &WitnessId) -> Self {
        Self(format!("did:key:{}", id.0))
    }

    /// Reconstructs a `did:key:` DID from a `MeshAddress` by string-prepending
    /// the `did:key:` prefix.
    ///
    /// **Note:** A `MeshAddress` is libp2p PeerId multihash form, which is NOT
    /// the same encoding as the DID multibase form. The resulting DID is
    /// reachable as a HashMap key (string round-trip works) but is NOT
    /// cryptographically valid as a real `did:key`. This shim exists for the
    /// trust system's mesh-keyed lookups; do not use it where DID validity
    /// matters.
    #[must_use]
    pub fn from_mesh_address(addr: &MeshAddress) -> Self {
        Self(format!("did:key:{}", addr.0))
    }

    /// Converts a `did:key:` DID to a `MeshAddress` by stripping the `did:key:`
    /// prefix. See `from_mesh_address` for the cryptographic caveat.
    #[must_use]
    pub fn to_mesh_address(&self) -> MeshAddress {
        MeshAddress(
            self.0
                .strip_prefix("did:key:")
                .unwrap_or(&self.0)
                .to_string(),
        )
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Sanitizes the DID string for use in file paths.
    ///
    /// M2 FIX: Defensive sanitization — replaces all characters that are not
    /// alphanumeric, hyphen, or underscore with underscores, then rejects any
    /// result containing path traversal components.
    #[must_use]
    pub fn to_safe_name(&self) -> String {
        let sanitized: String = self
            .0
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();

        // M1 FIX: Runtime traversal check (promoted from debug_assert).
        // The character-level sanitization above should make traversal impossible,
        // but if it ever fails, fall back to a hash-based name rather than
        // silently producing a traversal path in production.
        if std::path::Path::new(&sanitized)
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            // Should be unreachable given the sanitization above, but fail safe.
            return format!("_hash_{:08x}", {
                let mut h: u32 = 5381;
                for b in self.0.as_bytes() {
                    h = h.wrapping_mul(33).wrapping_add(u32::from(*b));
                }
                h
            });
        }

        // Final guard: if empty after sanitization, return a fixed placeholder
        if sanitized.is_empty() {
            "_empty_".to_string()
        } else {
            sanitized
        }
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

/// Forensic identity: bs58-encoded multibase form (e.g. `z6Mk...`).
///
/// Round-trips with `Did` via `Did::to_witness_id` / `Did::from_witness_id`.
/// Stable across transport changes — used by every signed `WitnessEnvelope`,
/// `CausalitySession`, persisted evidence record. A `WitnessId` produced
/// today must remain valid against the same keypair material in 2030 even if
/// the underlying mesh transport (libp2p) is replaced.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WitnessId(pub String);

impl WitnessId {
    /// H1: Maximum byte length for a WitnessId on the wire.
    pub const MAX_WIRE_LEN: usize = 256;

    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the multibase-encoded forensic identifier as a Base58 string.
    #[inline]
    pub fn to_base58(&self) -> &str {
        &self.0
    }

    /// Generates a random WitnessId for testing. Produces a multibase-shaped
    /// string (`z`-prefixed base58); the bytes do NOT decode to a valid
    /// Ed25519 public key, so this must only be used as a test fixture.
    pub fn random() -> Self {
        use rand::Rng;
        let bytes: [u8; 32] = rand::thread_rng().r#gen();
        Self(format!("z{}", bs58::encode(bytes).into_string()))
    }
}

impl std::fmt::Display for WitnessId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Mesh routing address: a libp2p `PeerId` rendered in base58 multibase form
/// (e.g. `12D3KooW...`).
///
/// Round-trips through `PeerMapper::from_mesh_address` → `PeerId::from_str`.
/// This type does **not** import any libp2p type — only the *format* is
/// libp2p-flavoured. Per the linguistic-code-model rule that the Dictionary
/// must not depend on libp2p, the format discipline is enforced at the
/// `phalanx-transport` boundary, not by this type's constructor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MeshAddress(pub String);

impl MeshAddress {
    /// H1: Maximum byte length for a MeshAddress on the wire.
    pub const MAX_WIRE_LEN: usize = 256;

    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Generates a random MeshAddress for testing. Produces an arbitrary
    /// base58 string; the bytes do NOT decode to a valid libp2p PeerId, so
    /// this must only be used as a test fixture.
    pub fn random() -> Self {
        use rand::Rng;
        let bytes: [u8; 32] = rand::thread_rng().r#gen();
        Self(bs58::encode(bytes).into_string())
    }
}

impl std::fmt::Display for MeshAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureHash(pub [u8; 32]);

/// The sovereign cryptographic root for a Phalanx Node.
///
/// M6 FIX: Removed Serialize/Deserialize to prevent accidental private key leakage.
/// Disk persistence is handled via an explicit `IdentityDiskFormat` in the node crate
/// that serializes keypair bytes only through the encrypted save/load path.
#[derive(Clone)]
pub struct PhalanxIdentity {
    pub version: u32,
    pub did: Did,
    /// Forensic identifier. Multibase form (`z6Mk...`); round-trips with `did`
    /// via `Did::to_witness_id` / `Did::from_witness_id`.
    pub witness_id: WitnessId,
    pub keypair: SigningKey,
    /// The public half of the revocation keypair. Derived from BIP39 mnemonic
    /// (seed bytes [32..64]). Default (all zeros) for ephemeral identities.
    pub revocation_key: RevocationKey,
    /// HKDF-derived master from which every per-recording DEK is expanded.
    /// Computed once from the BIP39 seed at genesis/restore. Persisted in
    /// `IdentityDiskFormat` under the same Argon2id passphrase wall as the
    /// keypair, so cold-boot can derive without re-typing the phrase.
    pub dek_master: DekMaster,
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

        let public_key_bytes = verifying_key.to_bytes();

        // Derive Decentralized Identifier (DID) first, then derive the
        // forensic `WitnessId` from it. This produces the canonical
        // multibase form (`z6Mk...`) — the same encoding produced by
        // `phalanx-node::identity::generate` for persistent identities.
        // Both constructor paths now agree on the same encoding for the
        // same key.
        //
        // The forensic `witness_id` is NOT the libp2p mesh routing
        // address — that is derived separately by
        // `Libp2pExt::to_mesh_address` at the `phalanx-transport`
        // boundary, and the two encodings differ.
        let did = Did::derive_did_key(&public_key_bytes);
        let witness_id = did.to_witness_id();

        // Ephemeral identities have no BIP39 mnemonic, so the dek_master is
        // random — recordings made under an ephemeral identity are not
        // phrase-recoverable (no phrase exists). Tests that need
        // recoverability use the persistent `generate()`/`restore()` path.
        let mut dek_master_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut dek_master_bytes);

        Self {
            version: IDENTITY_VERSION,
            did,
            witness_id,
            keypair: signing_key,
            revocation_key: RevocationKey::default(),
            dek_master: DekMaster::from_bytes(dek_master_bytes),
        }
    }
}

impl Default for PhalanxIdentity {
    fn default() -> Self {
        Self::new_ephemeral()
    }
}

// ── Identity Disk Format ────────────────────────────────────────────────

/// Encrypted disk persistence format for PhalanxIdentity.
///
/// Used by both phone (phalanx-node) and Stronghold (phalanx-stronghold).
/// This is the ONLY path through which private keypair bytes are serialized,
/// and it is always encrypted with Argon2-derived AEAD before touching disk.
///
/// M6 FIX: PhalanxIdentity itself has no Serialize/Deserialize.
/// All persistence flows through this explicit format.
#[derive(Serialize, Deserialize)]
pub struct IdentityDiskFormat {
    pub version: u32,
    pub did: Did,
    /// On-disk key remains `network_id` for backward compatibility with
    /// existing identity files. The Rust field is `witness_id` to match the
    /// canonical type. `into_identity` ignores this stored value and
    /// re-derives the canonical form from `did` (lossless).
    #[serde(rename = "network_id")]
    pub witness_id: WitnessId,
    pub keypair_bytes: [u8; 32],
    /// Revocation public key. `serde(default)` for backwards compatibility —
    /// existing identity files load with `RevocationKey::default()`.
    #[serde(default)]
    pub revocation_key: RevocationKey,
    /// HKDF-derived DEK master, persisted under the passphrase wall.
    /// Present only in v2+ files. v1 files lack this field; the v1 → v2
    /// upgrade requires re-restore from the BIP39 phrase.
    #[serde(default)]
    pub dek_master_bytes: [u8; 32],
}

impl IdentityDiskFormat {
    /// Convert a runtime identity to the disk format.
    pub fn from_identity(identity: &PhalanxIdentity) -> Self {
        Self {
            version: identity.version,
            did: identity.did.clone(),
            witness_id: identity.witness_id.clone(),
            keypair_bytes: identity.keypair.to_bytes(),
            revocation_key: identity.revocation_key,
            dek_master_bytes: *identity.dek_master.as_bytes(),
        }
    }

    /// Restore a runtime identity from the disk format.
    ///
    /// Re-derives `witness_id` from the persisted `did` instead of trusting
    /// the on-disk value. This is lossless — the keypair bytes are
    /// authoritative; the `did` is itself derived from the keypair; and the
    /// `witness_id` is `did.to_witness_id()`. Older identity files that
    /// stored a non-canonical encoding (raw-pubkey base58, missing the `z`
    /// multibase prefix) migrate transparently on load: the canonical
    /// multibase form is computed from the `did` and the on-disk
    /// `witness_id` value is discarded.
    ///
    /// Schema version handling:
    /// - v2 (current): all fields present; reconstructs directly.
    /// - v1: lacks `dek_master_bytes`; returns `SchemaUpgradeRequired`. The
    ///   caller must re-restore from the BIP39 phrase to derive the master.
    /// - other: returns `UnknownVersion`.
    pub fn into_identity(self) -> Result<PhalanxIdentity, IdentityError> {
        match self.version {
            IDENTITY_VERSION => {
                // M-FIX (encoding canonicalization): derive the canonical
                // forensic identifier from the persisted `did` rather than
                // trusting whatever was previously written to disk.
                let witness_id = self.did.to_witness_id();
                Ok(PhalanxIdentity {
                    version: self.version,
                    did: self.did,
                    witness_id,
                    keypair: SigningKey::from_bytes(&self.keypair_bytes),
                    revocation_key: self.revocation_key,
                    dek_master: DekMaster::from_bytes(self.dek_master_bytes),
                })
            }
            1 => Err(IdentityError::SchemaUpgradeRequired {
                from: 1,
                to: IDENTITY_VERSION,
            }),
            other => Err(IdentityError::UnknownVersion(other)),
        }
    }
}

impl std::fmt::Debug for PhalanxIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhalanxIdentity")
            .field("version", &self.version)
            .field("did", &self.did)
            .field("witness_id", &self.witness_id)
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
    pub id: RecordingId,
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
            id: RecordingId::from_str(id_str).map_err(|_| LocatorError::ParseError)?,
            secret: secret_str.to_string(),
            author: crate::identity::Did(author_str.to_string()),
            recipient_did: crate::identity::Did(recipient_str.to_string()),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Ownership {
    /// Tentative ownership based on first-seen shard. Subject to displacement.
    Tentative(Did),
    /// Authoritative ownership proven by Genesis (Seq 0) or Handover. Permanent.
    Authoritative(Did),
}

impl Ownership {
    pub fn did(&self) -> &Did {
        match self {
            Self::Tentative(d) | Self::Authoritative(d) => d,
        }
    }

    pub fn is_authoritative(&self) -> bool {
        matches!(self, Self::Authoritative(_))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;

    #[test]
    fn test_to_safe_name_normal_did() {
        let did = Did::new("did:key:z6MkqAWvMbaN66Vt");
        let safe = did.to_safe_name();
        assert_eq!(safe, "did_key_z6MkqAWvMbaN66Vt");
    }

    #[test]
    fn test_to_safe_name_traversal_unix() {
        let did = Did::new("did:key:../../../etc/passwd");
        let safe = did.to_safe_name();
        // All slashes and dots become underscores — no traversal possible
        assert!(!safe.contains(".."));
        assert!(!safe.contains('/'));
    }

    #[test]
    fn test_to_safe_name_traversal_windows() {
        let did = Did::new("did:key:..\\..\\windows\\system32");
        let safe = did.to_safe_name();
        assert!(!safe.contains(".."));
        assert!(!safe.contains('\\'));
    }

    #[test]
    fn test_to_safe_name_absolute_path() {
        let did = Did::new("/absolute/path");
        let safe = did.to_safe_name();
        assert!(!safe.contains('/'));
        assert!(
            !safe.starts_with('_') && safe.starts_with('_')
                || safe
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        );
    }

    #[test]
    fn test_to_safe_name_empty() {
        let did = Did::new("");
        let safe = did.to_safe_name();
        assert_eq!(safe, "_empty_");
    }

    #[test]
    fn test_recording_id_to_safe_name_normal() {
        let id = RecordingId::new("rec_2026_session_42");
        assert_eq!(id.to_safe_name(), "rec_2026_session_42");
    }

    #[test]
    fn test_recording_id_to_safe_name_traversal_unix() {
        let id = RecordingId::new("../../../etc/passwd");
        let safe = id.to_safe_name();
        assert!(!safe.contains(".."));
        assert!(!safe.contains('/'));
    }

    #[test]
    fn test_recording_id_to_safe_name_traversal_windows() {
        let id = RecordingId::new("..\\..\\windows\\system32");
        let safe = id.to_safe_name();
        assert!(!safe.contains(".."));
        assert!(!safe.contains('\\'));
    }

    #[test]
    fn test_recording_id_to_safe_name_absolute_path() {
        let id = RecordingId::new("/absolute/path");
        let safe = id.to_safe_name();
        assert!(!safe.contains('/'));
        assert!(
            safe.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        );
    }

    #[test]
    fn test_recording_id_to_safe_name_empty() {
        let id = RecordingId::new("");
        assert_eq!(id.to_safe_name(), "_empty_");
    }

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

    // === WitnessId / MeshAddress round-trip tests ===

    #[test]
    fn witness_id_serializes_transparently() {
        // Newtype + #[serde(transparent)]: the inner string is the only thing
        // on the wire, byte-identical with serializing a bare `&str`.
        let id = WitnessId::new("z6MkqAWvMbaN66Vt");
        let id_bytes = postcard::to_allocvec(&id).unwrap();
        let str_bytes = postcard::to_allocvec("z6MkqAWvMbaN66Vt").unwrap();
        assert_eq!(id_bytes, str_bytes);
    }

    #[test]
    fn witness_id_postcard_roundtrips() {
        let id = WitnessId::new("z6MkqAWvMbaN66Vt");
        let bytes = postcard::to_allocvec(&id).unwrap();
        let restored: WitnessId = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(id, restored);
    }

    #[test]
    fn mesh_address_serializes_transparently() {
        let addr = MeshAddress::new("12D3KooWExample");
        let addr_bytes = postcard::to_allocvec(&addr).unwrap();
        let str_bytes = postcard::to_allocvec("12D3KooWExample").unwrap();
        assert_eq!(addr_bytes, str_bytes);
    }

    #[test]
    fn mesh_address_postcard_roundtrips() {
        let addr = MeshAddress::new("12D3KooWExample");
        let bytes = postcard::to_allocvec(&addr).unwrap();
        let restored: MeshAddress = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(addr, restored);
    }

    #[test]
    fn did_round_trips_through_witness_id() {
        let did = Did::new("did:key:z6MkqAWvMbaN66Vt");
        let witness_id = did.to_witness_id();
        assert_eq!(witness_id.as_str(), "z6MkqAWvMbaN66Vt");
        let restored = Did::from_witness_id(&witness_id);
        assert_eq!(restored, did);
    }

    // === Canonicalization tests (Commit 2) ===

    #[test]
    fn phalanx_identity_ephemeral_uses_multibase_witness_id() {
        // After canonicalization, the ephemeral constructor produces the same
        // multibase form (`z`-prefixed) as the persistent constructor.
        let identity = PhalanxIdentity::new_ephemeral();
        assert!(
            identity.witness_id.0.starts_with('z'),
            "ephemeral identity's witness_id should be multibase-prefixed (got {:?})",
            identity.witness_id
        );
        assert_eq!(identity.witness_id, identity.did.to_witness_id());
    }

    #[test]
    fn identity_disk_format_migrates_legacy_raw_encoding() {
        // Simulate a legacy v2 identity file: same did + keypair, but the
        // persisted `witness_id` is the old raw-pubkey base58 form.
        let identity = PhalanxIdentity::new_ephemeral();
        let raw_pubkey_b58 =
            bs58::encode(identity.keypair.verifying_key().to_bytes()).into_string();
        let legacy_disk = IdentityDiskFormat {
            version: identity.version,
            did: identity.did.clone(),
            witness_id: WitnessId::new(raw_pubkey_b58.clone()),
            keypair_bytes: identity.keypair.to_bytes(),
            revocation_key: identity.revocation_key,
            dek_master_bytes: *identity.dek_master.as_bytes(),
        };
        // The on-load migration must discard the raw form and re-derive the
        // canonical multibase form from the `did`.
        let restored = legacy_disk.into_identity().unwrap();
        assert_ne!(restored.witness_id.0, raw_pubkey_b58);
        assert!(restored.witness_id.0.starts_with('z'));
        assert_eq!(restored.witness_id, restored.did.to_witness_id());
    }

    #[test]
    fn phalanx_identity_round_trips_through_disk_format() {
        let identity = PhalanxIdentity::new_ephemeral();
        let disk = IdentityDiskFormat::from_identity(&identity);
        let restored = disk.into_identity().unwrap();
        assert_eq!(restored.did, identity.did);
        assert_eq!(restored.witness_id, identity.witness_id);
        assert_eq!(restored.version, identity.version);
        assert_eq!(
            restored.dek_master.as_bytes(),
            identity.dek_master.as_bytes()
        );
    }

    #[test]
    fn v1_identity_file_returns_schema_upgrade_required() {
        let identity = PhalanxIdentity::new_ephemeral();
        let v1_disk = IdentityDiskFormat {
            version: 1,
            did: identity.did.clone(),
            witness_id: identity.witness_id.clone(),
            keypair_bytes: identity.keypair.to_bytes(),
            revocation_key: identity.revocation_key,
            dek_master_bytes: [0u8; 32],
        };
        match v1_disk.into_identity() {
            Err(IdentityError::SchemaUpgradeRequired { from: 1, to }) => {
                assert_eq!(to, IDENTITY_VERSION);
            }
            other => panic!("expected SchemaUpgradeRequired, got {:?}", other.is_ok()),
        }
    }

    #[test]
    fn future_identity_version_returns_unknown_version() {
        let identity = PhalanxIdentity::new_ephemeral();
        let future_disk = IdentityDiskFormat {
            version: 999,
            did: identity.did.clone(),
            witness_id: identity.witness_id.clone(),
            keypair_bytes: identity.keypair.to_bytes(),
            revocation_key: identity.revocation_key,
            dek_master_bytes: *identity.dek_master.as_bytes(),
        };
        assert!(matches!(
            future_disk.into_identity(),
            Err(IdentityError::UnknownVersion(999))
        ));
    }
}
