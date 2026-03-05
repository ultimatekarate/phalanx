use crate::identity::Did;
use crate::time::PhalanxTimestamp;
use crate::time::TimeError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Offense {
    InvalidSignature,
    ReplayAttack,
    QuotaExceeded,
    MalformedPacket,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    Blocked,
    #[default]
    Ignored,
    Verified,
    Ally,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRecord {
    pub reputation: i64,
    pub is_banned: bool,
    pub last_update_secs: MonotonicClock,
}

impl Default for TrustRecord {
    fn default() -> Self {
        Self {
            reputation: 100, // Default starting trust score
            is_banned: false,
            last_update_secs: MonotonicClock(0),
        }
    }
}

/// The Trust Registry: The Noun that holds the mesh's perception of peers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustRegistry {
    pub peers: HashMap<Did, TrustRecord>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PeerReputation {
    pub invalid_sigs: u32,
    pub quota_violations: u32,
    pub total_shards_sent: u64,
    pub active_buffers: usize,
    pub last_seen_load: f32,
    pub is_blacklisted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub did: Did,
    pub pet_name: PetName,
    pub level: TrustLevel,
    pub added_at: PhalanxTimestamp,
    pub last_interaction: PhalanxTimestamp,
    pub reputation: PeerReputation,
}

/// A user-defined local identifier for a DID (Pet name).
///
/// Constraints:
/// - Max length: 64 chars
/// - No control characters
/// - Cannot be empty
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PetName(String);

impl PetName {
    #[allow(clippy::missing_errors_doc)]
    pub fn new(s: impl Into<String>) -> Result<Self, TrustError> {
        let s = s.into();
        if s.trim().is_empty() {
            return Err(TrustError::InvalidPetName(
                "Pet name cannot be empty".into(),
            ));
        }
        if s.len() > 64 {
            return Err(TrustError::InvalidPetName(
                "Pet name too long (max 64)".into(),
            ));
        }
        if s.chars().any(|c| c.is_control()) {
            return Err(TrustError::InvalidPetName(
                "Pet name contains control characters".into(),
            ));
        }
        Ok(Self(s))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PetName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Error)]
pub enum TrustError {
    #[error("The pet name '{0}' is already in use by another DID")]
    PetnameCollision(String),
    #[error("Failed to persist registry: {0}")]
    IoError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Invalid Pet name format: {0}")]
    InvalidPetName(String),
    #[error("Trusted clock failure: {0}")]
    TimeSource(#[from] TimeError),
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct MonotonicClock(pub u64);

impl MonotonicClock {
    pub fn elapsed_since(&self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}
