use crate::identity::Did;
use crate::time::PhalanxTimestamp;
use crate::time::TimeError;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Offense {
    InvalidSignature,
    ReplayAttack,
    QuotaExceeded,
    MalformedPacket,
    IdentityTheft,
    ProtocolViolation,
    TemporalSkew,
    SpectralAnomaly,
    EclipseAttempt,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustLevel {
    Blocked,
    #[default]
    Ignored,
    Verified,
    Ally,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerReputation {
    pub invalid_sigs: u32,
    pub quota_violations: u32,
    pub total_shards_sent: u64,
    pub active_buffers: usize,
    pub last_seen_load: f32,
    pub is_blacklisted: bool,
    pub score: i64,
    pub last_update_secs: MonotonicClock,
    /// Timestamp of last recorded offense. Used for recovery cooldown (§6 eclipse remediation).
    pub last_offense_secs: MonotonicClock,
}

impl Default for PeerReputation {
    fn default() -> Self {
        Self {
            invalid_sigs: 0,
            quota_violations: 0,
            total_shards_sent: 0,
            active_buffers: 0,
            last_seen_load: 0.0,
            is_blacklisted: false,
            score: 100,
            last_update_secs: MonotonicClock::default(),
            last_offense_secs: MonotonicClock::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerRecord {
    pub did: Did,
    pub pet_name: Option<PetName>,
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
    #[error("Peer with DID {0} already exists")]
    PeerAlreadyExists(Did),
    #[error("Peer with DID {0} not found")]
    PeerNotFound(Did),
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

// MonotonicClock moved to time.rs (Tense, not Trust)
pub use crate::time::MonotonicClock;
