use crate::prelude::NetworkId;
use crate::prelude::PhalanxIdentity;
use crate::prelude::SignatureHash;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use std::sync::Arc;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct PhalanxTimestamp(pub u64);

impl PhalanxTimestamp {
    pub fn from_u64(raw: u64) -> Self {
        Self(raw)
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
    pub fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    pub fn now() -> Self {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System clock went backwards")
            .as_millis() as u64;

        Self(millis)
    }
}

pub trait TrustedClock: Send + Sync {
    fn now(&self) -> PhalanxTimestamp;
}

/// A stateful session that maintains the causality chain for a specific timeline.
pub struct CausalitySession {
    pub identity: Arc<PhalanxIdentity>,
    pub peer_id: NetworkId,
    pub last_hash: Option<SignatureHash>,
}

impl CausalitySession {
    pub fn new(identity: Arc<PhalanxIdentity>, peer_id: NetworkId) -> Self {
        Self {
            identity,
            peer_id,
            last_hash: None,
        }
    }
}

#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum TimeError {
    #[error("System clock drift detected")]
    ClockSkew,
    #[error("Time synchronization lock poisoned")]
    LockPoisoned,
    #[error("Timestamp is too far in the past: {0}s difference")]
    Stale(u64),
    #[error("Timestamp is in the future: {0}s difference")]
    Future(u64),
    #[error("NTP Sync failed: {0}")]
    NtpError(String),
}
