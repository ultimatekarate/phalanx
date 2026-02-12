use std::ops::{AddAssign, SubAssign};
use serde::{Serialize, Deserialize};
use std::fmt;
use crate::core::config::PhalanxPhysics;
use std::time::Duration;

/// A type-safe wrapper for values that MUST be between 0.0 and 1.0.
/// Replaces raw f32 for Battery and Load metrics.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct UnitInterval(f32);

impl UnitInterval {
    /// Creates a new UnitInterval, clamping the value between 0.0 and 1.0.
    pub fn new(val: f32) -> Self {
        Self(val.clamp(0.0, 1.0))
    }

    /// Returns the underlying float value.
    pub fn as_f32(&self) -> f32 {
        self.0
    }

    /// Convenience check for the 15% Leaf Mode threshold.
    pub fn is_critical(&self) -> bool {
        self.0 < 0.15
    }

    /// Inverts the interval (e.g., Load -> Capacity).
    pub fn complement(&self) -> Self {
        Self(1.0 - self.0)
    }
}

impl From<f32> for UnitInterval {
    fn from(val: f32) -> Self {
        Self::new(val)
    }
}

impl fmt::Display for UnitInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.2}%", self.0 * 100.0)
    }
}

/// A type-safe wrapper for storage measurements.
/// Prevents primitive obsession with u64 and provides safe arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct ByteCapacity(pub u64);

impl ByteCapacity {
    pub fn from_mib(mib: u64) -> Self {
        Self(mib * 1024 * 1024)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn as_mib(&self) -> u64 {
        self.0 / (1024 * 1024)
    }

    /// Safe addition that prevents overflow.
    pub fn saturating_add(self, other: u64) -> Self {
        Self(self.0.saturating_add(other))
    }

    /// Safe subtraction that prevents underflow.
    pub fn saturating_sub(self, other: u64) -> Self {
        Self(self.0.saturating_sub(other))
    }
}

impl fmt::Display for ByteCapacity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 >= 1024 * 1024 * 1024 {
            write!(f, "{:.2} GiB", self.0 as f64 / (1024.0 * 1024.0 * 1024.0))
        } else {
            write!(f, "{} MiB", self.as_mib())
        }
    }
}

impl AddAssign<u64> for ByteCapacity {
    fn add_assign(&mut self, rhs: u64) {
        self.0 = self.0.saturating_add(rhs);
    }
}

impl SubAssign<u64> for ByteCapacity {
    fn sub_assign(&mut self, rhs: u64) {
        self.0 = self.0.saturating_sub(rhs);
    }
}

// Also helpful for Comparing types
impl AddAssign<ByteCapacity> for ByteCapacity {
    fn add_assign(&mut self, rhs: ByteCapacity) {
        self.0 = self.0.saturating_add(rhs.0);
    }
}

/// A type-safe wrapper for Phalanx network topics.
/// Enforces naming conventions and prevents case-mismatch errors.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MeshTopic(String);

impl MeshTopic {
    pub fn new(name: &str) -> Self {
        // Ensure the topic is lowercase and follows our namespace
        let formatted = if name.starts_with("/phalanx/") {
            name.to_lowercase()
        } else {
            format!("/phalanx/{}", name.to_lowercase())
        };
        Self(formatted)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Facilitate conversion to libp2p types
impl From<MeshTopic> for libp2p::gossipsub::IdentTopic {
    fn from(topic: MeshTopic) -> Self {
        libp2p::gossipsub::IdentTopic::new(topic.0)
    }
}

impl fmt::Display for MeshTopic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for MeshTopic {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for MeshTopic {
    fn from(s: String) -> Self {
        Self::new(&s)
    }
}

impl PartialEq<&str> for MeshTopic {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<MeshTopic> for &str {
    fn eq(&self, other: &MeshTopic) -> bool {
        *self == other.0
    }
}

impl PartialEq<String> for MeshTopic {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl From<MeshTopic> for String {
    fn from(topic: MeshTopic) -> Self {
        topic.0
    }
}

impl From<&MeshTopic> for String {
    fn from(topic: &MeshTopic) -> Self {
        topic.0.clone()
    }
}

// This specifically helps with libp2p's IdentTopic::new() requirements
impl AsRef<str> for MeshTopic {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VitalityRate(pub u64); // Milliseconds

impl VitalityRate {
    /// Minimum allowed heartbeat (100ms) to prevent CPU/Radio thrashing.
    const MIN_MS: u64 = 100;
    /// Maximum allowed heartbeat (30s) to prevent node timeout in the mesh.
    const MAX_MS: u64 = 30_000;

    pub fn new(ms: u64) -> Self {
        Self(ms.clamp(Self::MIN_MS, Self::MAX_MS))
    }

    /// Derives a heartbeat interval based on current system power and load.
    pub fn calculate(physics: &PhalanxPhysics, state: PowerState, load: UnitInterval) -> Self {
        let base_ms = (physics.tau_rtt / 2) as f32;
        
        // 2. Load Scaling: Scaled by 1.0 + load factor
        let mut dynamic_ms = base_ms * (1.0 + load.as_f32());

        // 3. Power State Modifier: If in Leaf Mode, slow down significantly to save radio
        if state == PowerState::Leaf {
            dynamic_ms *= 5.0; // 5x slower for self-preservation
        }

        Self::new(dynamic_ms as u64)
    }

    pub fn as_duration(&self) -> Duration {
        Duration::from_millis(self.0)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

// src/core/types.rs

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PowerState {
    #[default]
    Normal,
    /// Focus strictly on self-preservation: Only accept local data
    Leaf, 
}

/// Central authority for deciding which data chunks are accepted.
/// Prevents logic drift between the Sentinel and Guardian.
pub struct TrafficGovernor {
    pub power_state: PowerState,
}

impl TrafficGovernor {
    pub fn new() -> Self {
        Self {
            power_state: PowerState::Normal,
        }
    }

    /// Primary security gate: Determines if a chunk should be processed.
    pub fn should_accept(
        &self, 
        chunk_owner: &crate::security::identity::Did, 
        local_did: &crate::security::identity::Did
    ) -> bool {
        match self.power_state {
            PowerState::Normal => true,
            // The Logic is still centralized here, satisfying the audit.
            PowerState::Leaf => chunk_owner == local_did,
        }
    }

    pub fn set_state(&mut self, state: PowerState) {
        self.power_state = state;
    }
}