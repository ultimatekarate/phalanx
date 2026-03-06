use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::ops::{AddAssign, SubAssign};
use std::time::Duration;

/// The Noun: PhalanxPhysics represents the physical constraints
/// observed by the node in the current mesh environment.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PhalanxPhysics {
    /// The smoothed Round Trip Time (RTT) constant used for temporal governance.
    pub tau_rtt: u64,
    /// Environmental signal-to-noise ratio or battery coefficient (0.0 to 1.0).
    pub energy_efficiency: UnitInterval,
}

impl PhalanxPhysics {
    /// WAN defaults: higher RTT, full energy.
    pub fn default_wan() -> Self {
        Self {
            tau_rtt: 200,
            energy_efficiency: UnitInterval(1.0),
        }
    }
}

impl Default for PhalanxPhysics {
    fn default() -> Self {
        Self {
            tau_rtt: 200, // Default 200ms RTT
            energy_efficiency: UnitInterval(1.0),
        }
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct UnitInterval(f32);

impl UnitInterval {
    /// Creates a new UnitInterval, clamping the value between 0.0 and 1.0.
    #[must_use]
    pub fn new(val: f32) -> Self {
        if val.is_nan() {
            // FORENSIC PROTOCOL: Panic or default to max load on NaN?
            // Panicking is safer for debugging; defaulting to 1.0 is safer for runtime stability.
            // We choose 1.0 (Max Load) to trigger traffic shedding if math fails.
            return Self(1.0);
        }

        Self(val.clamp(0.0, 1.0))
    }

    /// Returns the underlying float value.
    #[must_use]
    pub fn as_f32(&self) -> f32 {
        self.0
    }

    /// Convenience check for the 15% Leaf Mode threshold.
    #[must_use]
    pub fn is_critical(&self) -> bool {
        self.0 < 0.15
    }

    /// Inverts the interval (e.g., Load -> Capacity).
    #[must_use]
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

// 2. Strict Equality (Eq)
// Valid because we filter NaNs in new().
impl PartialEq for UnitInterval {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for UnitInterval {}

// 3. Strict Ordering (Ord)
// Essential for sorting vectors of loads or using in BTreeMaps.
impl Ord for UnitInterval {
    fn cmp(&self, other: &Self) -> Ordering {
        // total_cmp defines a total ordering for floats (handling -0.0 vs +0.0)
        self.0.total_cmp(&other.0)
    }
}

impl PartialOrd for UnitInterval {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq<f32> for UnitInterval {
    fn eq(&self, other: &f32) -> bool {
        self.0 == *other
    }
}

impl PartialOrd<f32> for UnitInterval {
    fn partial_cmp(&self, other: &f32) -> Option<Ordering> {
        self.0.partial_cmp(other)
    }
}

impl PartialEq<f64> for UnitInterval {
    fn eq(&self, other: &f64) -> bool {
        (self.0 as f64) == *other
    }
}

impl PartialOrd<f64> for UnitInterval {
    fn partial_cmp(&self, other: &f64) -> Option<Ordering> {
        (self.0 as f64).partial_cmp(other)
    }
}
/// A type-safe wrapper for storage measurements.
/// Prevents primitive obsession with u64 and provides safe arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct ByteCapacity(pub u64);

impl ByteCapacity {
    #[must_use]
    pub fn from_mib(mib: u64) -> Self {
        Self(mib * 1024 * 1024)
    }

    #[must_use]
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    #[must_use]
    pub fn as_mib(&self) -> u64 {
        self.0 / (1024 * 1024)
    }

    /// Safe addition that prevents overflow.
    #[must_use]
    pub fn saturating_add(self, other: u64) -> Self {
        Self(self.0.saturating_add(other))
    }

    /// Safe subtraction that prevents underflow.
    #[must_use]
    pub fn saturating_sub(self, other: u64) -> Self {
        Self(self.0.saturating_sub(other))
    }
}

// Type safe wrapper for storage constraints
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskCost {
    Light, // e.g., signature verification
    Heavy, // e.g., FFTs, video encoding
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SystemStress {
    Nominal,  // 0, Cool & Charged. Full Speed.
    Fair,     // 1, Warm or < 50% Battery. Throttle background tasks.
    Serious,  // 2, Hot or < 20% Battery. Stop all forensics.
    Critical, // 3, Melting or < 5% Battery. Emergency shutdown.
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NodeMode {
    /// A mobile or edge device. Only accepts and reassembles local ForensicUnits.
    /// Rejects all foreign relay traffic to conserve battery and bandwidth.
    Leaf,
    /// A full mesh participant. Reassembles both local data and witnessed
    /// relay traffic from the network.
    Standard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VitalityRate(pub u64); // Milliseconds

impl VitalityRate {
    /// Minimum allowed heartbeat (100ms) to prevent CPU/Radio thrashing.
    const MIN_MS: u64 = 100;
    /// Maximum allowed heartbeat (30s) to prevent node timeout in the mesh.
    const MAX_MS: u64 = 30_000;

    #[must_use]
    pub fn new(ms: u64) -> Self {
        Self(ms.clamp(Self::MIN_MS, Self::MAX_MS))
    }

    /// Derives a heartbeat interval based on current system power and load.
    #[must_use]
    pub fn as_duration(&self) -> Duration {
        Duration::from_millis(self.0)
    }

    #[must_use]
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PowerState {
    #[default]
    Normal,
    /// Focus strictly on self-preservation: Only accept local data
    Leaf,
}

pub trait ValidationState {}

pub struct Unverified; // Data just off the wire
pub struct Verified; // Data that has passed the Gates

impl ValidationState for Unverified {}
impl ValidationState for Verified {}

pub struct ForensicUnit<T, S: ValidationState> {
    pub data: T,
    pub _state: std::marker::PhantomData<S>,
}

impl<T> ForensicUnit<T, Unverified> {
    /// Create a new unit from raw bytes or a packet.
    pub fn new(data: T) -> Self {
        Self {
            data,
            _state: std::marker::PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unit_interval_behavior() {
        // Test clamping
        let high = UnitInterval::new(1.5);
        assert_eq!(high.as_f32(), 1.0);

        let low = UnitInterval::new(-0.1);
        assert_eq!(low.as_f32(), 0.0);

        // Test NaN safety (Forensic Protocol: default to 1.0)
        let nan = UnitInterval::new(f32::NAN);
        assert_eq!(nan.as_f32(), 1.0);

        // Test complement
        let load = UnitInterval::new(0.3);
        assert_eq!(load.complement().as_f32(), 0.7);

        // Test critical threshold
        let critical = UnitInterval::new(0.1);
        assert!(critical.is_critical());

        let healthy = UnitInterval::new(0.2);
        assert!(!healthy.is_critical());
    }

    #[test]
    fn test_byte_capacity_arithmetic() {
        let cap = ByteCapacity::from_mib(10);

        let added = cap.saturating_add(1024);
        assert_eq!(added.as_u64(), 10 * 1024 * 1024 + 1024);

        let subbed = cap.saturating_sub(20 * 1024 * 1024);
        assert_eq!(subbed.as_u64(), 0);
    }
}
