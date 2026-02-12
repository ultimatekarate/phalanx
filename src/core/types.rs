use std::ops::{AddAssign, SubAssign};
use serde::{Serialize, Deserialize};
use std::fmt;

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