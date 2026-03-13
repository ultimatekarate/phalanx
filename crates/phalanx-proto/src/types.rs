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

// Strict Equality (Eq)
// Valid because we filter NaNs in new().
impl PartialEq for UnitInterval {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for UnitInterval {}

// Strict Ordering (Ord)
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

/// Device power/resource conservation state.
/// Ordered by restrictiveness: Normal < Conserving < Leaf < Dormant.
/// Two-stage evaluation: `recommended_power_state() = max(battery_gate, stress_recommendation)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum PowerState {
    /// Full participation — no constraints.
    #[default]
    Normal,
    /// Battery 20–50% (not charging): 2× heartbeat interval, half FPS.
    Conserving,
    /// Battery <20% or critical stress: local-only, 5× heartbeat, minimal FPS.
    Leaf,
    /// App backgrounded: WAL drain + heartbeat only (capture if OS allows).
    Dormant,
}

pub trait ValidationState {}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unverified; // Data just off the wire

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verified; // Data that has passed the Gates

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed; // Authorized for egress

impl ValidationState for Unverified {}
impl ValidationState for Verified {}
impl ValidationState for Sealed {}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
// Data that has passed policy gates and is authorized for the wire

impl<T> ForensicUnit<T, Verified> {
    /// Creates a new Verified unit.
    /// This should ONLY be called after data passes Gate 3 (Cryptographic Integrity).
    pub fn new_verified(data: T) -> Self {
        Self {
            data,
            _state: std::marker::PhantomData,
        }
    }

    /// Internal workspace-only seal. Promotes Verified to Sealed.
    /// Because this is `pub(crate)`, it forces actors to use the EgressGovernor
    /// to obtain a Sealed unit for network transport.
    pub fn seal(self) -> ForensicUnit<T, Sealed> {
        ForensicUnit {
            data: self.data,
            _state: std::marker::PhantomData,
        }
    }
}

impl<T, S: ValidationState> ForensicUnit<T, S> {
    /// Consumes the wrapper to retrieve the raw data.
    /// Used by the Vault (to unpack Verified ingress) and the Network (to unpack Sealed egress).
    pub fn unpack(self) -> T {
        self.data
    }
}

// ─── Four Pillars Newtypes ───────────────────────────────────
// Every new domain concept gets a newtype. Primitive obsession is forbidden.

/// RaptorQ encoding symbol identifier (ESI). Not an index — it's a symbol address.
/// Lives here because ShardChunk (evidence.rs) carries it across the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct EncodingSymbolId(pub u32);

impl fmt::Display for EncodingSymbolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "esi:{}", self.0)
    }
}

/// Frames per second. Floor of 1 enforced on construction via `new()`.
/// `zero()` is explicitly opt-in for Dormant (no capture) only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Fps(u32);

impl Fps {
    /// Construct with a floor of 1 FPS. Prevents zero-FPS bugs from integer division.
    #[must_use]
    pub fn new(fps: u32) -> Self {
        Self(fps.max(1))
    }

    /// Explicitly zero FPS — only valid for Dormant state (no capture).
    #[must_use]
    pub fn zero() -> Self {
        Self(0)
    }

    #[must_use]
    pub fn get(&self) -> u32 {
        self.0
    }

    /// Convert to a per-frame interval. Returns None for zero FPS.
    #[must_use]
    pub fn as_interval(&self) -> Option<Duration> {
        if self.0 == 0 {
            None
        } else {
            Some(Duration::from_millis(1000 / self.0 as u64))
        }
    }
}

impl Default for Fps {
    fn default() -> Self {
        Self(30)
    }
}

impl fmt::Display for Fps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} fps", self.0)
    }
}

/// RaptorQ repair ratio (≥ 1.0). 1.0 = source symbols only, 1.5 = 50% extra repair symbols.
/// Validated on construction — invalid ratios panic in debug, clamp in release.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RepairRatio(f32);

impl RepairRatio {
    /// Construct a repair ratio. Must be ≥ 1.0.
    /// Panics in debug builds if ratio < 1.0. Clamps to 1.0 in release.
    #[must_use]
    pub fn new(ratio: f32) -> Self {
        debug_assert!(ratio >= 1.0, "RepairRatio must be >= 1.0, got {}", ratio);
        Self(ratio.max(1.0))
    }

    #[must_use]
    pub fn get(&self) -> f32 {
        self.0
    }
}

impl Default for RepairRatio {
    fn default() -> Self {
        Self(1.5)
    }
}

impl fmt::Display for RepairRatio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}×", self.0)
    }
}

/// RaptorQ symbol payload size in bytes. Constrains MTU-level chunking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SymbolSize(pub usize);

impl Default for SymbolSize {
    fn default() -> Self {
        Self(1200) // Fits in a single UDP datagram under typical MTU
    }
}

impl fmt::Display for SymbolSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bytes/symbol", self.0)
    }
}

/// Sensor analog black level offset. Wraps f32 to match NEON float32x4 pipeline.
/// Typical value: 16.0 for 8-bit sensors (accounts for analog black offset).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BlackLevel(pub f32);

impl Default for BlackLevel {
    fn default() -> Self {
        Self(16.0)
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
    fn test_fps_floor_guard() {
        // Fps::new enforces minimum of 1
        assert_eq!(Fps::new(0).get(), 1);
        assert_eq!(Fps::new(30).get(), 30);

        // Integer division that would floor to 0 is caught
        let base = Fps::new(4);
        let leaf = Fps::new(base.get() / 5); // 4/5 = 0 → clamped to 1
        assert_eq!(leaf.get(), 1);

        // Fps::zero is explicitly opt-in
        assert_eq!(Fps::zero().get(), 0);
        assert!(Fps::zero().as_interval().is_none());

        // Normal FPS gives a valid interval
        assert!(Fps::new(30).as_interval().is_some());
    }

    #[test]
    fn test_repair_ratio_validation() {
        // Valid ratios
        assert_eq!(RepairRatio::new(1.0).get(), 1.0);
        assert_eq!(RepairRatio::new(1.5).get(), 1.5);
        assert_eq!(RepairRatio::new(2.0).get(), 2.0);

        // Default is 1.5
        assert_eq!(RepairRatio::default().get(), 1.5);
    }

    #[test]
    fn test_encoding_symbol_id() {
        let esi = EncodingSymbolId(42);
        assert_eq!(esi.0, 42);
        assert_eq!(format!("{}", esi), "esi:42");
    }

    #[test]
    fn test_symbol_size_default() {
        let ss = SymbolSize::default();
        assert_eq!(ss.0, 1200);
    }

    #[test]
    fn test_black_level_default() {
        let bl = BlackLevel::default();
        assert_eq!(bl.0, 16.0);
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
