// crates/phalanx-proto/src/vitals.rs
use crate::identity::MeshAddress;
use serde::{Deserialize, Serialize};

/// Bounded composite-stress reading in [0.0, 1.0]. Constructor clamps;
/// the wire form is a plain f32 (transparent newtype, postcard-identical).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StressLoad(pub f32);

impl StressLoad {
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // raw is clamped to [0.0, 1.0] before cast.
    pub fn from_clamped(raw: f64) -> Self {
        Self(raw.clamp(0.0, 1.0) as f32)
    }

    #[must_use]
    pub fn as_f32(&self) -> f32 {
        self.0
    }
}

/// Eight integral-state observations in fixed wire order
/// `[s, d, e, l, m, w, b, c]`. Locked at the type level — accessors
/// return the named integral, never the raw index. Wire form is a
/// plain `[f32; 8]` (transparent newtype, postcard-identical).
///
/// **Order is a wire-format commitment.** Do not reshuffle without
/// bumping the protocol version. Matches `ResourceIntegrals` field
/// order in `phalanx-forensics::policy`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IntegralSummary(pub [f32; 8]);

impl IntegralSummary {
    #[must_use]
    pub fn s(&self) -> f32 {
        self.0[0]
    }
    #[must_use]
    pub fn d(&self) -> f32 {
        self.0[1]
    }
    #[must_use]
    pub fn e(&self) -> f32 {
        self.0[2]
    }
    #[must_use]
    pub fn l(&self) -> f32 {
        self.0[3]
    }
    #[must_use]
    pub fn m(&self) -> f32 {
        self.0[4]
    }
    #[must_use]
    pub fn w(&self) -> f32 {
        self.0[5]
    }
    #[must_use]
    pub fn b(&self) -> f32 {
        self.0[6]
    }
    #[must_use]
    pub fn c(&self) -> f32 {
        self.0[7]
    }
    #[must_use]
    pub fn as_array(&self) -> [f32; 8] {
        self.0
    }
}

/// The heartbeat of the Phalanx network.
/// Broadcasted to coordinate load-balancing and peer vitality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlMessage {
    pub sender: MeshAddress,
    pub load_factor: StressLoad,
    pub storage_remaining_mb: u64,
    pub heartbeat_ms: u64,
    pub is_leaf: bool,
    /// Tier 2 Shield Wall: optional integral state summary for spectral
    /// consistency verification.  Nodes that omit this field are still
    /// checked via Tier 1 behavioral signals (heartbeat jitter, throughput).
    #[serde(default)]
    pub integral_summary: Option<IntegralSummary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatInterval(pub u64);

impl HeartbeatInterval {
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}
