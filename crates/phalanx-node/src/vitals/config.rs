// crates/phalanx-node/src/vitals/config.rs
//
// Homeostatic configuration, integral state, and the Homeostasis trait.
//
// The mathematical primitives (DecayingIntegral, HomeostaticConfig,
// ResourceIntegrals, Homeostasis trait, scaler newtypes) now live in
// phalanx-forensics::policy.  This module re-exports them and keeps
// IntegralState, which composes ResourceIntegrals with phone-specific fields.

use tokio::time::Instant;

use phalanx_proto::types::PowerState;

// Re-export Laboratory primitives so existing `use super::config::*` works.
pub use phalanx_forensics::policy::{
    DecayingIntegral, Homeostasis, HomeostaticConfig, ResourceIntegrals,
};

use phalanx_forensics::policy::ResourceIntegrals as RI;

pub struct IntegralState {
    pub integrals: RI,
    // Phone-specific fields (unchanged):
    pub conserving_trigger_count: u8,
    pub leaf_trigger_count: u8,
    pub normal_trigger_count: u8,
    /// Tracks the stress-driven power state independently of battery gate.
    /// Used as hysteresis fallback by `stress_recommendation()` so it doesn't
    /// inherit battery-gate-driven Dormant/Leaf states.
    pub stress_power_state: PowerState,
    // Internet connectivity detection
    /// Whether the node believes it has internet connectivity.
    /// Determined by tracking peer discovery sources: if ALL connected peers
    /// are mDNS-local for >30s, internet is considered unavailable.
    pub internet_available: bool,
    /// Number of peers discovered via mDNS (local network).
    pub local_peer_count: usize,
    /// Number of peers discovered via non-local means (Kademlia, Bootstrap, Relay).
    pub internet_peer_count: usize,
    /// When the last non-mDNS peer was seen. Used for the 30s grace period
    /// before declaring internet unavailable.
    pub last_internet_peer_seen: Instant,
}

impl std::ops::Deref for IntegralState {
    type Target = RI;
    fn deref(&self) -> &RI {
        &self.integrals
    }
}

impl std::ops::DerefMut for IntegralState {
    fn deref_mut(&mut self) -> &mut RI {
        &mut self.integrals
    }
}

impl Default for IntegralState {
    fn default() -> Self {
        Self::new()
    }
}

impl IntegralState {
    pub fn new() -> Self {
        Self {
            integrals: RI::new(),
            conserving_trigger_count: 0,
            leaf_trigger_count: 0,
            normal_trigger_count: 0,
            stress_power_state: PowerState::Normal,
            internet_available: true,
            local_peer_count: 0,
            internet_peer_count: 0,
            last_internet_peer_seen: Instant::now(),
        }
    }
}
