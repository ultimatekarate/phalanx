use phalanx_proto::prelude::*;
use phalanx_proto::types::PhalanxPhysics;
use phalanx_proto::types::PowerState;
use phalanx_proto::types::UnitInterval;
use phalanx_proto::vitals::HeartbeatInterval;

pub struct TrafficGovernor {
    pub power_state: PowerState,
}

impl TrafficGovernor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            power_state: PowerState::Normal,
        }
    }

    /// Primary security gate: Determines if a chunk should be processed.
    #[must_use]
    pub fn should_accept(&self, peer_id: &NetworkId, local_peer_id: &NetworkId) -> bool {
        match self.power_state {
            PowerState::Normal => true,
            // Pre-allocation check: only allow loopback traffic when in survival mode
            PowerState::Leaf => peer_id == local_peer_id,
        }
    }

    pub fn set_state(&mut self, state: PowerState) {
        self.power_state = state;
    }
}

/// Take that, Clippy!
impl Default for TrafficGovernor {
    fn default() -> Self {
        Self::new()
    }
}

// crates/phalanx-forensics/src/policy.rs

pub struct HeartbeatGovernor;

impl HeartbeatGovernor {
    /// Derives a heartbeat interval based on current system power and load.
    /// This logic is part of the Laboratory's Governance role.
    #[must_use]
    pub fn derive_interval(
        physics: &PhalanxPhysics,
        state: PowerState,
        load: UnitInterval,
    ) -> HeartbeatInterval {
        let base_latency_ms = (physics.tau_rtt / 2) as f32;

        // Apply Load Scaling: 1.0 + load factor (range 1.0 to 2.0)
        let mut dynamic_ms = base_latency_ms * (1.0 + load.as_f32());

        // Apply Power State Modifier
        if state == PowerState::Leaf {
            // Leaf nodes prioritize radio silence and energy preservation.
            const LEAF_PRESERVATION_MULTIPLIER: f32 = 5.0;
            dynamic_ms *= LEAF_PRESERVATION_MULTIPLIER;
        }

        HeartbeatInterval(dynamic_ms as u64)
    }
}
