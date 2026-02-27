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
    pub fn should_accept(
        &self,
        peer_id: &crate::primitives::identity::NetworkId,
        local_peer_id: &crate::primitives::identity::NetworkId,
    ) -> bool {
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
