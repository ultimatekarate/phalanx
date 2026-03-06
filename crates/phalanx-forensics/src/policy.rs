use phalanx_proto::prelude::*;
use phalanx_proto::trust::TrustRecord;
use phalanx_proto::trust::{MonotonicClock, TrustRegistry};
use phalanx_proto::types::PhalanxPhysics;
use phalanx_proto::types::PowerState;
use phalanx_proto::types::SystemStress;
use phalanx_proto::types::UnitInterval;
use phalanx_proto::vitals::HeartbeatInterval;
use rand::Rng;
use std::collections::HashMap;

pub struct TrustArbiter;

impl TrustArbiter {
    /// Pure, deterministic recovery logic.
    pub fn accumulate_reputation(
        registry: &mut TrustRegistry,
        now: MonotonicClock,
        interval_secs: u64,
        recovery_step: i64,
    ) {
        const MAX_REPUTATION: i64 = 100; // The ceiling of trust

        for record in registry.peers.values_mut() {
            if record.is_banned {
                continue;
            }

            // last_update is now also a MonotonicClock
            let elapsed = now.elapsed_since(record.last_update_secs);
            let intervals = elapsed / interval_secs;

            if intervals > 0 {
                let total_recovery = (intervals as i64) * recovery_step;

                // ENFORCEMENT: Reputation cannot exceed the ceiling
                record.reputation = (record.reputation + total_recovery).min(MAX_REPUTATION);

                if record.reputation < 0 {
                    record.is_banned = true;
                }

                record.last_update_secs = now;
            }
        }
    }

    pub fn should_verify_signature<R: Rng>(record: &TrustRecord, rng: &mut R) -> bool {
        // Always verify if they are near the "Suspicion" zone
        if record.reputation < 80 {
            return true;
        }

        // Probabilistic sampling for high-trust peers
        // 100 Rep = 5% check rate
        // 80 Rep = 20% check rate
        let check_threshold: f64 = match record.reputation {
            100..=i64::MAX => 0.05,
            80..=99 => 0.20,
            _ => 1.0,
        };

        rng.gen_bool(check_threshold)
    }

    pub fn requires_heavy_verification<R: Rng>(record: &TrustRecord, rng: &mut R) -> bool {
        // High-Reputation (100+): 5% spot-check rate (1 in 20)
        // Established (80-99): 20% spot-check rate
        // New/Suspicious (<80): 100% check rate
        let probability = match record.reputation {
            100..=i64::MAX => 0.05,
            80..=99 => 0.20,
            _ => 1.0,
        };

        rng.gen_bool(probability)
    }
}

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

pub struct IngressGovernor {
    pub active_slots: HashMap<NetworkId, TrustLevel>,
    pub base_max_slots: usize,
}

impl IngressGovernor {
    pub fn new(base_max_slots: usize) -> Self {
        Self {
            active_slots: HashMap::new(),
            base_max_slots,
        }
    }

    pub fn current_capacity(&self, stress: SystemStress) -> usize {
        match stress {
            SystemStress::Nominal => self.base_max_slots,
            SystemStress::Fair => std::cmp::max(1, self.base_max_slots / 3),
            SystemStress::Serious | SystemStress::Critical => 1,
        }
    }

    pub fn try_allocate(
        &mut self,
        peer: NetworkId,
        level: TrustLevel,
        current_stress: SystemStress,
    ) -> Result<Option<NetworkId>, &'static str> {
        // 1. Stress Gate
        // In Serious/Critical modes, we only accept Verified or Ally peers.
        if current_stress >= SystemStress::Serious
            && Self::trust_score(level) < Self::trust_score(TrustLevel::Verified)
        {
            return Err("System stress too high for untrusted peer");
        }

        let capacity = self.current_capacity(current_stress);

        // 2. Capacity Check
        if self.active_slots.len() < capacity {
            self.active_slots.insert(peer, level);
            return Ok(None);
        }

        // 3. Preemption Logic (Identity-Weighted Fair Queuing)
        let incoming_score = Self::trust_score(level);

        // Find a peer in active_slots with a strictly lower TrustLevel.
        // We prioritize evicting the lowest trust peer to make room.
        let victim = self
            .active_slots
            .iter()
            .filter(|(_, &l)| Self::trust_score(l) < incoming_score)
            .min_by_key(|(_, &l)| Self::trust_score(l))
            .map(|(id, _)| id.clone());

        if let Some(victim_id) = victim {
            self.active_slots.remove(&victim_id);
            self.active_slots.insert(peer, level);
            Ok(Some(victim_id))
        } else {
            Err("No lower-priority slots available for preemption")
        }
    }

    pub fn release_slot(&mut self, peer: &NetworkId) {
        self.active_slots.remove(peer);
    }

    fn trust_score(level: TrustLevel) -> u8 {
        match level {
            TrustLevel::Blocked => 0,
            TrustLevel::Ignored => 1,
            TrustLevel::Verified => 2,
            TrustLevel::Ally => 3,
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockClock;
    use phalanx_proto::identity::Did;
    use phalanx_proto::trust::{TrustRecord, TrustRegistry};

    #[test]
    fn test_reputation_recovery_over_time() {
        let mut registry = TrustRegistry::default();
        let peer_did = Did("test_peer".to_string());
        let mut clock = MockClock::new(1000); // Start at T=1000

        // 1. Setup a penalized peer (not yet banned)
        registry.peers.insert(
            peer_did.clone(),
            TrustRecord {
                reputation: 50,
                is_banned: false,
                last_update_secs: clock.now(),
            },
        );

        // 2. Advance time by half an interval (No recovery expected)
        clock.tick(30);
        TrustArbiter::accumulate_reputation(&mut registry, clock.now(), 60, 10);
        assert_eq!(
            registry.peers[&peer_did].reputation, 50,
            "Should not recover before interval"
        );

        // 3. Advance time past the full interval (Recovery: 50 -> 60)
        clock.tick(31); // Total 61s elapsed
        TrustArbiter::accumulate_reputation(&mut registry, clock.now(), 60, 10);
        assert_eq!(
            registry.peers[&peer_did].reputation, 60,
            "Reputation should have increased by recovery_step"
        );

        // 4. Advance time by multiple intervals (Recovery: 60 -> 90)
        clock.tick(120); // 2 more intervals
        TrustArbiter::accumulate_reputation(&mut registry, clock.now(), 60, 10);
        assert_eq!(
            registry.peers[&peer_did].reputation, 80,
            "Reputation should follow multi-cycle recovery"
        );

        // 5. Ensure it caps at the baseline (100)
        clock.tick(600);
        TrustArbiter::accumulate_reputation(&mut registry, clock.now(), 60, 10);
        assert_eq!(
            registry.peers[&peer_did].reputation, 100,
            "Reputation must not exceed 100"
        );
    }

    #[test]
    fn test_banned_peers_do_not_recover() {
        let mut registry = TrustRegistry::default();
        let peer_did = Did("bad_actor".to_string());
        let mut clock = MockClock::new(1000);

        registry.peers.insert(
            peer_did.clone(),
            TrustRecord {
                reputation: -10,
                is_banned: true, // HARD BAN
                last_update_secs: clock.now(),
            },
        );

        clock.tick(3600); // 1 hour later
        TrustArbiter::accumulate_reputation(&mut registry, clock.now(), 60, 10);

        assert!(registry.peers[&peer_did].is_banned);
        assert_eq!(
            registry.peers[&peer_did].reputation, -10,
            "Banned peers require manual pardon"
        );
    }
}
