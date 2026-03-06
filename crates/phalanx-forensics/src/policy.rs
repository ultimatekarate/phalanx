use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::prelude::*;
use phalanx_proto::trust::PeerRecord;
use phalanx_proto::trust::{MonotonicClock, TrustRegistry};
use phalanx_proto::types::ForensicUnit;
use phalanx_proto::types::PhalanxPhysics;
use phalanx_proto::types::PowerState;
use phalanx_proto::types::Sealed;
use phalanx_proto::types::SystemStress;
use phalanx_proto::types::UnitInterval;
use phalanx_proto::types::Verified;
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
            if record.reputation.is_blacklisted {
                continue;
            }

            // last_update is now also a MonotonicClock
            let elapsed = now.elapsed_since(record.reputation.last_update_secs);
            let intervals = elapsed / interval_secs;

            if intervals > 0 {
                let total_recovery = (intervals as i64) * recovery_step;

                // ENFORCEMENT: Reputation cannot exceed the ceiling
                record.reputation.score =
                    (record.reputation.score + total_recovery).min(MAX_REPUTATION);

                if record.reputation.score < 0 {
                    record.reputation.is_blacklisted = true;
                }

                record.reputation.last_update_secs = now;
            }
        }
    }

    pub fn should_verify_signature<R: Rng>(record: &PeerRecord, rng: &mut R) -> bool {
        // Always verify if they are near the "Suspicion" zone
        if record.reputation.score < 80 {
            return true;
        }

        // Probabilistic sampling for high-trust peers
        // 100 Rep = 5% check rate
        // 80 Rep = 20% check rate
        let check_threshold: f64 = match record.reputation.score {
            100..=i64::MAX => 0.05,
            80..=99 => 0.20,
            _ => 1.0,
        };

        rng.gen_bool(check_threshold)
    }

    pub fn requires_heavy_verification<R: Rng>(record: &PeerRecord, rng: &mut R) -> bool {
        // High-Reputation (100+): 5% spot-check rate (1 in 20)
        // Established (80-99): 20% spot-check rate
        // New/Suspicious (<80): 100% check rate
        let probability = match record.reputation.score {
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

    pub fn release_slot(&mut self, peer: &NetworkId) {
        self.active_slots.remove(peer);
    }

    pub fn try_allocate(
        &mut self,
        peer: NetworkId,
        level: TrustLevel,
        current_stress: SystemStress,
    ) -> Result<Option<NetworkId>, &'static str> {
        let max_slots = self.current_capacity(current_stress);

        if self.active_slots.contains_key(&peer) {
            return Ok(None); // Peer already occupies a slot
        }

        // Under Serious stress, ONLY Ally or Verified peers are permitted
        if matches!(
            current_stress,
            SystemStress::Serious | SystemStress::Critical
        ) && matches!(level, TrustLevel::Blocked | TrustLevel::Ignored)
        {
            return Err("Capacity Exceeded: Thermal/Battery critical. Untrusted peers dropped.");
        }

        if self.active_slots.len() < max_slots {
            self.active_slots.insert(peer, level);
            return Ok(None);
        }

        // IWFQ Preemption: Find a peer with strictly lower trust to evict
        let target = self
            .active_slots
            .iter()
            .find(|(_, active_lvl)| active_lvl < &&level)
            .map(|(id, _)| id.clone());

        if let Some(evicted_peer) = target {
            self.active_slots.remove(&evicted_peer);
            self.active_slots.insert(peer, level);
            Ok(Some(evicted_peer))
        } else {
            Err("Capacity Exceeded: No lower-trust peers to preempt")
        }
    }
}

pub struct EgressGovernor;

impl EgressGovernor {
    /// Evaluates physical and social constraints to determine if a verified unit
    /// is authorized to be promoted for mesh egress.
    pub fn authorize(
        unit: ForensicUnit<WitnessEnvelope, Verified>,
        trust: &TrustLevel,
        stress: &SystemStress,
    ) -> Result<ForensicUnit<WitnessEnvelope, Sealed>, GuardianError> {
        // 1. Physical Constraint: Hardware Preservation
        // Prevent heavy network egress if the device battery is dying or thermal throttling.
        if matches!(stress, SystemStress::Critical | SystemStress::Serious) {
            return Err(GuardianError::VerificationFailed(
                "Egress blocked: System stress exceeds safe operational limits".into(),
            ));
        }

        // 2. Social Constraint: Zero-Trust Reputation
        // Prevent data exfiltration by untrusted, ignored, or actively malicious peers.
        if matches!(trust, TrustLevel::Blocked | TrustLevel::Ignored) {
            return Err(GuardianError::VerificationFailed(
                "Egress blocked: Requester lacks sufficient trust clearance".into(),
            ));
        }

        // Optional: If you want to restrict egress to ONLY explicitly Verified/Ally peers,
        // you could also block TrustLevel::Unknown here. For now, we block the known-bad.

        // 3. Typestate Promotion (The core architectural lock)
        // This is the ONLY place in the entire codebase where .seal() is called,
        // physically proving to the compiler that the data passed the policy gates.
        Ok(unit.seal())
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
    use phalanx_proto::trust::{PeerRecord, PeerReputation, TrustRegistry};

    #[test]
    fn test_reputation_recovery_over_time() {
        let mut registry = TrustRegistry::default();
        let peer_did = Did("test_peer".to_string());
        let mut clock = MockClock::new(1000); // Start at T=1000

        // 1. Setup a penalized peer (not yet banned)
        registry.peers.insert(
            peer_did.clone(),
            PeerRecord {
                reputation: PeerReputation {
                    score: 50,
                    is_blacklisted: false,
                    last_update_secs: clock.now(),
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        // 2. Advance time by half an interval (No recovery expected)
        clock.tick(30);
        TrustArbiter::accumulate_reputation(&mut registry, clock.now(), 60, 10);
        assert_eq!(
            registry.peers[&peer_did].reputation.score, 50,
            "Should not recover before interval"
        );

        // 3. Advance time past the full interval (Recovery: 50 -> 60)
        clock.tick(31); // Total 61s elapsed
        TrustArbiter::accumulate_reputation(&mut registry, clock.now(), 60, 10);
        assert_eq!(
            registry.peers[&peer_did].reputation.score, 60,
            "Reputation should have increased by recovery_step"
        );

        // 4. Advance time by multiple intervals (Recovery: 60 -> 90)
        clock.tick(120); // 2 more intervals
        TrustArbiter::accumulate_reputation(&mut registry, clock.now(), 60, 10);
        assert_eq!(
            registry.peers[&peer_did].reputation.score, 80,
            "Reputation should follow multi-cycle recovery"
        );

        // 5. Ensure it caps at the baseline (100)
        clock.tick(600);
        TrustArbiter::accumulate_reputation(&mut registry, clock.now(), 60, 10);
        assert_eq!(
            registry.peers[&peer_did].reputation.score, 100,
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
            PeerRecord {
                reputation: PeerReputation {
                    score: -10,
                    is_blacklisted: true, // HARD BAN
                    last_update_secs: clock.now(),
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        clock.tick(3600); // 1 hour later
        TrustArbiter::accumulate_reputation(&mut registry, clock.now(), 60, 10);

        assert!(registry.peers[&peer_did].reputation.is_blacklisted);
        assert_eq!(
            registry.peers[&peer_did].reputation.score, -10,
            "Banned peers require manual pardon"
        );
    }

    use phalanx_proto::identity::NetworkId;
    use phalanx_proto::trust::TrustLevel;
    use phalanx_proto::types::SystemStress;

    fn mock_peer() -> NetworkId {
        NetworkId::random()
    }

    #[test]
    fn test_iwfq_saturation_and_preemption() {
        let mut gov = IngressGovernor::new(10);
        let stress = SystemStress::Nominal;

        // 1. Fill 10 slots with low-trust peers
        for i in 0..10 {
            let res = gov.try_allocate(mock_peer(), TrustLevel::Ignored, stress);
            assert!(res.is_ok(), "Failed to fill slot {}", i);
        }

        // 2. Verify the 11th low-trust peer is REJECTED (Backpressure)
        let rejected_peer = mock_peer();
        let res = gov.try_allocate(rejected_peer, TrustLevel::Ignored, stress);
        assert!(res.is_err(), "11th Ignored peer should have been rejected");

        // 3. Verify a high-trust ALLY peer PREEMPTS a low-trust peer
        let ally_peer = mock_peer();
        match gov.try_allocate(ally_peer.clone(), TrustLevel::Ally, stress) {
            Ok(Some(evicted)) => {
                // Assert that one of the Ignored peers (0-9) was kicked out
                assert!(gov.active_slots.contains_key(&ally_peer));
                assert!(!gov.active_slots.contains_key(&evicted));
                println!("Preemption Success: Evicted low-trust peer {:?}", evicted);
            }
            other => panic!("Expected preemption of Ignored peer, got {:?}", other),
        }
    }

    #[test]
    fn test_thermal_load_shedding() {
        let mut gov = IngressGovernor::new(10);

        // Switch to Serious Stress (Capacity drops to 1)
        let stress = SystemStress::Serious;

        // 1. Verify Ignored peers are blocked regardless of capacity
        let res = gov.try_allocate(mock_peer(), TrustLevel::Ignored, stress);
        assert!(
            res.is_err(),
            "Ignored peer should be blocked during Serious stress"
        );

        // 2. Verify Ally peer can still take the single remaining slot
        let res = gov.try_allocate(mock_peer(), TrustLevel::Ally, stress);
        assert!(
            res.is_ok(),
            "Ally should be allowed 1 slot during Serious stress"
        );

        // 3. Verify second Ally is blocked (Capacity = 1)
        let res = gov.try_allocate(mock_peer(), TrustLevel::Ally, stress);
        assert!(
            res.is_err(),
            "Second Ally should be blocked by Serious capacity limit"
        );
    }

    #[test]
    fn test_causal_loop_recycling() {
        let mut gov = IngressGovernor::new(1);
        let peer = mock_peer();

        // Take the only slot
        gov.try_allocate(peer.clone(), TrustLevel::Verified, SystemStress::Nominal)
            .unwrap();

        // Verify full
        assert!(gov
            .try_allocate(mock_peer(), TrustLevel::Verified, SystemStress::Nominal)
            .is_err());

        // RELEASE via Causal Feedback
        gov.release_slot(&peer);

        // Verify slot is now usable again
        assert!(gov
            .try_allocate(mock_peer(), TrustLevel::Verified, SystemStress::Nominal)
            .is_ok());
    }
}
