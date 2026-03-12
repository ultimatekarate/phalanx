use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::prelude::*;
use phalanx_proto::trust::MonotonicClock;
use phalanx_proto::trust::PeerRecord;
use phalanx_proto::types::ForensicUnit;
use phalanx_proto::types::PhalanxPhysics;
use phalanx_proto::types::PowerState;
use phalanx_proto::types::Sealed;
use phalanx_proto::types::SystemStress;
use phalanx_proto::types::UnitInterval;
use phalanx_proto::types::Verified;
use phalanx_proto::vitals::HeartbeatInterval;

use std::collections::HashMap;

pub struct TrustArbiter;

impl TrustArbiter {
    /// Pure, deterministic recovery logic.
    pub fn accumulate_reputation(
        peers: &mut HashMap<Did, PeerRecord>,
        now: MonotonicClock,
        interval_secs: u64,
        recovery_step: i64,
    ) {
        const MAX_REPUTATION: i64 = 100; // The ceiling of trust

        for record in peers.values_mut() {
            if record.reputation.is_blacklisted {
                continue;
            }

            let elapsed = now.elapsed_since(record.reputation.last_update_secs);
            let intervals = elapsed / interval_secs;

            if intervals > 0 {
                // E7 FIX: Diminishing recovery — peers with lower scores recover slower.
                // Linear recovery allows penalized peers to regain full trust too quickly.
                // Scale recovery by the ratio of current score to MAX, with a minimum of 10%.
                // A peer at score 50 recovers at 50% rate; at score 10, at 10% rate.
                let recovery_factor = if record.reputation.score <= 0 {
                    0.1_f64 // Minimum recovery rate for deeply penalized peers
                } else {
                    (record.reputation.score as f64 / MAX_REPUTATION as f64).max(0.1)
                };
                let scaled_step = ((recovery_step as f64) * recovery_factor) as i64;
                let effective_step = scaled_step.max(1); // At least 1 per interval
                let total_recovery = (intervals as i64) * effective_step;

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

    /// Forensic Zero-Trust: Unconditional Cryptographic Verification.
    /// We no longer rely on probabilistic trust sampling. All signatures MUST be verified.
    #[inline(always)]
    pub fn should_verify_signature(record: &PeerRecord) -> bool {
        // We still reject blacklisted peers immediately, but for all others,
        // we demand 100% verification.
        !record.reputation.is_blacklisted
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
            PowerState::Normal | PowerState::Conserving => true,
            // Pre-allocation check: only allow loopback traffic when in survival mode
            PowerState::Leaf | PowerState::Dormant => peer_id == local_peer_id,
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
        mut unit: ForensicUnit<WitnessEnvelope, Verified>,
        trust: &TrustLevel,
        stress: &SystemStress,
        encryption_key: &SymmetricKey,
    ) -> Result<ForensicUnit<WitnessEnvelope, Sealed>, GuardianError> {
        use crate::gate::PrivacyGate;

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

        // 3. Privacy Gate: Encrypt evidence payload before egress
        unit.data.evidence = unit
            .data
            .evidence
            .safeguard(encryption_key)
            .map_err(|e| GuardianError::VerificationFailed(e.to_string()))?;

        // 4. Typestate Promotion (The core architectural lock)
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
        let power_multiplier = match state {
            PowerState::Normal => 1.0,
            PowerState::Conserving => 2.0,
            PowerState::Leaf => 5.0,
            PowerState::Dormant => 10.0,
        };
        dynamic_ms *= power_multiplier;

        HeartbeatInterval(dynamic_ms as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockClock;
    use phalanx_proto::identity::Did;
    use phalanx_proto::trust::{PeerRecord, PeerReputation};

    #[test]
    fn test_reputation_recovery_over_time() {
        let mut peers = HashMap::<Did, PeerRecord>::new();
        let peer_did = Did("test_peer".to_string());
        let mut clock = MockClock::new(1000); // Start at T=1000

        // 1. Setup a penalized peer (not yet banned)
        peers.insert(
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
        TrustArbiter::accumulate_reputation(&mut peers, clock.now(), 60, 10);
        assert_eq!(
            peers[&peer_did].reputation.score, 50,
            "Should not recover before interval"
        );

        // 3. Advance time past the full interval
        // E7 FIX: Diminishing recovery — at score 50, factor = 0.5, step = 5
        // Recovery: 50 -> 55
        clock.tick(31); // Total 61s elapsed
        TrustArbiter::accumulate_reputation(&mut peers, clock.now(), 60, 10);
        assert_eq!(
            peers[&peer_did].reputation.score, 55,
            "Reputation should have increased by scaled recovery_step (diminishing returns)"
        );

        // 4. Advance time by multiple intervals
        // E7 FIX: At score 55, factor = 0.55, step = 5 (truncated), 2 intervals = +10
        // Recovery: 55 -> 65
        clock.tick(120); // 2 more intervals
        TrustArbiter::accumulate_reputation(&mut peers, clock.now(), 60, 10);
        assert_eq!(
            peers[&peer_did].reputation.score, 65,
            "Reputation should follow diminishing multi-cycle recovery"
        );

        // 5. Ensure it caps at the baseline (100)
        clock.tick(600);
        TrustArbiter::accumulate_reputation(&mut peers, clock.now(), 60, 10);
        assert_eq!(
            peers[&peer_did].reputation.score, 100,
            "Reputation must not exceed 100"
        );
    }

    #[test]
    fn test_banned_peers_do_not_recover() {
        let mut peers = HashMap::<Did, PeerRecord>::new();
        let peer_did = Did("bad_actor".to_string());
        let mut clock = MockClock::new(1000);

        peers.insert(
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
        TrustArbiter::accumulate_reputation(&mut peers, clock.now(), 60, 10);

        assert!(peers[&peer_did].reputation.is_blacklisted);
        assert_eq!(
            peers[&peer_did].reputation.score, -10,
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
