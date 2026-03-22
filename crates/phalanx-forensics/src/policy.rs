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
        const RECOVERY_COOLDOWN_SECS: u64 = 60; // No recovery for 60s after last offense

        for record in peers.values_mut() {
            if record.reputation.is_blacklisted {
                continue;
            }

            // Cooldown: no recovery within 60 seconds of last offense
            let since_offense = now.elapsed_since(record.reputation.last_offense_secs);
            if since_offense < RECOVERY_COOLDOWN_SECS {
                continue;
            }

            let elapsed = now.elapsed_since(record.reputation.last_update_secs);
            let intervals = elapsed / interval_secs;

            if intervals > 0 {
                // Quadratic recovery: slower at low scores, faster near ceiling.
                // At score 20: (20/100)^2 = 4% speed. At score 80: (80/100)^2 = 64% speed.
                // Floor of 5% prevents permanent stalling.
                let normalized = if record.reputation.score <= 0 {
                    0.0_f64
                } else {
                    (record.reputation.score as f64 / MAX_REPUTATION as f64).max(0.0)
                };
                let recovery_factor = (normalized * normalized).max(0.05);
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

        // Physical Constraint: Hardware Preservation
        // Prevent heavy network egress if the device battery is dying or thermal throttling.
        if matches!(stress, SystemStress::Critical | SystemStress::Serious) {
            return Err(GuardianError::VerificationFailed(
                "Egress blocked: System stress exceeds safe operational limits".into(),
            ));
        }

        // Social Constraint: Zero-Trust Reputation
        // Prevent data exfiltration by untrusted, ignored, or actively malicious peers.
        if matches!(trust, TrustLevel::Blocked | TrustLevel::Ignored) {
            return Err(GuardianError::VerificationFailed(
                "Egress blocked: Requester lacks sufficient trust clearance".into(),
            ));
        }

        // Privacy Gate: Encrypt evidence payload before egress
        unit.data.evidence = unit
            .data
            .evidence
            .safeguard(encryption_key)
            .map_err(|e| GuardianError::VerificationFailed(e.to_string()))?;

        // Typestate Promotion (The core architectural lock)
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

        // Setup a penalized peer (not yet banned)
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

        // Advance time by half an interval (No recovery expected)
        clock.tick(30);
        TrustArbiter::accumulate_reputation(&mut peers, clock.now(), 60, 10);
        assert_eq!(
            peers[&peer_did].reputation.score, 50,
            "Should not recover before interval"
        );

        // Advance time past the full interval
        // Quadratic recovery: at score 50, factor = (50/100)^2 = 0.25, step = max(1, 2) = 2
        // Recovery: 50 -> 52
        clock.tick(31); // Total 61s elapsed
        TrustArbiter::accumulate_reputation(&mut peers, clock.now(), 60, 10);
        assert_eq!(
            peers[&peer_did].reputation.score, 52,
            "Reputation should have increased by quadratic recovery_step"
        );

        // Advance time by multiple intervals
        // At score 52, factor = (52/100)^2 = 0.2704, step = max(1, 2) = 2, 2 intervals = +4
        // Recovery: 52 -> 56
        clock.tick(120); // 2 more intervals
        TrustArbiter::accumulate_reputation(&mut peers, clock.now(), 60, 10);
        assert_eq!(
            peers[&peer_did].reputation.score, 56,
            "Reputation should follow quadratic multi-cycle recovery"
        );

        // Ensure it caps at the baseline (100) — quadratic recovery is slower, so
        // allow enough time for score to climb from 56 to the ceiling.
        clock.tick(6000);
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

        // Fill 10 slots with low-trust peers
        for i in 0..10 {
            let res = gov.try_allocate(mock_peer(), TrustLevel::Ignored, stress);
            assert!(res.is_ok(), "Failed to fill slot {}", i);
        }

        // Verify the 11th low-trust peer is REJECTED (Backpressure)
        let rejected_peer = mock_peer();
        let res = gov.try_allocate(rejected_peer, TrustLevel::Ignored, stress);
        assert!(res.is_err(), "11th Ignored peer should have been rejected");

        // Verify a high-trust ALLY peer PREEMPTS a low-trust peer
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

        // Verify Ignored peers are blocked regardless of capacity
        let res = gov.try_allocate(mock_peer(), TrustLevel::Ignored, stress);
        assert!(
            res.is_err(),
            "Ignored peer should be blocked during Serious stress"
        );

        // Verify Ally peer can still take the single remaining slot
        let res = gov.try_allocate(mock_peer(), TrustLevel::Ally, stress);
        assert!(
            res.is_ok(),
            "Ally should be allowed 1 slot during Serious stress"
        );

        // Verify second Ally is blocked (Capacity = 1)
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
