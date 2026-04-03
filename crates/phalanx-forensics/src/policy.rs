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
use std::time::Duration;

pub struct TrustArbiter;

impl TrustArbiter {
    /// Pure, deterministic recovery logic.
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Reputation arithmetic — scores clamped to [0, MAX_REPUTATION].
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
                                                         // intervals is bounded by elapsed/interval_secs, safe to cast.
                #[allow(clippy::cast_possible_wrap)]
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

        // dynamic_ms is non-negative: base_latency_ms, load, and power_multiplier are all >= 0.
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        HeartbeatInterval(dynamic_ms as u64)
    }
}

// =====================================================================
// VOLTERRA INTEGRAL TYPES (Homeostatic Kernel)
// =====================================================================
//
// These types were extracted from phalanx-node::vitals so that the
// Laboratory owns the mathematical primitives.  The Sentence (phalanx-node)
// re-exports them for backward compatibility.

// --- Physical Constants & Derivation Anchors ---

const LN_2: f64 = core::f64::consts::LN_2;

/// Normal-state vitals tick interval (seconds). Anchors time-based thresholds.
/// s_crit and lambda_sys are both coupled to this interval.
pub const NORMAL_TICK_SECS: f64 = 5.0;

/// Fraction of device RAM that constitutes critical memory pressure.
/// At 4GB reference device: 0.125 × 4096 MiB = 512 MiB.
pub const MEMORY_CRITICAL_FRACTION: f64 = 0.125;

/// Reference device RAM (MiB) used when HardwareProbe doesn't provide actual RAM.
/// Fallback for tests, sim, and desktop without probe.
pub const REFERENCE_RAM_MIB: f64 = 4096.0;

/// Safety margin on storage before critical (20% headroom for phone).
pub const STORAGE_SAFETY_MARGIN: f64 = 0.20;

/// Safety margin on connections before critical (10% for phone).
pub const CONNECTION_SAFETY_MARGIN: f64 = 0.10;

/// Sustained bandwidth rate that constitutes full pressure (MiB/s).
/// At NORMAL_TICK_SECS=5: 20 × 5 = 100 MiB per tick cycle.
pub const BANDWIDTH_BUDGET_MIB_PER_SEC: f64 = 20.0;

/// Pipeline capacity multiplier. The ingestion pipeline can buffer
/// PIPELINE_CAPACITY_FACTOR × s_crit concurrent stress units.
/// At s_crit=10, this yields 200 — enough to absorb a 200-chunk
/// burst without backpressure at normal operating stress.
const PIPELINE_CAPACITY_FACTOR: f64 = 20.0;

// --- Half-lives (seconds) ---
// Each half-life is the physical time for an integral to forget half
// of a past impulse. lambda = ln(2) / half_life.

/// CPU contention resolves within ~170ms (scheduler preemption quantum).
const HALF_LIFE_SYS: f64 = 0.17;
/// I/O latency spikes resolve within ~1.4s (disk flush cycle).
const HALF_LIFE_IO: f64 = 1.4;
/// Memory allocation patterns shift over ~2.3s (GC/drop cycles).
const HALF_LIFE_MEM: f64 = 2.3;
/// Storage fills/drains slowly — ~14s memory (WAL rotation period).
const HALF_LIFE_WAL: f64 = 14.0;
/// Bandwidth bursts are transient — matched to I/O recovery.
const HALF_LIFE_BW: f64 = 1.4;
/// Connection churn settles over ~3.5s (TCP/QUIC handshake window).
const HALF_LIFE_CONN: f64 = 3.5;
/// Trust decisions are sticky — ~69s memory (multiple topology ticks).
const HALF_LIFE_REP: f64 = 69.0;
/// Entry pressure persists across ~7s (Sybil attack detection window).
const HALF_LIFE_ENTRY: f64 = 7.0;
/// Network RTT changes rapidly — ~700ms memory.
const HALF_LIFE_LAT: f64 = 0.7;
/// Contribution tracking — 5-minute half-life matches the maintenance tick interval.
/// Longer than λ_rep (69s) to resist end-of-tick burst attacks.
/// Does NOT enter composite stress — lives in a feedforward path only.
const HALF_LIFE_CONTRIB: f64 = 300.0;

// --- Scaler Newtypes ---

/// Hardened newtypes for the homeostasis API boundaries.

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct IngestionScale(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct FinalizationScale(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct SybilEndowment(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct MemoryScale(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct StorageScale(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct BandwidthScale(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct ConnectionScale(pub f64);

impl IngestionScale {
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Throttle arithmetic — delay values bounded by base_delay_ms.
    pub fn as_throttle_delay(&self, base_delay_ms: u64) -> Duration {
        if self.0 <= 0.01 {
            Duration::from_millis(base_delay_ms * 100)
        } else {
            let multiplier = (1.0 / self.0) - 1.0;
            // base_delay_ms and multiplier are non-negative.
            #[allow(clippy::cast_sign_loss)]
            Duration::from_millis((base_delay_ms as f64 * multiplier) as u64)
        }
    }
}

// --- DecayingIntegral ---

use tokio::time::Instant;

/// A single Volterra second-kind integral with its own time cursor.
/// Each integral decays independently: I(t+dt) = impulse + I(t) · exp(-λ·dt)
/// where dt is measured from THIS integral's last update, not a shared clock.
///
/// Before this fix, all integrals shared a single `last_sys_tick`. High-frequency
/// updates to one integral (e.g., bandwidth) would suppress decay in all others,
/// causing phantom cross-coupling and ~10x pressure inflation under load.
#[derive(Debug)]
pub struct DecayingIntegral {
    value: f64,
    lambda: f64,
    last_update: Instant,
}

impl DecayingIntegral {
    pub fn new(lambda: f64) -> Self {
        Self {
            value: 0.0,
            lambda,
            last_update: Instant::now(),
        }
    }

    /// Record an impulse, applying exponential decay since this integral's last update.
    pub fn record(&mut self, impulse: f64) {
        let now = Instant::now();
        let dt = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;
        self.value = impulse + self.value * (-self.lambda * dt).exp();
    }

    /// Read the current decayed value without mutating state.
    /// Applies lazy decay based on elapsed time since last update.
    pub fn current_value(&self) -> f64 {
        let dt = self.last_update.elapsed().as_secs_f64();
        self.value * (-self.lambda * dt).exp()
    }
}

// --- HomeostaticConfig ---

#[derive(Debug, Clone)]
pub struct HomeostaticConfig {
    pub lambda_sys: f64,
    pub s_crit: f64,
    pub lambda_io: f64,
    pub d_crit: f64,
    pub lambda_rep: f64,
    pub omega: f64,
    pub lambda_entry: f64,
    pub psi_max: f64,
    pub k_sybil: f64,
    pub base_temporal_drift: Duration,
    // Resource pressure decay constants (Volterra kernel parameters)
    pub lambda_mem: f64,                  // Memory pressure decay rate
    pub m_crit: f64,                      // Memory critical threshold (MiB)
    pub lambda_wal: f64,                  // WAL/storage pressure decay rate
    pub w_crit: f64,                      // Storage critical ratio (0.0-1.0)
    pub lambda_bw: f64,                   // Bandwidth pressure decay rate
    pub b_crit: f64,                      // Bandwidth critical threshold (MiB)
    pub lambda_conn: f64,                 // Connection pressure decay rate
    pub c_crit: f64,                      // Connection critical ratio (0.0-1.0)
    pub lambda_lat: f64,                  // Latency pressure decay rate (independent of lambda_sys)
    pub lambda_contrib: f64,              // Contribution tracking decay rate (reciprocity floor)
    pub max_temporal_tolerance: Duration, // Hard clamp on temporal_tolerance (T2 fix)
    /// Composite stress weights [s, d, m, w, b]. Sum = 1.0.
    pub stress_weights: [f64; 5],
}

impl HomeostaticConfig {
    #[allow(clippy::cast_possible_truncation)] // f64 to usize — pipeline capacity is small by design.
    pub fn pipeline_capacity(&self) -> usize {
        // s_crit and PIPELINE_CAPACITY_FACTOR are positive constants.
        #[allow(clippy::cast_sign_loss)]
        {
            (self.s_crit * PIPELINE_CAPACITY_FACTOR) as usize
        }
    }
}

impl Default for HomeostaticConfig {
    fn default() -> Self {
        Self {
            // Decay rates: lambda = ln(2) / half_life
            lambda_sys: LN_2 / HALF_LIFE_SYS,
            lambda_io: LN_2 / HALF_LIFE_IO,
            lambda_mem: LN_2 / HALF_LIFE_MEM,
            lambda_wal: LN_2 / HALF_LIFE_WAL,
            lambda_bw: LN_2 / HALF_LIFE_BW,
            lambda_conn: LN_2 / HALF_LIFE_CONN,
            lambda_rep: LN_2 / HALF_LIFE_REP,
            lambda_entry: LN_2 / HALF_LIFE_ENTRY,
            lambda_lat: LN_2 / HALF_LIFE_LAT,
            lambda_contrib: LN_2 / HALF_LIFE_CONTRIB,
            // Critical thresholds: derived from tick interval and physical parameters
            s_crit: 2.0 * NORMAL_TICK_SECS,
            d_crit: 5.0 * NORMAL_TICK_SECS,
            m_crit: REFERENCE_RAM_MIB * MEMORY_CRITICAL_FRACTION,
            w_crit: 1.0 - STORAGE_SAFETY_MARGIN,
            b_crit: BANDWIDTH_BUDGET_MIB_PER_SEC * NORMAL_TICK_SECS,
            c_crit: 1.0 - CONNECTION_SAFETY_MARGIN,
            // Sybil parameters
            // psi_max: per-peer resource ceiling. At 64 max connections,
            // total system capacity = 50 × 64 = 3200 units.
            psi_max: 50.0,
            // k_sybil: at entry pressure = psi_max/k = 25, endowment halves.
            k_sybil: 2.0,
            // omega: reputation scaling. With half-life=69s, a single evidence
            // (±1.0) decays to ±0.5 after 69s. At omega=100, ~100 valid
            // messages needed to fully restore a zero-reputation peer.
            omega: 100.0,
            // Temporal constants
            // 500ms: typical NTP sync accuracy on mobile devices.
            base_temporal_drift: Duration::from_millis(500),
            // 10s = 2 × NORMAL_TICK_SECS. Beyond this, timestamps are too
            // stale for forensic chain-of-custody guarantees.
            // NORMAL_TICK_SECS is a positive constant (5.0).
            #[allow(
                clippy::cast_sign_loss,
                clippy::arithmetic_side_effects,
                clippy::cast_possible_truncation
            )]
            max_temporal_tolerance: Duration::from_secs(2 * NORMAL_TICK_SECS as u64),
            // Composite stress weights. Sum = 1.0.
            // Risk hierarchy: system metabolic (most critical — blocks all work) >
            // I/O, memory, bandwidth (equal — all limit throughput) >
            // storage (least critical — can defer writes).
            stress_weights: [0.25, 0.20, 0.20, 0.15, 0.20],
        }
    }
}

// --- ResourceIntegrals ---

/// The generic Volterra integral bank, extracted from IntegralState.
/// Contains only the mathematical integrals — no phone-specific fields.
pub struct ResourceIntegrals {
    pub s: DecayingIntegral, // System/metabolic
    pub d: DecayingIntegral, // I/O digestion
    pub e: DecayingIntegral, // Entry/Sybil
    pub l: DecayingIntegral, // Latency
    pub m: DecayingIntegral, // Memory
    pub w: DecayingIntegral, // WAL/storage
    pub b: DecayingIntegral, // Bandwidth
    pub c: DecayingIntegral, // Connection
    pub r_integrals: HashMap<String, DecayingIntegral>,
}

impl Default for ResourceIntegrals {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceIntegrals {
    pub fn new() -> Self {
        Self::from_config(&HomeostaticConfig::default())
    }

    pub fn from_config(config: &HomeostaticConfig) -> Self {
        Self {
            s: DecayingIntegral::new(config.lambda_sys),
            d: DecayingIntegral::new(config.lambda_io),
            e: DecayingIntegral::new(config.lambda_entry),
            l: DecayingIntegral::new(config.lambda_lat),
            m: DecayingIntegral::new(config.lambda_mem),
            w: DecayingIntegral::new(config.lambda_wal),
            b: DecayingIntegral::new(config.lambda_bw),
            c: DecayingIntegral::new(config.lambda_conn),
            r_integrals: HashMap::new(),
        }
    }
}

// --- Homeostasis Trait ---

pub trait Homeostasis {
    fn temporal_tolerance(&self) -> Duration;
    fn record_metabolic_pressure(&self, duration: Duration);
    fn record_latency_pressure(&self, duration: Duration);
    fn record_io_pressure(&self, duration: Duration);
    fn record_entry_pressure(&self);
    fn record_eclipse_impulse(&self, magnitude: f64);
    fn ingestion_scaler(&self) -> IngestionScale;
    fn finalization_scaler(&self) -> FinalizationScale;
    fn sybil_endowment(&self) -> SybilEndowment;
    // Resource pressure integrals (Volterra extensions)
    fn record_memory_pressure(&self, bytes_held: usize);
    fn record_storage_pressure(&self, used_bytes: u64, max_bytes: u64);
    fn record_bandwidth_pressure(&self, bytes: usize);
    fn record_connection_pressure(&self, active: usize, max: usize);
    fn memory_scaler(&self) -> MemoryScale;
    fn storage_scaler(&self) -> StorageScale;
    fn bandwidth_scaler(&self) -> BandwidthScale;
    fn connection_scaler(&self) -> ConnectionScale;
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
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
