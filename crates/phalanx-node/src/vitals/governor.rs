// crates/phalanx-node/src/vitals/governor.rs
//
// The System Governor: core homeostasis engine and power state management.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::time::Instant;

use phalanx_proto::types::{PowerState, SystemStress};

use super::config::{DecayingIntegral, Homeostasis, HomeostaticConfig, IntegralState};
use super::hardware::{HardwareProbe, SysfsProbe};
use super::types::{
    BandwidthScale, ConnectionScale, FinalizationScale, IngestionScale, MemoryScale, StorageScale,
    SybilEndowment,
};

pub struct SystemGovernor {
    current_state: RwLock<SystemStress>,
    probe: Arc<dyn HardwareProbe>,
    pub config: HomeostaticConfig,
    pub integrals: RwLock<IntegralState>,
    pub recommended_state: RwLock<PowerState>,
    /// Monotonic epoch for DecayingIntegral time domain.
    /// Uses tokio::time::Instant so paused virtual time (sim) is respected.
    epoch: Instant,
    // Socket-level I/O counters from the transport layer.
    // Sampled on the vitals tick to feed Volterra integrals.
    io_bytes_sent: Option<Arc<AtomicU64>>,
    io_bytes_received: Option<Arc<AtomicU64>>,
    io_ops: Option<Arc<AtomicU64>>,
    transport_drops: Option<Arc<AtomicU64>>,
    /// Outbound command-channel depth from the libp2p adapter. A *level*
    /// signal: each tick it contributes
    /// `queue_depth × queue_pressure_bytes_per_slot` bytes of pressure to
    /// the `b` integral. Diagnostic for the post-prune state where
    /// `bytes_sent` flatlines but pending demand is still high.
    queue_depth: Option<Arc<AtomicU64>>,
    last_io_bytes_sent: AtomicU64,
    last_io_bytes_received: AtomicU64,
    last_io_ops: AtomicU64,
    last_transport_drops: AtomicU64,
}

impl Default for SystemGovernor {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemGovernor {
    pub fn new() -> Self {
        Self::with_config(HomeostaticConfig::default())
    }

    /// Monotonic seconds since this governor's epoch.
    /// Uses tokio::time::Instant so sim virtual time is respected.
    pub fn now_secs(&self) -> f64 {
        self.epoch.elapsed().as_secs_f64()
    }

    /// Create with a custom hardware probe (for mobile platforms).
    /// Overrides m_crit from actual device RAM if the probe provides it.
    pub fn with_probe(mut config: HomeostaticConfig, probe: Arc<dyn HardwareProbe>) -> Self {
        if let Some(ram_bytes) = probe.total_ram_bytes() {
            let ram_mib = ram_bytes as f64 / 1_048_576.0;
            config.m_crit = ram_mib * phalanx_forensics::policy::MEMORY_CRITICAL_FRACTION;
        }
        let epoch = Instant::now();
        let integrals = IntegralState::from_config(&config, 0.0);
        Self {
            current_state: RwLock::new(SystemStress::Nominal),
            probe,
            integrals: RwLock::new(integrals),
            config,
            recommended_state: RwLock::new(PowerState::Normal),
            epoch,
            io_bytes_sent: None,
            io_bytes_received: None,
            io_ops: None,
            transport_drops: None,
            queue_depth: None,
            last_io_bytes_sent: AtomicU64::new(0),
            last_io_bytes_received: AtomicU64::new(0),
            last_io_ops: AtomicU64::new(0),
            last_transport_drops: AtomicU64::new(0),
        }
    }

    pub fn with_state<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&IntegralState) -> R,
    {
        let state = self.integrals.read().unwrap_or_else(|e| e.into_inner());
        f(&state)
    }

    /// The "State Monad" helper for mutable state access.
    pub fn with_state_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut IntegralState) -> R,
    {
        let mut state = self.integrals.write().unwrap_or_else(|e| e.into_inner());
        f(&mut state)
    }

    pub fn with_config(config: HomeostaticConfig) -> Self {
        let epoch = Instant::now();
        let integrals = IntegralState::from_config(&config, 0.0);
        Self {
            current_state: RwLock::new(SystemStress::Nominal),
            probe: Arc::new(SysfsProbe::new()),
            integrals: RwLock::new(integrals),
            config,
            recommended_state: RwLock::new(PowerState::Normal),
            epoch,
            io_bytes_sent: None,
            io_bytes_received: None,
            io_ops: None,
            transport_drops: None,
            queue_depth: None,
            last_io_bytes_sent: AtomicU64::new(0),
            last_io_bytes_received: AtomicU64::new(0),
            last_io_ops: AtomicU64::new(0),
            last_transport_drops: AtomicU64::new(0),
        }
    }

    /// Attach socket-level I/O counters from the transport layer.
    /// Seeds last-values from the current counter state so the first
    /// vitals tick sees delta=0 (no spike from connection setup traffic).
    pub fn with_io_counters(
        mut self,
        sent: Arc<AtomicU64>,
        received: Arc<AtomicU64>,
        ops: Arc<AtomicU64>,
        dropped: Arc<AtomicU64>,
    ) -> Self {
        self.last_io_bytes_sent = AtomicU64::new(sent.load(Ordering::Relaxed));
        self.last_io_bytes_received = AtomicU64::new(received.load(Ordering::Relaxed));
        self.last_io_ops = AtomicU64::new(ops.load(Ordering::Relaxed));
        self.last_transport_drops = AtomicU64::new(dropped.load(Ordering::Relaxed));
        self.io_bytes_sent = Some(sent);
        self.io_bytes_received = Some(received);
        self.io_ops = Some(ops);
        self.transport_drops = Some(dropped);
        self
    }

    /// Attach the transport's outbound command-channel depth gauge.
    /// Each vitals tick, the current depth contributes a bytes-equivalent
    /// impulse to the `b` integral, so a sustained queue is visible to the
    /// homeostasis loop even when bytes_sent has flatlined (the post-
    /// gossipsub-mesh-prune state). Optional and additive: omitting it
    /// preserves prior behaviour exactly.
    pub fn with_queue_depth(mut self, queue_depth: Arc<AtomicU64>) -> Self {
        self.queue_depth = Some(queue_depth);
        self
    }

    pub fn current_stress(&self) -> SystemStress {
        *self
            .current_state
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    pub fn check_permission(&self, task_cost: phalanx_proto::types::TaskCost) -> bool {
        let state = *self
            .current_state
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        match (state, task_cost) {
            (SystemStress::Nominal, _) => true,
            (SystemStress::Fair, phalanx_proto::types::TaskCost::Heavy) => false,
            (SystemStress::Fair, phalanx_proto::types::TaskCost::Light) => true,
            (SystemStress::Serious, _) => false,
            (SystemStress::Critical, _) => false,
        }
    }

    #[tracing::instrument(level = "debug", skip_all)]
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // IO counter delta arithmetic and bandwidth casting.
    pub fn update_vitals(&self) {
        let t_stress = self.read_thermal();
        let b_stress = self.read_battery();
        let new_stress = std::cmp::max(t_stress, b_stress);

        // Periodic connectivity check (30s grace period)
        self.check_connectivity();

        // Each penalty = fraction of s_crit. Ensures heat penalties scale
        // with the system integral's critical threshold.
        let heat_penalty = match new_stress {
            SystemStress::Nominal => 0.0,
            SystemStress::Fair => 0.05 * self.config.s_crit, // 5% of critical
            SystemStress::Serious => 0.20 * self.config.s_crit, // 20% of critical
            SystemStress::Critical => self.config.s_crit,    // saturates s in one tick
        };

        if heat_penalty > 0.0 {
            let now = self.now_secs();
            self.with_state_mut(|s| s.s.record(heat_penalty, now));
        }

        // Sample socket-level I/O counters from the transport layer.
        self.sample_io_counters();

        let mut state = self
            .current_state
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *state = new_stress;

        // Automatic power state transition driven by composite integral stress
        let new_power = self.recommended_power_state();
        let mut power = self
            .recommended_state
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *power = new_power;
    }

    /// Sample socket-level I/O counters and feed deltas into Volterra integrals.
    /// Bandwidth (bytes sent+received) → b integral.
    /// Connection health (drops/ops ratio) → c integral.
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Delta arithmetic on saturating counters; u64→usize safe on 64-bit targets.
    fn sample_io_counters(&self) {
        // Bandwidth: bidirectional wire bytes (delta this tick) plus
        // outbound-queue back-pressure (level × bytes-per-slot) → b integral.
        //
        // The queue contribution is what catches the post-mesh-prune state:
        // when gossipsub has dropped the publisher's mesh peers, bytes_sent
        // flatlines but the command channel between Egress and the swarm
        // task stays full, so this term keeps the b integral fed and the
        // homeostasis loop responsive (PowerState transitions, FPS step-down)
        // even though no wire activity is occurring.
        if let (Some(sent), Some(recv)) = (&self.io_bytes_sent, &self.io_bytes_received) {
            let cur_sent = sent.load(Ordering::Relaxed);
            let cur_recv = recv.load(Ordering::Relaxed);
            let prev_sent = self.last_io_bytes_sent.swap(cur_sent, Ordering::Relaxed);
            let prev_recv = self
                .last_io_bytes_received
                .swap(cur_recv, Ordering::Relaxed);
            let bytes_delta =
                cur_sent.saturating_sub(prev_sent) + cur_recv.saturating_sub(prev_recv);

            let queue_impulse = self
                .queue_depth
                .as_ref()
                .map(|qd| {
                    qd.load(Ordering::Relaxed)
                        .saturating_mul(self.config.queue_pressure_bytes_per_slot)
                })
                .unwrap_or(0);

            let total = bytes_delta.saturating_add(queue_impulse);
            if total > 0 {
                self.record_bandwidth_pressure(total as usize);
            }
        }

        // Connection health: drops/ops is a self-normalizing ratio [0, 1].
        // No arbitrary constants — drops are bounded by ops.
        let ops_delta = if let Some(ref ops) = self.io_ops {
            let cur = ops.load(Ordering::Relaxed);
            let prev = self.last_io_ops.swap(cur, Ordering::Relaxed);
            cur.saturating_sub(prev)
        } else {
            0
        };

        let drops_delta = if let Some(ref drops) = self.transport_drops {
            let cur = drops.load(Ordering::Relaxed);
            let prev = self.last_transport_drops.swap(cur, Ordering::Relaxed);
            cur.saturating_sub(prev)
        } else {
            0
        };

        if ops_delta > 0 && drops_delta > 0 {
            let now = self.now_secs();
            self.with_state_mut(|s| {
                let ratio = (drops_delta as f64 / ops_delta as f64).min(1.0);
                s.c.record(ratio, now);
            });
        }
    }

    // --- Immune Integral (Reputation) ---

    pub fn record_peer_evidence(&self, peer_id: &str, is_valid: bool) {
        let now = self.now_secs();
        self.with_state_mut(|s| {
            let delta = if is_valid { 1.0 } else { -self.config.omega };
            s.r_integrals
                .entry(peer_id.to_string())
                .or_insert_with(|| DecayingIntegral::new(self.config.lambda_rep, now))
                .record(delta, now);

            // Also record to the contribution integral (separate key, separate decay).
            // Only positive contributions count — invalid evidence doesn't earn credit.
            if is_valid {
                let contrib_key = format!("contrib:{}", peer_id);
                s.r_integrals
                    .entry(contrib_key)
                    .or_insert_with(|| DecayingIntegral::new(self.config.lambda_contrib, now))
                    .record(1.0, now);
            }
        });
    }

    pub fn is_peer_coupled(&self, peer_id: &str) -> bool {
        let now = self.now_secs();
        self.with_state(|s| {
            s.r_integrals
                .get(peer_id)
                .is_none_or(|r| r.current_value(now) >= 0.0)
        })
    }

    /// Per-peer bandwidth check via the r_integrals namespace.
    /// Peers accumulate +1.0 per event under a "bw:{peer_id}" key.
    /// Returns false when accumulated bandwidth pressure exceeds the sybil ceiling.
    pub fn is_peer_bandwidth_ok(&self, peer_id: &str) -> bool {
        let now = self.now_secs();
        let key = format!("bw:{}", peer_id);
        self.with_state(|s| {
            s.r_integrals
                .get(&key)
                .is_none_or(|r| r.current_value(now) < self.config.psi_max)
        })
    }

    /// Records per-peer bandwidth event into the r_integrals namespace.
    pub fn record_peer_bandwidth(&self, peer_id: &str) {
        let now = self.now_secs();
        let key = format!("bw:{}", peer_id);
        self.with_state_mut(|s| {
            s.r_integrals
                .entry(key)
                .or_insert_with(|| DecayingIntegral::new(self.config.lambda_rep, now))
                .record(1.0, now);
        });
    }

    /// Per-recording retrieval rate limit.
    /// Returns false if this recording has been requested too frequently.
    pub fn is_retrieval_rate_ok(&self, recording_id: &str) -> bool {
        let now = self.now_secs();
        let key = format!("ret:{}", recording_id);
        self.with_state(|s| {
            s.r_integrals
                .get(&key)
                .is_none_or(|r| r.current_value(now) < self.config.psi_max)
        })
    }

    /// Record a retrieval attempt for rate limiting.
    pub fn record_retrieval_attempt(&self, recording_id: &str) {
        let now = self.now_secs();
        let key = format!("ret:{}", recording_id);
        self.with_state_mut(|s| {
            s.r_integrals
                .entry(key)
                .or_insert_with(|| DecayingIntegral::new(self.config.lambda_rep, now))
                .record(1.0, now);
        });
    }

    /// Shield Wall: record a spectral anomaly for a peer.
    ///
    /// Drives the peer's reputation integral toward decoupling via
    /// negative impulse.  The existing `is_peer_coupled()` check in
    /// the ingestion pipeline will reject the peer when the integral
    /// goes below zero.
    pub fn record_spectral_anomaly(&self, peer_id: &str, residual: f64) {
        let now = self.now_secs();
        self.with_state_mut(|s| {
            s.r_integrals
                .entry(peer_id.to_string())
                .or_insert_with(|| DecayingIntegral::new(self.config.lambda_rep, now))
                .record(-residual, now);
        });
    }

    /// Read the contribution integral for a peer (reciprocity floor).
    ///
    /// Reads from the `"contrib:{peer_id}"` key in `r_integrals`, which is
    /// written by `record_peer_evidence` and never touched by penalty paths.
    pub fn peer_contribution_value(&self, peer_id: &str) -> f64 {
        let now = self.now_secs();
        let key = format!("contrib:{}", peer_id);
        self.with_state(|s| {
            s.r_integrals
                .get(&key)
                .map_or(0.0, |r| r.current_value(now))
        })
    }

    /// Remove `r_integrals` entries that have decayed to near-zero.
    ///
    /// Bounds unbounded growth of per-peer reputation, bandwidth, and
    /// contribution keys. Safe because `entry().or_insert_with()` recreates
    /// entries on the next impulse.
    pub fn prune_stale_integrals(&self) {
        const EPSILON: f64 = 0.001;
        let now = self.now_secs();
        self.with_state_mut(|s| {
            s.r_integrals
                .retain(|_, integral| integral.current_value(now).abs() > EPSILON);
        });
    }

    /// Bounded composite stress as a `StressLoad`, suitable for outbound
    /// `ControlMessage` heartbeats. Clamps `composite_stress()` to `[0, 1]`.
    pub fn load_factor(&self) -> phalanx_proto::vitals::StressLoad {
        phalanx_proto::vitals::StressLoad::from_clamped(self.composite_stress())
    }

    /// True when the recommended power state is at or below `Leaf`.
    /// `Dormant` is treated as leaf for advertised-capacity purposes:
    /// a Dormant node is not contributing capacity by definition.
    /// Mirrors the reciprocity-floor sweep pattern in MeshSentinel.
    pub fn is_leaf_state(&self) -> bool {
        matches!(
            self.current_power_state(),
            PowerState::Leaf | PowerState::Dormant
        )
    }

    /// Eight integral observations in fixed wire order `[s, d, e, l, m, w, b, c]`,
    /// each normalized by its critical threshold and clamped to `[0, 1]`.
    /// Suitable for outbound `ControlMessage::integral_summary` (Tier 2 Shield Wall).
    ///
    /// Order is locked by `IntegralSummary`'s named accessors. Do not reshuffle
    /// without bumping the protocol version.
    ///
    /// `e` (entry/sybil) normalizes by `psi_max` because there is no `e_crit`;
    /// `l` (latency) normalizes by `max_temporal_tolerance` converted to seconds.
    #[tracing::instrument(level = "debug", skip_all)]
    #[allow(clippy::cast_possible_truncation)] // values are clamped to [0, 1] before cast.
    pub fn integral_summary(&self) -> phalanx_proto::vitals::IntegralSummary {
        let now = self.now_secs();
        let l_crit_secs = self
            .config
            .max_temporal_tolerance
            .as_secs_f64()
            .max(f64::EPSILON);
        let arr = self.with_state(|s| {
            let norm = |v: f64, crit: f64| (v / crit.max(f64::EPSILON)).clamp(0.0, 1.0) as f32;
            [
                norm(s.s.current_value(now), self.config.s_crit),
                norm(s.d.current_value(now), self.config.d_crit),
                norm(s.e.current_value(now), self.config.psi_max),
                norm(s.l.current_value(now), l_crit_secs),
                norm(s.m.current_value(now), self.config.m_crit),
                norm(s.w.current_value(now), self.config.w_crit),
                norm(s.b.current_value(now), self.config.b_crit),
                norm(s.c.current_value(now), self.config.c_crit),
            ]
        });
        phalanx_proto::vitals::IntegralSummary(arr)
    }

    /// Weighted composite of all integral pressures for power state transitions.
    /// Returns 0.0 (idle) to 1.0+ (saturated).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn composite_stress(&self) -> f64 {
        let w = &self.config.stress_weights;
        let now = self.now_secs();
        self.with_state(|s| {
            let normalized = [
                s.s.current_value(now) / self.config.s_crit,
                s.d.current_value(now) / self.config.d_crit,
                s.m.current_value(now) / self.config.m_crit,
                s.w.current_value(now) / self.config.w_crit,
                s.b.current_value(now) / self.config.b_crit,
            ];
            w.iter()
                .zip(normalized.iter())
                .map(|(wi, ni)| wi * ni.min(1.0))
                .sum()
        })
    }

    /// Two-stage power state evaluation. Final state = max restriction wins.
    ///
    /// Stage 1: Battery gate (hard physical constraint, NO hysteresis — physical state is authoritative)
    /// Stage 2: Composite stress (software signal, existing hysteresis: 0.85/0.50/0.30 thresholds)
    ///
    /// `Dormant > Leaf > Conserving > Normal` in restrictiveness (PowerState derives Ord).
    pub fn recommended_power_state(&self) -> PowerState {
        // Stage 1: Battery gate (hard physical constraint)
        let battery = self.battery_gate();

        // Stage 2: Composite stress with hysteresis
        let stress = self.stress_recommendation();

        // Max restriction wins
        battery.max(stress)
    }

    // Hysteresis thresholds for power state transitions.
    // Thresholds divide the [0, 1] composite_stress range into response zones.
    // De-escalation requires more evidence (5 ticks) than escalation (3 ticks)
    // because premature de-escalation wastes battery.
    const LEAF_THRESHOLD: f64 = 0.85;
    const CONSERVING_THRESHOLD: f64 = 0.50;
    const NORMAL_THRESHOLD: f64 = 0.30;
    const ESCALATION_TICKS: u8 = 3;
    const DEESCALATION_TICKS: u8 = 5;

    /// Composite-stress-driven power state recommendation with hysteresis.
    ///
    /// **Important:** Stress can only produce Normal/Conserving/Leaf — never Dormant.
    /// Dormant is exclusively a battery gate output (background state, not software stress).
    /// The hysteresis fallback clamps to Leaf to prevent inheriting battery-gate-driven Dormant.
    fn stress_recommendation(&self) -> PowerState {
        let composite = self.composite_stress();
        let mut integrals = self.integrals.write().unwrap_or_else(|e| e.into_inner());

        if composite > Self::LEAF_THRESHOLD {
            integrals.leaf_trigger_count = integrals.leaf_trigger_count.saturating_add(1);
            integrals.conserving_trigger_count = 0;
            integrals.normal_trigger_count = 0;
        } else if composite > Self::CONSERVING_THRESHOLD {
            integrals.conserving_trigger_count =
                integrals.conserving_trigger_count.saturating_add(1);
            integrals.leaf_trigger_count = 0;
            integrals.normal_trigger_count = 0;
        } else if composite < Self::NORMAL_THRESHOLD {
            integrals.normal_trigger_count = integrals.normal_trigger_count.saturating_add(1);
            integrals.leaf_trigger_count = 0;
            integrals.conserving_trigger_count = 0;
        } else {
            integrals.leaf_trigger_count = 0;
            integrals.conserving_trigger_count = 0;
            integrals.normal_trigger_count = 0;
        }

        let stress_state = if integrals.leaf_trigger_count >= Self::ESCALATION_TICKS {
            PowerState::Leaf
        } else if integrals.conserving_trigger_count >= Self::ESCALATION_TICKS {
            PowerState::Conserving
        } else if integrals.normal_trigger_count >= Self::DEESCALATION_TICKS {
            PowerState::Normal
        } else {
            // Maintain stress-specific state during hysteresis window.
            // Uses stress_power_state (not recommended_state) to avoid inheriting
            // battery-gate-driven Dormant — stress never produces Dormant.
            integrals.stress_power_state
        };

        // Record stress output for next hysteresis fallback
        integrals.stress_power_state = stress_state;
        stress_state
    }

    /// Reads the current recommended power state (updated by update_vitals polling).
    pub fn current_power_state(&self) -> PowerState {
        *self
            .recommended_state
            .read()
            .unwrap_or_else(|e| e.into_inner())
    }

    // --- Internet Connectivity Detection ---

    /// Duration after the last internet peer was seen before declaring offline.
    const INTERNET_GRACE_PERIOD: Duration = Duration::from_secs(30);

    /// Update connectivity state based on a newly discovered peer and its discovery source.
    ///
    /// Detection strategy (from architectural plan):
    /// - If the node has connected non-mDNS peers (relay, Kademlia bootstrap), internet is available.
    /// - If ALL connected peers are mDNS-local for >30s, mark internet as unavailable.
    pub fn record_peer_discovery(&self, source: phalanx_proto::telemetry::DiscoverySource) {
        use phalanx_proto::telemetry::DiscoverySource;

        self.with_state_mut(|s| {
            match source {
                DiscoverySource::Mdns => {
                    s.local_peer_count = s.local_peer_count.saturating_add(1);
                }
                DiscoverySource::Bootstrap
                | DiscoverySource::Kademlia
                | DiscoverySource::Identify
                | DiscoverySource::Quic => {
                    s.internet_peer_count = s.internet_peer_count.saturating_add(1);
                    s.last_internet_peer_seen = Instant::now();
                    // Immediately mark internet as available
                    if !s.internet_available {
                        tracing::info!(
                            event = "internet_restored",
                            "Internet connectivity detected via {:?} peer",
                            source
                        );
                    }
                    s.internet_available = true;
                }
            }
        });
    }

    /// Record a peer departure (disconnect). Adjusts local/internet counts.
    pub fn record_peer_departure(&self, was_local: bool) {
        self.with_state_mut(|s| {
            if was_local {
                s.local_peer_count = s.local_peer_count.saturating_sub(1);
            } else {
                s.internet_peer_count = s.internet_peer_count.saturating_sub(1);
            }
        });
    }

    /// Periodic connectivity check — called by the vitals polling tick.
    /// If no internet peers have been seen for the grace period, marks internet as unavailable.
    pub fn check_connectivity(&self) {
        self.with_state_mut(|s| {
            if s.internet_peer_count == 0
                && s.last_internet_peer_seen.elapsed() > Self::INTERNET_GRACE_PERIOD
            {
                if s.internet_available {
                    tracing::warn!(
                        event = "internet_lost",
                        local_peers = s.local_peer_count,
                        grace_elapsed_secs = s.last_internet_peer_seen.elapsed().as_secs(),
                        "No internet peers for >30s — marking offline"
                    );
                }
                s.internet_available = false;
            }
        });
    }

    /// Returns whether the node believes it has internet connectivity.
    pub fn internet_available(&self) -> bool {
        self.with_state(|s| s.internet_available)
    }

    /// Returns the count of locally-discovered (mDNS) peers.
    pub fn local_peer_count(&self) -> usize {
        self.with_state(|s| s.local_peer_count)
    }

    // --- Hardware Probing (via HardwareProbe trait) ---

    fn read_thermal(&self) -> SystemStress {
        let thresholds = self.probe.thermal_thresholds();
        match self.probe.thermal_reading() {
            Some(temp) if temp > thresholds.critical => SystemStress::Critical,
            Some(temp) if temp > thresholds.serious => SystemStress::Serious,
            Some(temp) if temp > thresholds.fair => SystemStress::Fair,
            _ => SystemStress::Nominal,
        }
    }

    fn read_battery(&self) -> SystemStress {
        match self.probe.battery_level() {
            Some(level) if level.get() < 5 => SystemStress::Critical,
            Some(level) if level.get() < 15 => SystemStress::Serious,
            Some(level) if level.get() < 50 => SystemStress::Fair,
            _ => SystemStress::Nominal, // No battery sensor → assume AC power
        }
    }

    // --- Battery gate (hard physical constraint, NOT composite_stress) ---

    /// Hard physical battery gate. A dead phone produces zero evidence.
    /// Battery is NOT a composite_stress weight — it short-circuits directly to PowerState.
    ///
    /// Charging bypasses the 20-50% gates (plugged in = no energy concern).
    fn battery_gate(&self) -> PowerState {
        if self.probe.is_background() {
            return PowerState::Dormant;
        }
        match self.probe.battery_level() {
            Some(level) if level.get() < 10 => PowerState::Leaf,
            Some(level) if level.get() < 50 && !self.probe.is_charging() => PowerState::Conserving,
            _ => PowerState::Normal, // No battery constraint (AC, charging, or >50%)
        }
    }

    /// Returns a reference to the hardware probe.
    pub fn probe(&self) -> &dyn HardwareProbe {
        &*self.probe
    }

    /// P12 FIX: Record connection pressure based on current tracked peer counts.
    /// Called from MeshSentinel on PeerDiscovered/PeerDisconnected events.
    /// Uses a default max of 64 connections (matching QUIC server default).
    const MAX_EXPECTED_CONNECTIONS: usize = 64;

    pub fn record_connection_gauge(&self) {
        let (local, internet) = self.with_state(|s| (s.local_peer_count, s.internet_peer_count));
        let total = local.saturating_add(internet);
        self.record_connection_pressure(total, Self::MAX_EXPECTED_CONNECTIONS);
    }

    // --- Adaptive Vitals Polling Interval ---

    /// Returns the vitals polling interval based on the current power state.
    /// Less restrictive states poll more frequently for faster adaptation.
    ///
    /// - Normal: 5s (fast response to load changes)
    /// - Conserving: 15s (balanced energy/responsiveness)
    /// - Leaf: 30s (minimal overhead, battery critical)
    /// - Dormant: 60s (background — battery/thermal readings only, no capture)
    pub fn vitals_polling_interval(&self) -> Duration {
        match self.current_power_state() {
            PowerState::Normal => Duration::from_secs(5),
            PowerState::Conserving => Duration::from_secs(15),
            PowerState::Leaf => Duration::from_secs(30),
            PowerState::Dormant => Duration::from_secs(60),
        }
    }
}

// =====================================================================
// THE HOMEOSTASIS IMPLEMENTATION
// =====================================================================

impl Homeostasis for SystemGovernor {
    fn record_metabolic_pressure(&self, duration: Duration) {
        let now = self.now_secs();
        self.with_state_mut(|s| s.s.record(duration.as_secs_f64(), now));
    }

    fn record_latency_pressure(&self, duration: Duration) {
        let now = self.now_secs();
        self.with_state_mut(|s| s.l.record(duration.as_secs_f64(), now));
    }

    fn record_io_pressure(&self, duration: Duration) {
        let now = self.now_secs();
        self.with_state_mut(|s| s.d.record(duration.as_secs_f64(), now));
    }

    fn record_entry_pressure(&self) {
        let now = self.now_secs();
        self.with_state_mut(|s| s.e.record(1.0, now));
    }

    /// Eclipse remediation: inject a scaled impulse into the Sybil integral.
    /// Eclipse is a topological Sybil signal — same integral, different input.
    fn record_eclipse_impulse(&self, magnitude: f64) {
        let now = self.now_secs();
        self.with_state_mut(|s| s.e.record(magnitude, now));
    }

    #[allow(clippy::arithmetic_side_effects)] // Duration addition — base + expansion, clamped by min().
    fn temporal_tolerance(&self) -> Duration {
        let now = self.now_secs();
        self.with_state(|s| {
            let base = self.config.base_temporal_drift;
            let expansion = Duration::from_secs_f64(s.l.current_value(now));
            let total = base + expansion;
            total.min(self.config.max_temporal_tolerance) // T2: Hard clamp
        })
    }

    fn ingestion_scaler(&self) -> IngestionScale {
        let now = self.now_secs();
        self.with_state(|s| {
            IngestionScale((1.0 - (s.s.current_value(now) / self.config.s_crit)).max(0.0))
        })
    }

    fn finalization_scaler(&self) -> FinalizationScale {
        let now = self.now_secs();
        self.with_state(|s| {
            FinalizationScale((1.0 - (s.d.current_value(now) / self.config.d_crit)).max(0.0))
        })
    }

    fn sybil_endowment(&self) -> SybilEndowment {
        let now = self.now_secs();
        self.with_state(|s| {
            SybilEndowment(
                self.config.psi_max
                    / (1.0 + (self.config.k_sybil * s.e.current_value(now)).powi(2)),
            )
        })
    }

    // --- Resource Pressure Recording (Volterra second-kind convolution) ---

    fn record_memory_pressure(&self, bytes_held: usize) {
        let now = self.now_secs();
        self.with_state_mut(|s| {
            let mib = bytes_held as f64 / 1_048_576.0;
            s.m.record(mib, now);
        });
    }

    fn record_storage_pressure(&self, used_bytes: u64, max_bytes: u64) {
        let now = self.now_secs();
        self.with_state_mut(|s| {
            let ratio = if max_bytes > 0 {
                used_bytes as f64 / max_bytes as f64
            } else {
                1.0
            };
            s.w.record(ratio, now);
        });
    }

    fn record_bandwidth_pressure(&self, bytes: usize) {
        let now = self.now_secs();
        self.with_state_mut(|s| {
            let mib = bytes as f64 / 1_048_576.0;
            s.b.record(mib, now);
        });
    }

    fn record_connection_pressure(&self, active: usize, max: usize) {
        let now = self.now_secs();
        self.with_state_mut(|s| {
            let ratio = if max > 0 {
                active as f64 / max as f64
            } else {
                1.0
            };
            s.c.record(ratio, now);
        });
    }

    // --- Resource Scalers (1.0 = nominal, 0.0 = saturated) ---

    fn memory_scaler(&self) -> MemoryScale {
        let now = self.now_secs();
        self.with_state(|s| {
            MemoryScale((1.0 - (s.m.current_value(now) / self.config.m_crit)).max(0.0))
        })
    }

    fn storage_scaler(&self) -> StorageScale {
        let now = self.now_secs();
        self.with_state(|s| {
            StorageScale((1.0 - (s.w.current_value(now) / self.config.w_crit)).max(0.0))
        })
    }

    fn bandwidth_scaler(&self) -> BandwidthScale {
        let now = self.now_secs();
        self.with_state(|s| {
            BandwidthScale((1.0 - (s.b.current_value(now) / self.config.b_crit)).max(0.0))
        })
    }

    fn connection_scaler(&self) -> ConnectionScale {
        let now = self.now_secs();
        self.with_state(|s| {
            ConnectionScale((1.0 - (s.c.current_value(now) / self.config.c_crit)).max(0.0))
        })
    }
}

// =====================================================================
// TESTS
// =====================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use crate::vitals::*;
    use phalanx_proto::types::{PowerState, SystemStress, TaskCost};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU64, Ordering};
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::time::Instant;

    // --- MockProbe: Configurable hardware probe for testing ---

    struct MockProbe {
        temperature: AtomicI32,
        battery: AtomicU8,
        charging: AtomicBool,
        background: AtomicBool,
        can_capture_bg: bool,
        thresholds: ThermalThresholds,
    }

    impl MockProbe {
        fn new() -> Self {
            Self {
                temperature: AtomicI32::new(30),
                battery: AtomicU8::new(100),
                charging: AtomicBool::new(true),
                background: AtomicBool::new(false),
                can_capture_bg: true,
                thresholds: ThermalThresholds::desktop(),
            }
        }

        fn set_temperature(&self, celsius: i32) {
            self.temperature.store(celsius, Ordering::Relaxed);
        }

        fn set_battery(&self, pct: u8) {
            self.battery.store(pct, Ordering::Relaxed);
        }

        fn set_charging(&self, charging: bool) {
            self.charging.store(charging, Ordering::Relaxed);
        }

        fn set_background(&self, bg: bool) {
            self.background.store(bg, Ordering::Relaxed);
        }
    }

    impl HardwareProbe for MockProbe {
        fn battery_level(&self) -> Option<BatteryLevel> {
            Some(BatteryLevel::new(self.battery.load(Ordering::Relaxed)))
        }

        fn thermal_reading(&self) -> Option<Celsius> {
            Some(Celsius(self.temperature.load(Ordering::Relaxed)))
        }

        fn is_charging(&self) -> bool {
            self.charging.load(Ordering::Relaxed)
        }

        fn is_background(&self) -> bool {
            self.background.load(Ordering::Relaxed)
        }

        fn can_capture_in_background(&self) -> bool {
            self.can_capture_bg
        }

        fn thermal_thresholds(&self) -> ThermalThresholds {
            self.thresholds
        }
    }

    fn make_governor_with_probe(probe: Arc<MockProbe>) -> SystemGovernor {
        SystemGovernor::with_probe(HomeostaticConfig::default(), probe)
    }

    fn setup_mock_sysfs(root: &std::path::Path) -> (PathBuf, PathBuf) {
        let thermal_dir = root.join("sys/class/thermal/thermal_zone0");
        let battery_dir = root.join("sys/class/power_supply/battery");

        fs::create_dir_all(&thermal_dir).unwrap();
        fs::create_dir_all(&battery_dir).unwrap();

        fs::write(thermal_dir.join("type"), "cpu-thermal\n").unwrap();
        fs::write(thermal_dir.join("temp"), "40000\n").unwrap();

        fs::write(battery_dir.join("type"), "Battery\n").unwrap();
        fs::write(battery_dir.join("capacity"), "80\n").unwrap();

        (thermal_dir.join("temp"), battery_dir.join("capacity"))
    }

    #[test]
    fn test_hardware_discovery_logic() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        let thermal_path = SysfsProbe::find_path(
            &root.join("sys/class/thermal").to_string_lossy(),
            "temp",
            &["cpu"],
        );
        let battery_path = SysfsProbe::find_path(
            &root.join("sys/class/power_supply").to_string_lossy(),
            "capacity",
            &["battery"],
        );

        assert!(thermal_path.is_none());
        assert!(battery_path.is_none());
        setup_mock_sysfs(root);

        let thermal_path = SysfsProbe::find_path(
            &root.join("sys/class/thermal").to_string_lossy(),
            "temp",
            &["cpu"],
        )
        .expect("Should find CPU thermal");

        assert!(thermal_path.to_string_lossy().contains("thermal_zone0"));

        let battery_path = SysfsProbe::find_path(
            &root.join("sys/class/power_supply").to_string_lossy(),
            "capacity",
            &["battery"],
        )
        .expect("Should find battery supply");

        assert!(battery_path.to_string_lossy().contains("battery"));
    }

    #[test]
    fn test_permission_logic_matrix() {
        let gov = SystemGovernor::new();

        assert!(gov.check_permission(TaskCost::Light));
        assert!(gov.check_permission(TaskCost::Heavy));

        if let Ok(mut state) = gov.current_state.write() {
            *state = SystemStress::Fair;
        }
        assert!(gov.check_permission(TaskCost::Light));
        assert!(!gov.check_permission(TaskCost::Heavy));

        if let Ok(mut state) = gov.current_state.write() {
            *state = SystemStress::Critical;
        }
        assert!(!gov.check_permission(TaskCost::Light));
        assert!(!gov.check_permission(TaskCost::Heavy));
    }

    #[test]
    fn test_vitals_update_calculation() {
        let probe = Arc::new(MockProbe::new());
        probe.set_temperature(30); // Nominal
        probe.set_battery(80); // Nominal

        let gov = make_governor_with_probe(probe.clone());

        gov.update_vitals();
        assert_eq!(gov.current_stress(), SystemStress::Nominal);

        // Critical temperature
        probe.set_temperature(80);
        gov.update_vitals();
        assert_eq!(gov.current_stress(), SystemStress::Critical);

        // Low temperature, low battery → battery stress wins
        probe.set_temperature(30);
        probe.set_battery(10);
        gov.update_vitals();
        assert_eq!(gov.current_stress(), SystemStress::Serious);
    }

    #[test]
    fn test_memory_scaler_decay() {
        let gov = SystemGovernor::new();

        // Record 256 MiB of memory pressure
        gov.record_memory_pressure(256 * 1024 * 1024);
        let scale1 = gov.memory_scaler();
        // 256 MiB / 512 MiB crit = 0.5 ratio → scaler ≈ 0.5
        assert!(
            scale1.0 > 0.0 && scale1.0 < 1.0,
            "Scale should be between 0 and 1, got {}",
            scale1.0
        );

        // Wait briefly and record zero pressure — integral should decay
        std::thread::sleep(Duration::from_millis(50));
        gov.record_memory_pressure(0);
        let scale2 = gov.memory_scaler();
        assert!(
            scale2.0 > scale1.0,
            "After decay with zero forcing, scaler should increase (pressure drop)"
        );
    }

    #[test]
    fn test_storage_gate_rejects_when_full() {
        let gov = SystemGovernor::new();

        // Slam storage to 100% repeatedly to overwhelm the scaler
        for _ in 0..20 {
            gov.record_storage_pressure(1_000_000, 1_000_000); // 100% ratio
        }
        let scale = gov.storage_scaler();
        assert!(
            scale.0 < 0.05,
            "Storage scaler should be near zero at 100% usage, got {}",
            scale.0
        );
    }

    #[test]
    fn test_bandwidth_scaler_responds_to_load() {
        let gov = SystemGovernor::new();

        // Record 100 MiB bandwidth pressure repeatedly
        for _ in 0..20 {
            gov.record_bandwidth_pressure(100 * 1024 * 1024);
        }
        let scale = gov.bandwidth_scaler();
        assert!(
            scale.0 < 0.1,
            "Bandwidth scaler should be near zero under heavy load, got {}",
            scale.0
        );
    }

    #[test]
    fn test_temporal_tolerance_clamped() {
        let config = HomeostaticConfig {
            max_temporal_tolerance: Duration::from_secs(5),
            ..Default::default()
        };
        let gov = SystemGovernor::with_config(config);

        // Pump up latency integral to force tolerance expansion
        for _ in 0..50 {
            gov.record_latency_pressure(Duration::from_secs(10));
        }
        let tolerance = gov.temporal_tolerance();
        assert!(
            tolerance <= Duration::from_secs(5),
            "Tolerance {} should be clamped to 5s",
            tolerance.as_secs_f64()
        );
    }

    #[test]
    fn test_composite_stress_triggers_leaf() {
        let config = HomeostaticConfig {
            s_crit: 1.0,
            d_crit: 1.0,
            m_crit: 1.0,
            w_crit: 1.0,
            b_crit: 1.0,
            ..Default::default()
        };
        let gov = SystemGovernor::with_config(config);

        // Saturate all integrals (composite uses s, d, m, w, b)
        for _ in 0..30 {
            gov.record_metabolic_pressure(Duration::from_secs(5));
            gov.record_io_pressure(Duration::from_secs(5));
            gov.record_memory_pressure(10 * 1024 * 1024);
            gov.record_storage_pressure(900, 1000);
            gov.record_bandwidth_pressure(10 * 1024 * 1024);
        }

        let composite = gov.composite_stress();
        assert!(
            composite > 0.85,
            "Composite stress should exceed 0.85, got {}",
            composite
        );

        // Three consecutive calls should trigger Leaf
        let _p1 = gov.recommended_power_state();
        let _p2 = gov.recommended_power_state();
        let p3 = gov.recommended_power_state();
        assert_eq!(
            p3,
            PowerState::Leaf,
            "Should transition to Leaf after 3 ticks above threshold"
        );
    }

    #[test]
    fn test_per_peer_bandwidth_gate() {
        let config = HomeostaticConfig {
            psi_max: 5.0, // Low ceiling for testing
            ..Default::default()
        };
        let gov = SystemGovernor::with_config(config);

        let peer = "test_peer";
        assert!(gov.is_peer_bandwidth_ok(peer), "Fresh peer should be OK");

        // Exceed the bandwidth ceiling
        for _ in 0..10 {
            gov.record_peer_bandwidth(peer);
        }
        assert!(
            !gov.is_peer_bandwidth_ok(peer),
            "Peer should be throttled after exceeding ceiling"
        );
    }

    // --- Phase 3: Internet Connectivity Detection Tests ---

    #[test]
    fn test_connectivity_default_is_online() {
        let gov = SystemGovernor::new();
        assert!(
            gov.internet_available(),
            "Fresh governor should default to internet available"
        );
        assert_eq!(gov.local_peer_count(), 0);
    }

    #[test]
    fn test_internet_peer_keeps_online() {
        use phalanx_proto::telemetry::DiscoverySource;
        let gov = SystemGovernor::new();

        // Discover a Kademlia peer — internet should stay available
        gov.record_peer_discovery(DiscoverySource::Kademlia);
        assert!(gov.internet_available());

        gov.with_state(|s| {
            assert_eq!(s.internet_peer_count, 1);
            assert_eq!(s.local_peer_count, 0);
        });
    }

    #[test]
    fn test_mdns_peer_increments_local_count() {
        use phalanx_proto::telemetry::DiscoverySource;
        let gov = SystemGovernor::new();

        gov.record_peer_discovery(DiscoverySource::Mdns);
        gov.record_peer_discovery(DiscoverySource::Mdns);
        assert_eq!(gov.local_peer_count(), 2);

        gov.with_state(|s| {
            assert_eq!(s.internet_peer_count, 0);
        });
    }

    #[test]
    fn test_connectivity_transitions_to_offline() {
        use phalanx_proto::telemetry::DiscoverySource;
        let gov = SystemGovernor::new();

        // Start with only mDNS peers, no internet peers ever seen
        gov.record_peer_discovery(DiscoverySource::Mdns);

        // Force last_internet_peer_seen to be >30s ago
        gov.with_state_mut(|s| {
            s.internet_peer_count = 0;
            s.last_internet_peer_seen = Instant::now() - Duration::from_secs(35);
        });

        // Connectivity check should detect offline
        gov.check_connectivity();
        assert!(
            !gov.internet_available(),
            "Should be offline after 30s grace with no internet peers"
        );
    }

    #[test]
    fn test_connectivity_restores_on_internet_peer() {
        use phalanx_proto::telemetry::DiscoverySource;
        let gov = SystemGovernor::new();

        // Force offline state
        gov.with_state_mut(|s| {
            s.internet_available = false;
            s.internet_peer_count = 0;
            s.last_internet_peer_seen = Instant::now() - Duration::from_secs(60);
        });
        assert!(!gov.internet_available());

        // A Bootstrap peer arrives — should immediately restore
        gov.record_peer_discovery(DiscoverySource::Bootstrap);
        assert!(
            gov.internet_available(),
            "Internet should restore immediately on non-local peer discovery"
        );
    }

    #[test]
    fn test_peer_departure_adjusts_counts() {
        use phalanx_proto::telemetry::DiscoverySource;
        let gov = SystemGovernor::new();

        gov.record_peer_discovery(DiscoverySource::Mdns);
        gov.record_peer_discovery(DiscoverySource::Mdns);
        gov.record_peer_discovery(DiscoverySource::Kademlia);

        assert_eq!(gov.local_peer_count(), 2);
        gov.with_state(|s| assert_eq!(s.internet_peer_count, 1));

        // Depart one local peer
        gov.record_peer_departure(true);
        assert_eq!(gov.local_peer_count(), 1);

        // Depart the internet peer
        gov.record_peer_departure(false);
        gov.with_state(|s| assert_eq!(s.internet_peer_count, 0));
    }

    // --- Phase 4: Mobile Energy Guardian Tests ---

    #[test]
    fn test_battery_gate_low_battery_triggers_leaf() {
        let probe = Arc::new(MockProbe::new());
        probe.set_battery(5);
        probe.set_charging(false);
        probe.set_background(false);

        let gov = make_governor_with_probe(probe);
        let state = gov.recommended_power_state();
        assert_eq!(
            state,
            PowerState::Leaf,
            "Battery <10% should trigger Leaf, got {:?}",
            state
        );
    }

    #[test]
    fn test_battery_gate_mid_battery_not_charging_triggers_conserving() {
        let probe = Arc::new(MockProbe::new());
        probe.set_battery(30);
        probe.set_charging(false);
        probe.set_background(false);

        let gov = make_governor_with_probe(probe);
        let state = gov.recommended_power_state();
        assert_eq!(
            state,
            PowerState::Conserving,
            "Battery 30% not charging should trigger Conserving, got {:?}",
            state
        );
    }

    #[test]
    fn test_battery_gate_charging_bypasses_conserving() {
        let probe = Arc::new(MockProbe::new());
        probe.set_battery(30);
        probe.set_charging(true); // Charging! Should bypass
        probe.set_background(false);

        let gov = make_governor_with_probe(probe);
        let state = gov.recommended_power_state();
        assert_eq!(
            state,
            PowerState::Normal,
            "Battery 30% while charging should remain Normal, got {:?}",
            state
        );
    }

    #[test]
    fn test_battery_gate_background_triggers_dormant() {
        let probe = Arc::new(MockProbe::new());
        probe.set_battery(100);
        probe.set_charging(true);
        probe.set_background(true); // App backgrounded

        let gov = make_governor_with_probe(probe);
        let state = gov.recommended_power_state();
        assert_eq!(
            state,
            PowerState::Dormant,
            "Background app should trigger Dormant, got {:?}",
            state
        );
    }

    #[test]
    fn test_two_stage_max_restriction_battery_vs_stress() {
        // Low battery (Conserving) + high composite stress (Leaf) → Leaf wins
        let probe = Arc::new(MockProbe::new());
        probe.set_battery(30);
        probe.set_charging(false);
        probe.set_background(false);

        let config = HomeostaticConfig {
            s_crit: 1.0,
            d_crit: 1.0,
            m_crit: 1.0,
            w_crit: 1.0,
            b_crit: 1.0,
            ..Default::default()
        };
        let gov = SystemGovernor::with_probe(config, probe);

        // Saturate all integrals to push composite above 0.85
        for _ in 0..30 {
            gov.record_metabolic_pressure(Duration::from_secs(5));
            gov.record_io_pressure(Duration::from_secs(5));
            gov.record_memory_pressure(10 * 1024 * 1024);
            gov.record_storage_pressure(900, 1000);
            gov.record_bandwidth_pressure(10 * 1024 * 1024);
        }

        // 3 ticks to trigger Leaf via stress recommendation
        let _p1 = gov.recommended_power_state();
        let _p2 = gov.recommended_power_state();
        let p3 = gov.recommended_power_state();

        // Battery gate says Conserving, stress says Leaf → max = Leaf
        assert_eq!(
            p3,
            PowerState::Leaf,
            "Max restriction should be Leaf (stress beats battery's Conserving), got {:?}",
            p3
        );
    }

    #[test]
    fn test_two_stage_battery_wins_over_normal_stress() {
        // Battery at 5% → Leaf gate. Stress is nominal → Normal.
        // Max(Leaf, Normal) = Leaf.
        let probe = Arc::new(MockProbe::new());
        probe.set_battery(5);
        probe.set_charging(false);
        probe.set_background(false);

        let gov = make_governor_with_probe(probe);
        // No stress applied → composite is near 0.0 → stress_recommendation returns Normal
        let state = gov.recommended_power_state();
        assert_eq!(
            state,
            PowerState::Leaf,
            "Battery gate (Leaf) should override stress (Normal), got {:?}",
            state
        );
    }

    #[test]
    fn test_simulated_battery_drain_transitions() {
        // Simulate 100% → 5%: verify Normal → Conserving → Leaf transitions
        let probe = Arc::new(MockProbe::new());
        probe.set_charging(false);
        probe.set_background(false);

        // 100% → Normal
        probe.set_battery(100);
        let gov = make_governor_with_probe(probe.clone());
        assert_eq!(gov.recommended_power_state(), PowerState::Normal);

        // 45% → Conserving (below 50, not charging)
        probe.set_battery(45);
        assert_eq!(gov.recommended_power_state(), PowerState::Conserving);

        // 8% → Leaf (below 10)
        probe.set_battery(8);
        assert_eq!(gov.recommended_power_state(), PowerState::Leaf);
    }

    #[test]
    fn test_battery_level_clamping() {
        // BatteryLevel should clamp to 100
        let level = BatteryLevel::new(255);
        assert_eq!(level.get(), 100);

        let level = BatteryLevel::new(0);
        assert_eq!(level.get(), 0);
    }

    #[test]
    fn test_thermal_thresholds_platform_variants() {
        let desktop = ThermalThresholds::desktop();
        let mobile = ThermalThresholds::mobile();

        // Mobile thresholds should be lower than desktop (tighter thermal envelope)
        assert!(mobile.fair.0 < desktop.fair.0);
        assert!(mobile.serious.0 < desktop.serious.0);
        assert!(mobile.critical.0 < desktop.critical.0);
    }

    #[test]
    fn test_hardware_probe_thermal_reading_drives_stress() {
        let probe = Arc::new(MockProbe::new());
        let gov = make_governor_with_probe(probe.clone());

        // Nominal temperature
        probe.set_temperature(30);
        gov.update_vitals();
        assert_eq!(gov.current_stress(), SystemStress::Nominal);

        // Fair threshold (desktop default = 45°C)
        probe.set_temperature(50);
        gov.update_vitals();
        assert_eq!(gov.current_stress(), SystemStress::Fair);

        // Serious threshold (desktop default = 60°C)
        probe.set_temperature(65);
        gov.update_vitals();
        assert_eq!(gov.current_stress(), SystemStress::Serious);

        // Critical threshold (desktop default = 75°C)
        probe.set_temperature(80);
        gov.update_vitals();
        assert_eq!(gov.current_stress(), SystemStress::Critical);
    }

    #[test]
    fn test_dormant_with_can_capture_background() {
        // Mock probe that reports can_capture_in_background = true (Android-like)
        let probe = Arc::new(MockProbe::new());
        probe.set_background(true);

        let gov = make_governor_with_probe(probe.clone());
        let state = gov.recommended_power_state();
        assert_eq!(state, PowerState::Dormant);
        // Verify the probe correctly reports capability
        assert!(gov.probe().can_capture_in_background());
    }

    // --- Phase 4c: Adaptive Vitals Polling Tests ---

    #[test]
    fn test_vitals_polling_interval_normal() {
        let probe = Arc::new(MockProbe::new());
        probe.set_battery(100);
        probe.set_charging(true);
        probe.set_background(false);

        let gov = make_governor_with_probe(probe);
        // Fresh governor defaults to Normal power state
        assert_eq!(
            gov.vitals_polling_interval(),
            Duration::from_secs(5),
            "Normal should poll every 5s"
        );
    }

    #[test]
    fn test_vitals_polling_interval_adapts_to_power_state() {
        let probe = Arc::new(MockProbe::new());
        probe.set_charging(false);
        probe.set_background(false);

        let gov = make_governor_with_probe(probe.clone());

        // Force Conserving via battery gate (30%, not charging)
        probe.set_battery(30);
        gov.update_vitals();
        assert_eq!(
            gov.vitals_polling_interval(),
            Duration::from_secs(15),
            "Conserving should poll every 15s"
        );

        // Force Leaf via battery gate (<10%)
        probe.set_battery(5);
        gov.update_vitals();
        assert_eq!(
            gov.vitals_polling_interval(),
            Duration::from_secs(30),
            "Leaf should poll every 30s"
        );

        // Force Dormant via background
        probe.set_background(true);
        gov.update_vitals();
        assert_eq!(
            gov.vitals_polling_interval(),
            Duration::from_secs(60),
            "Dormant should poll every 60s"
        );
    }

    #[test]
    fn test_lifecycle_event_triggers_immediate_vitals_update() {
        // Verify that update_vitals() after a lifecycle event changes power state
        let probe = Arc::new(MockProbe::new());
        probe.set_battery(100);
        probe.set_charging(true);
        probe.set_background(true); // Start backgrounded → Dormant

        let gov = make_governor_with_probe(probe.clone());
        gov.update_vitals();
        assert_eq!(gov.current_power_state(), PowerState::Dormant);

        // Simulate foregrounding (in real app, the lifecycle_rx channel would fire)
        probe.set_background(false);
        gov.update_vitals(); // Immediate recalculation
        assert_eq!(
            gov.current_power_state(),
            PowerState::Normal,
            "Should transition to Normal immediately after foregrounding"
        );
    }

    // --- Volterra Decoupling Regression Test ---

    #[test]
    fn test_integrals_are_decoupled() {
        let gov = SystemGovernor::new();

        // Record bandwidth pressure rapidly (simulates high-traffic burst).
        // Before the fix, this would reset the shared last_sys_tick on every call,
        // suppressing decay in all other integrals.
        for _ in 0..100 {
            gov.record_bandwidth_pressure(64 * 1024);
        }

        // Record a single small memory impulse (1 MiB out of 512 MiB crit)
        gov.record_memory_pressure(1_048_576);

        // Memory scaler should reflect only 1 MiB / 512 MiB ≈ 0.002 pressure.
        // Before decoupling, bandwidth's rapid clock resets would suppress memory
        // decay, inflating the integral ~10x.
        let mem = gov.memory_scaler();
        assert!(
            mem.0 > 0.99,
            "Memory scaler should be near 1.0 (1/512 MiB), got {}. \
             If this fails, integrals may still be coupled via a shared clock.",
            mem.0
        );
    }

    // --- IoCounter → Volterra Integral Wiring Tests ---

    #[test]
    fn test_io_bandwidth_delta_feeds_b_integral() {
        let bytes_sent = Arc::new(AtomicU64::new(0));
        let bytes_received = Arc::new(AtomicU64::new(0));
        let io_ops = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicU64::new(0));

        let gov = SystemGovernor::new().with_io_counters(
            bytes_sent.clone(),
            bytes_received.clone(),
            io_ops.clone(),
            dropped.clone(),
        );

        // Simulate 10 MiB of wire traffic
        bytes_sent.fetch_add(5 * 1024 * 1024, Ordering::Relaxed);
        bytes_received.fetch_add(5 * 1024 * 1024, Ordering::Relaxed);

        gov.update_vitals();

        let now = gov.now_secs();
        let b_value = gov.with_state(|s| s.b.current_value(now));
        assert!(
            b_value > 0.0,
            "Bandwidth integral should reflect wire bytes, got {}",
            b_value
        );

        // Second tick with no new traffic → delta = 0, no additional pressure
        let now = gov.now_secs();
        let b_before = gov.with_state(|s| s.b.current_value(now));
        gov.update_vitals();
        let now = gov.now_secs();
        let b_after = gov.with_state(|s| s.b.current_value(now));
        assert!(
            b_after <= b_before,
            "Bandwidth integral should not increase without new traffic (before={}, after={})",
            b_before,
            b_after
        );
    }

    #[test]
    fn test_io_counters_first_tick_seeding() {
        // Simulate counters that already have connection setup traffic
        let bytes_sent = Arc::new(AtomicU64::new(5000));
        let bytes_received = Arc::new(AtomicU64::new(5000));
        let io_ops = Arc::new(AtomicU64::new(100));
        let dropped = Arc::new(AtomicU64::new(5));

        let gov = SystemGovernor::new().with_io_counters(
            bytes_sent.clone(),
            bytes_received.clone(),
            io_ops.clone(),
            dropped.clone(),
        );

        // First tick: last-values were seeded, so delta should be 0
        gov.update_vitals();

        let now = gov.now_secs();
        let b_value = gov.with_state(|s| s.b.current_value(now));
        assert!(
            b_value < 0.001,
            "First tick should see zero bandwidth delta (seeded), got {}",
            b_value
        );
    }

    #[test]
    fn test_drop_ratio_feeds_connection_integral() {
        let bytes_sent = Arc::new(AtomicU64::new(0));
        let bytes_received = Arc::new(AtomicU64::new(0));
        let io_ops = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicU64::new(0));

        let gov = SystemGovernor::new().with_io_counters(
            bytes_sent.clone(),
            bytes_received.clone(),
            io_ops.clone(),
            dropped.clone(),
        );

        // Simulate 1000 ops with 500 drops → 50% drop ratio
        io_ops.fetch_add(1000, Ordering::Relaxed);
        dropped.fetch_add(500, Ordering::Relaxed);

        gov.update_vitals();

        let now = gov.now_secs();
        let c_value = gov.with_state(|s| s.c.current_value(now));
        assert!(
            c_value > 0.0,
            "Connection integral should reflect drop ratio, got {}",
            c_value
        );

        // No drops with ops → no connection pressure
        let now = gov.now_secs();
        let c_before = gov.with_state(|s| s.c.current_value(now));
        io_ops.fetch_add(1000, Ordering::Relaxed);
        gov.update_vitals();
        let now = gov.now_secs();
        let c_after = gov.with_state(|s| s.c.current_value(now));
        assert!(
            c_after <= c_before,
            "Connection integral should not increase without drops (before={}, after={})",
            c_before,
            c_after
        );
    }

    // ---------------- Heartbeat accessor tests ----------------

    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        clippy::float_cmp
    )]
    mod heartbeat_accessor_tests {
        use super::*;

        #[test]
        fn load_factor_clamps_composite_stress_into_unit_interval() {
            let gov = SystemGovernor::new();
            // Slam memory to a multiple of m_crit so composite_stress saturates
            // at or above 1.0; load_factor must clamp to 1.0.
            let m_crit_bytes = (gov.config.m_crit * 1024.0 * 1024.0) as usize;
            for _ in 0..50 {
                gov.record_memory_pressure(m_crit_bytes * 4);
            }
            let load = gov.load_factor();
            assert!(
                (0.0..=1.0).contains(&load.as_f32()),
                "load_factor must be clamped to [0, 1], got {}",
                load.as_f32()
            );

            // A fresh governor with no pressure should report near zero.
            let fresh = SystemGovernor::new();
            let zero = fresh.load_factor();
            assert!(
                zero.as_f32() < 0.5,
                "fresh governor's load_factor should be well below 0.5, got {}",
                zero.as_f32()
            );
        }

        #[test]
        fn is_leaf_state_tracks_current_power_state() {
            let gov = SystemGovernor::new();
            // Default fresh state is Normal — not leaf, not dormant.
            assert_eq!(gov.current_power_state(), PowerState::Normal);
            assert!(
                !gov.is_leaf_state(),
                "Normal power state must not register as leaf"
            );

            // Forge the recommended state to Leaf via direct write.
            *gov.recommended_state.write().unwrap() = PowerState::Leaf;
            assert!(
                gov.is_leaf_state(),
                "PowerState::Leaf must register as leaf"
            );

            // Dormant is also leaf-equivalent for advertised-capacity purposes.
            *gov.recommended_state.write().unwrap() = PowerState::Dormant;
            assert!(
                gov.is_leaf_state(),
                "PowerState::Dormant must register as leaf for capacity advertisement"
            );
        }

        #[test]
        fn integral_summary_returns_eight_clamped_values_in_locked_order() {
            let gov = SystemGovernor::new();
            let summary = gov.integral_summary();
            let arr = summary.as_array();

            // Every value must be a clamped, finite f32 in [0, 1].
            for (i, v) in arr.iter().enumerate() {
                assert!(v.is_finite(), "integral[{}] must be finite, got {}", i, v);
                assert!(
                    (0.0..=1.0).contains(v),
                    "integral[{}] must be in [0, 1], got {}",
                    i,
                    v
                );
            }

            // Named accessors must agree with array indices — locks the wire
            // order at the type level. Bit-equality is the right test here:
            // both sides come from the same `[f32; 8]` slot, so they're not
            // just close but identical.
            assert_eq!(summary.s().to_bits(), arr[0].to_bits());
            assert_eq!(summary.d().to_bits(), arr[1].to_bits());
            assert_eq!(summary.e().to_bits(), arr[2].to_bits());
            assert_eq!(summary.l().to_bits(), arr[3].to_bits());
            assert_eq!(summary.m().to_bits(), arr[4].to_bits());
            assert_eq!(summary.w().to_bits(), arr[5].to_bits());
            assert_eq!(summary.b().to_bits(), arr[6].to_bits());
            assert_eq!(summary.c().to_bits(), arr[7].to_bits());

            // Memory pressure must show up as the m-slot increasing.
            let m_crit_bytes = (gov.config.m_crit * 1024.0 * 1024.0) as usize;
            gov.record_memory_pressure(m_crit_bytes * 2);
            let after = gov.integral_summary();
            assert!(
                after.m() > summary.m(),
                "memory pressure must lift the m integral (before={}, after={})",
                summary.m(),
                after.m()
            );
        }
    }
}
