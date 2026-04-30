// crates/phalanx-node/src/vitals/spectral.rs
//
// Shield Wall: Spectral behavioral detection for Byzantine peer identification.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;
use tokio::time::Instant;

use phalanx_proto::identity::MeshAddress;
use phalanx_proto::vitals::ControlMessage;

/// Per-peer behavioral observation state for spectral consistency detection.
pub struct PeerObservation {
    /// Ring buffer of recent heartbeat arrival times.
    heartbeat_times: VecDeque<Instant>,
    /// Data volume received from this peer in current window (bytes).
    data_volume_bytes: u64,
    /// Observation window start.
    window_start: Instant,
    /// Last claimed load factor from ControlMessage.
    claimed_load: f32,
    /// Last claimed leaf state from ControlMessage.
    claimed_is_leaf: bool,
    /// Last claimed integral summary (Tier 2, if available).
    pub claimed_integrals: Option<[f32; 8]>,
}

impl PeerObservation {
    fn new() -> Self {
        Self {
            heartbeat_times: VecDeque::new(),
            data_volume_bytes: 0,
            window_start: Instant::now(),
            claimed_load: 0.0,
            claimed_is_leaf: false,
            claimed_integrals: None,
        }
    }
}

/// Spectral behavioral observer.
///
/// Tracks per-peer behavioral observations and evaluates dynamical
/// consistency against claimed state.  The residual signal drives the
/// existing Volterra reputation integral toward decoupling for
/// inconsistent peers.
pub struct SpectralObserver {
    peers: HashMap<MeshAddress, PeerObservation>,
    /// Minimum heartbeats before evaluation begins.
    pub min_observations: usize,
    /// Maximum heartbeat timestamps retained per peer.
    max_history: usize,
    /// Observation window for data volume measurement.
    window_duration: Duration,
    /// Residual above this value triggers anomaly impulse.
    pub anomaly_threshold: f64,
}

impl SpectralObserver {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            min_observations: 3,
            max_history: 10,
            window_duration: Duration::from_secs(60),
            anomaly_threshold: 0.3,
        }
    }

    /// Record a heartbeat arrival and update the peer's claimed state.
    pub fn record_heartbeat(&mut self, peer_id: MeshAddress, msg: &ControlMessage) {
        let obs = self
            .peers
            .entry(peer_id)
            .or_insert_with(PeerObservation::new);

        obs.heartbeat_times.push_back(Instant::now());
        if obs.heartbeat_times.len() > self.max_history {
            obs.heartbeat_times.pop_front();
        }

        obs.claimed_load = msg.load_factor;
        obs.claimed_is_leaf = msg.is_leaf;
        obs.claimed_integrals = msg.integral_summary;

        // Reset data volume window if expired
        if obs.window_start.elapsed() > self.window_duration {
            obs.data_volume_bytes = 0;
            obs.window_start = Instant::now();
        }
    }

    /// Record data volume received from a peer (called on every data message).
    #[allow(clippy::arithmetic_side_effects)] // Counter increment — overflow not reachable in practice.
    pub fn record_data_received(&mut self, peer_id: MeshAddress, bytes: usize) {
        let obs = self
            .peers
            .entry(peer_id)
            .or_insert_with(PeerObservation::new);
        obs.data_volume_bytes += bytes as u64;
    }

    /// Evaluate spectral consistency for a peer.
    ///
    /// Returns `Some(residual)` if enough observations have accumulated,
    /// `None` if insufficient data for evaluation.  The residual is a
    /// non-negative scalar: 0.0 = perfectly consistent, higher = more
    /// anomalous.
    pub fn evaluate(&self, peer_id: &MeshAddress) -> Option<f64> {
        let obs = self.peers.get(peer_id)?;
        if obs.heartbeat_times.len() < self.min_observations {
            return None;
        }
        Some(Self::compute_residual(obs))
    }

    /// Remove observation state for a disconnected peer.
    pub fn remove_peer(&mut self, peer_id: &MeshAddress) {
        self.peers.remove(peer_id);
    }

    /// Compute the spectral residual from three independent consistency checks.
    ///
    /// Check 1: Load-throughput consistency.
    ///   A peer claiming high load should not be flooding us with data.
    ///
    /// Check 2: Heartbeat regularity.
    ///   Genuine nodes have load-proportional jitter in heartbeat timing.
    ///   Suspiciously precise timing under high claimed load → simulated.
    ///
    /// Check 3: Leaf state contradiction.
    ///   A peer claiming leaf mode should not be sending data traffic.
    fn compute_residual(obs: &PeerObservation) -> f64 {
        let mut error_sq = 0.0_f64;

        // Check 1: Load-throughput consistency
        // Predicted: a node at load X should emit data at rate proportional to (1-X).
        // Observed: data volume over window duration.
        let window_secs = obs.window_start.elapsed().as_secs_f64().max(1.0);
        let observed_rate = obs.data_volume_bytes as f64 / window_secs;
        // Normalize: consider > 100 KB/s as "full throughput" (rate = 1.0)
        let observed_norm = (observed_rate / 100_000.0).min(1.0);
        let predicted_max_rate = (1.0 - obs.claimed_load as f64).max(0.0);
        // Anomaly: observed rate significantly exceeds what claimed load allows
        let throughput_error = (observed_norm - predicted_max_rate).max(0.0);
        error_sq += throughput_error * throughput_error;

        // Check 2: Heartbeat regularity
        if obs.heartbeat_times.len() >= 3 {
            let intervals: Vec<f64> = obs
                .heartbeat_times
                .iter()
                .zip(obs.heartbeat_times.iter().skip(1))
                .map(|(a, b)| b.duration_since(*a).as_secs_f64())
                .collect();

            let n = intervals.len() as f64;
            let mean = intervals.iter().sum::<f64>() / n;
            let variance = intervals.iter().map(|i| (i - mean).powi(2)).sum::<f64>() / n;
            let cv = if mean > 1e-6 {
                variance.sqrt() / mean
            } else {
                0.0
            };

            // Under high load, expect higher jitter (CV).  Under low load, low CV is fine.
            // Suspiciously regular timing under high claimed load → simulated node.
            let expected_min_cv = obs.claimed_load as f64 * 0.05;
            if cv < expected_min_cv * 0.5 && obs.claimed_load > 0.3 {
                let jitter_error = expected_min_cv - cv;
                error_sq += jitter_error * jitter_error;
            }
        }

        // Check 3: Leaf state contradiction
        // A leaf node should not be sending data on video/audio topics.
        if obs.claimed_is_leaf && obs.data_volume_bytes > 10_000 {
            error_sq += 1.0;
        }

        error_sq.sqrt()
    }
}

impl Default for SpectralObserver {
    fn default() -> Self {
        Self::new()
    }
}

// =====================================================================
// Shield Wall: SpectralObserver unit tests
// =====================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod shield_wall_tests {
    use super::*;

    /// Helper: build a ControlMessage with specified load/leaf/integrals.
    fn make_control(load: f32, is_leaf: bool) -> ControlMessage {
        ControlMessage {
            sender: MeshAddress("peer-1".to_string()),
            load_factor: load,
            storage_remaining_mb: 1000,
            heartbeat_ms: 5000,
            is_leaf,
            integral_summary: None,
        }
    }

    #[test]
    fn test_spectral_observer_records_heartbeat() {
        let mut observer = SpectralObserver::new();
        let peer = MeshAddress("peer-1".to_string());
        let msg = make_control(0.5, false);

        observer.record_heartbeat(peer.clone(), &msg);

        let obs = observer.peers.get(&peer).expect("Peer should exist");
        assert_eq!(obs.heartbeat_times.len(), 1);
        assert!((obs.claimed_load - 0.5).abs() < f32::EPSILON);
        assert!(!obs.claimed_is_leaf);
    }

    #[test]
    fn test_insufficient_data_returns_none() {
        let mut observer = SpectralObserver::new();
        let peer = MeshAddress("peer-1".to_string());
        let msg = make_control(0.1, false);

        // Record fewer heartbeats than min_observations (default: 3)
        observer.record_heartbeat(peer.clone(), &msg);
        observer.record_heartbeat(peer.clone(), &msg);

        assert!(
            observer.evaluate(&peer).is_none(),
            "Should return None with fewer than min_observations heartbeats"
        );
    }

    #[test]
    fn test_spectral_residual_zero_for_consistent_peer() {
        let mut observer = SpectralObserver::new();
        let peer = MeshAddress("peer-consistent".to_string());

        // Low load, no data sent, not a leaf — perfectly consistent
        let msg = make_control(0.1, false);
        for _ in 0..5 {
            observer.record_heartbeat(peer.clone(), &msg);
        }
        // No data volume recorded → observed rate = 0, predicted max rate = 0.9
        // error₁ = max(0, 0 - 0.9)² = 0 (clamped at zero because observed < predicted)
        // error₂ ≈ 0 (low load, low CV is acceptable)
        // error₃ = 0 (not leaf)

        let residual = observer.evaluate(&peer).expect("Should have enough data");
        assert!(
            residual < 0.01,
            "Consistent peer residual should be near zero, got {}",
            residual
        );
    }

    #[test]
    fn test_spectral_residual_high_for_inconsistent_peer() {
        let mut observer = SpectralObserver::new();
        let peer = MeshAddress("peer-liar".to_string());

        // Peer claims high load (0.95) but sends lots of data
        let msg = make_control(0.95, false);
        for _ in 0..5 {
            observer.record_heartbeat(peer.clone(), &msg);
        }
        // Flood with data: 5 MB in the window → high throughput
        observer.record_data_received(peer.clone(), 5_000_000);

        let residual = observer.evaluate(&peer).expect("Should have enough data");
        assert!(
            residual > observer.anomaly_threshold,
            "Inconsistent peer (high claimed load, high data volume) should trigger anomaly. \
             Residual: {}, threshold: {}",
            residual,
            observer.anomaly_threshold
        );
    }

    #[test]
    fn test_leaf_contradiction_detected() {
        let mut observer = SpectralObserver::new();
        let peer = MeshAddress("peer-fake-leaf".to_string());

        // Peer claims to be a leaf but sends significant data
        let msg = make_control(0.0, true);
        for _ in 0..5 {
            observer.record_heartbeat(peer.clone(), &msg);
        }
        // Send > 10KB of data (threshold for leaf contradiction)
        observer.record_data_received(peer.clone(), 50_000);

        let residual = observer.evaluate(&peer).expect("Should have enough data");
        // Leaf contradiction adds 1.0 to error_sq → residual >= 1.0
        assert!(
            residual >= 1.0,
            "Leaf node sending data should produce residual >= 1.0, got {}",
            residual
        );
    }

    #[test]
    fn test_remove_peer_cleans_state() {
        let mut observer = SpectralObserver::new();
        let peer = MeshAddress("peer-temp".to_string());
        let msg = make_control(0.1, false);

        observer.record_heartbeat(peer.clone(), &msg);
        assert!(observer.peers.contains_key(&peer));

        observer.remove_peer(&peer);
        assert!(!observer.peers.contains_key(&peer));
        assert!(observer.evaluate(&peer).is_none());
    }

    #[test]
    fn test_heartbeat_history_bounded() {
        let mut observer = SpectralObserver::new();
        let peer = MeshAddress("peer-chatty".to_string());
        let msg = make_control(0.1, false);

        // Record more heartbeats than max_history (default: 10)
        for _ in 0..20 {
            observer.record_heartbeat(peer.clone(), &msg);
        }

        let obs = observer.peers.get(&peer).unwrap();
        assert_eq!(
            obs.heartbeat_times.len(),
            observer.max_history,
            "Heartbeat history should be bounded to max_history"
        );
    }

    #[test]
    fn test_data_volume_accumulates() {
        let mut observer = SpectralObserver::new();
        let peer = MeshAddress("peer-sender".to_string());

        observer.record_data_received(peer.clone(), 1000);
        observer.record_data_received(peer.clone(), 2000);
        observer.record_data_received(peer.clone(), 3000);

        let obs = observer.peers.get(&peer).unwrap();
        assert_eq!(obs.data_volume_bytes, 6000);
    }
}
