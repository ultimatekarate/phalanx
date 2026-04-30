use phalanx_proto::prelude::*;
use phalanx_proto::trust::Offense;

/// The Verb "To Assess": Maps an Offense to its penalty magnitude.
pub fn assess_penalty(offense: &Offense) -> i64 {
    match offense {
        Offense::QuotaExceeded => 25,
        Offense::InvalidSignature | Offense::IdentityTheft => 101,
        Offense::EclipseAttempt | Offense::DualPresence => 50,
        Offense::SpectralAnomaly | Offense::NonReciprocal => 15,
        _ => 10,
    }
}

/// Boundary: Allows any component to verify peer standing.
pub trait ReputationGate {
    fn is_blacklisted(&self, did: &Did) -> bool;
}

/// Boundary: Used by Kademlia to rank peers during routing.
pub trait PeerEvaluator: Send + Sync {
    fn evaluate_reputation(&self, peer_id: &MeshAddress) -> f32;
}

// ── Reciprocity Floor ──────────────────────────────────────────────────

/// Configuration for the reciprocity evaluator.
#[derive(Debug, Clone)]
pub struct ReciprocityParams {
    /// Grace period before evaluating new peers (seconds).
    pub grace_period_secs: u64,
    /// Base contribution floor. Divided by mesh peer count to get per-peer floor.
    pub floor_base: f64,
}

impl Default for ReciprocityParams {
    fn default() -> Self {
        Self {
            grace_period_secs: 600,
            floor_base: 3.0,
        }
    }
}

/// Snapshot of a single peer's contribution state.
#[derive(Debug, Clone)]
pub struct PeerContribution {
    /// How long this peer has been connected (seconds).
    pub connected_secs: u64,
    /// Current value of the peer's contribution integral.
    pub contribution_integral: f64,
    /// Whether this peer is on a local mesh (BLE) transport.
    pub is_local_mesh: bool,
}

/// Result of evaluating a peer's reciprocity.
#[derive(Debug, Clone, PartialEq)]
pub enum ReciprocityVerdict {
    /// Peer is within the grace period — too early to judge.
    GracePeriod,
    /// Peer is contributing adequately.
    Reciprocal,
    /// Peer is below the reciprocity floor. Deficit is 0.0–1.0
    /// (0.0 = just below floor, 1.0 = zero contribution).
    NonReciprocal { deficit: f64 },
}

/// The Verb "To Evaluate": Pure function that determines whether a peer
/// meets the reciprocity floor.
#[allow(clippy::arithmetic_side_effects)] // Floor division and deficit clamping — all values bounded.
pub fn evaluate_reciprocity(
    peer: &PeerContribution,
    params: &ReciprocityParams,
    mesh_peer_count: usize,
) -> ReciprocityVerdict {
    if peer.connected_secs < params.grace_period_secs {
        return ReciprocityVerdict::GracePeriod;
    }

    // Floor scales inversely with mesh size. Clamp denominator to ≥2
    // to avoid division issues in tiny meshes.
    let denominator = mesh_peer_count.max(2) as f64;
    let mut floor = params.floor_base / denominator;

    // LocalMesh (BLE) peers get 50% leniency — lower throughput expected.
    if peer.is_local_mesh {
        floor *= 0.5;
    }

    if peer.contribution_integral >= floor {
        ReciprocityVerdict::Reciprocal
    } else {
        // Deficit: 0.0 (just below floor) to 1.0 (zero contribution).
        let deficit = if floor > 0.0 {
            1.0 - (peer.contribution_integral / floor)
        } else {
            0.0
        };
        ReciprocityVerdict::NonReciprocal {
            deficit: deficit.clamp(0.0, 1.0),
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    fn default_params() -> ReciprocityParams {
        ReciprocityParams::default()
    }

    /// Peer under the grace period always gets GracePeriod regardless of contribution.
    #[test]
    fn reciprocity_grace_period() {
        let peer = PeerContribution {
            connected_secs: 300, // 5 min < 600s grace
            contribution_integral: 0.0,
            is_local_mesh: false,
        };
        assert_eq!(
            evaluate_reciprocity(&peer, &default_params(), 3),
            ReciprocityVerdict::GracePeriod
        );
    }

    /// Peer with adequate contribution passes the floor.
    #[test]
    fn reciprocity_healthy_peer() {
        // Floor = 3.0 / max(3, 2) = 1.0. Integral 2.0 > 1.0.
        let peer = PeerContribution {
            connected_secs: 900,
            contribution_integral: 2.0,
            is_local_mesh: false,
        };
        assert_eq!(
            evaluate_reciprocity(&peer, &default_params(), 3),
            ReciprocityVerdict::Reciprocal
        );
    }

    /// Zero contribution at 15 minutes → NonReciprocal with deficit 1.0.
    #[test]
    fn reciprocity_black_hole() {
        let peer = PeerContribution {
            connected_secs: 900, // 15 min > grace
            contribution_integral: 0.0,
            is_local_mesh: false,
        };
        assert_eq!(
            evaluate_reciprocity(&peer, &default_params(), 3),
            ReciprocityVerdict::NonReciprocal { deficit: 1.0 }
        );
    }

    /// Peer just below the floor → small deficit.
    #[test]
    fn reciprocity_partial_contributor() {
        // Floor = 3.0 / 3 = 1.0. Integral 0.8 → deficit = 1.0 - 0.8/1.0 = 0.2
        let peer = PeerContribution {
            connected_secs: 900,
            contribution_integral: 0.8,
            is_local_mesh: false,
        };
        match evaluate_reciprocity(&peer, &default_params(), 3) {
            ReciprocityVerdict::NonReciprocal { deficit } => {
                assert!(
                    (deficit - 0.2).abs() < 0.01,
                    "deficit should be ~0.2, got {deficit}"
                );
            }
            other => panic!("Expected NonReciprocal, got {other:?}"),
        }
    }

    /// Floor inversely proportional to mesh peer count.
    #[test]
    fn reciprocity_scales_with_mesh_size() {
        // 3 peers: floor = 3.0/3 = 1.0
        // 10 peers: floor = 3.0/10 = 0.3
        let peer = PeerContribution {
            connected_secs: 900,
            contribution_integral: 0.5,
            is_local_mesh: false,
        };
        // Fails at 3 peers (0.5 < 1.0) but passes at 10 (0.5 > 0.3).
        assert!(matches!(
            evaluate_reciprocity(&peer, &default_params(), 3),
            ReciprocityVerdict::NonReciprocal { .. }
        ));
        assert_eq!(
            evaluate_reciprocity(&peer, &default_params(), 10),
            ReciprocityVerdict::Reciprocal
        );
    }

    /// LocalMesh (BLE) peers get 50% leniency on the floor.
    #[test]
    fn reciprocity_local_mesh_leniency() {
        // 3 peers: floor = 3.0/3 = 1.0, with leniency: 0.5
        let peer = PeerContribution {
            connected_secs: 900,
            contribution_integral: 0.6,
            is_local_mesh: true,
        };
        // 0.6 > 0.5 (LocalMesh floor) → passes
        assert_eq!(
            evaluate_reciprocity(&peer, &default_params(), 3),
            ReciprocityVerdict::Reciprocal
        );
        // Same contribution on Internet → 0.6 < 1.0 → fails
        let internet_peer = PeerContribution {
            is_local_mesh: false,
            ..peer
        };
        assert!(matches!(
            evaluate_reciprocity(&internet_peer, &default_params(), 3),
            ReciprocityVerdict::NonReciprocal { .. }
        ));
    }

    /// mesh_count=1 is clamped to 2 to prevent division weirdness.
    #[test]
    fn reciprocity_minimum_mesh_size_clamp() {
        // mesh_count=1 → clamped to 2 → floor = 3.0/2 = 1.5
        let peer = PeerContribution {
            connected_secs: 900,
            contribution_integral: 0.0,
            is_local_mesh: false,
        };
        match evaluate_reciprocity(&peer, &default_params(), 1) {
            ReciprocityVerdict::NonReciprocal { deficit } => {
                assert!(
                    (deficit - 1.0).abs() < 0.01,
                    "deficit should be 1.0 at zero contrib"
                );
            }
            other => panic!("Expected NonReciprocal, got {other:?}"),
        }
    }

    /// NonReciprocal offense carries 15-point penalty (same as SpectralAnomaly).
    #[test]
    fn non_reciprocal_penalty_is_15() {
        assert_eq!(assess_penalty(&Offense::NonReciprocal), 15);
    }
}
