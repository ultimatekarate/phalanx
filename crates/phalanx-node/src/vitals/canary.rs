// crates/phalanx-node/src/vitals/canary.rs
//
// Silent Canary: community-scoped dead man's switch.
//
// Monitors mesh presence of community peers during active recordings.
// "Going dark" = mesh disconnection + heartbeat staleness, NOT shard flow
// cessation. A peer who stops recording but stays connected is alive.
//
// All state is ephemeral (memory-only, never persisted). If the phone is
// seized, disk must not contain a MeshAddress -> Did roster.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use phalanx_proto::identity::{Did, MeshAddress, RecordingId};

/// Monitors community peers during active recordings. Fires when a peer's
/// mesh presence disappears (disconnect + heartbeat staleness confirmed).
pub struct CanaryMonitor {
    /// Community peers contributing to the current event.
    watched: HashMap<MeshAddress, WatchedPeer>,
    /// How many consecutive staleness checks before confirming silence.
    confirmation_required: u32,
    /// Per-peer consecutive stale count (incremented on stale tick, reset on reconnect).
    stale_counts: HashMap<MeshAddress, u32>,
    /// Peers whose disconnect has been observed but not yet confirmed stale.
    pending_confirmation: HashSet<MeshAddress>,
}

struct WatchedPeer {
    #[allow(dead_code)] // Stored for future use (e.g., per-peer identity in alerts).
    did: Did,
    #[allow(dead_code)]
    last_contribution: Instant,
    /// Recording IDs this peer contributed to (for re-replication targeting).
    recordings: HashSet<RecordingId>,
}

/// Canary state after evaluating the watched set.
#[derive(Debug, Clone)]
pub enum CanaryState {
    /// No watched peers are silent.
    Normal,
    /// One or more community peers confirmed silent.
    Alert {
        /// NetworkIds of peers confirmed dark.
        silent_peers: Vec<MeshAddress>,
        /// Recording IDs those peers were contributing to.
        recordings_at_risk: HashSet<RecordingId>,
        /// How many watched community peers are still alive.
        peers_remaining: usize,
    },
}

impl CanaryMonitor {
    /// Create a new canary monitor.
    ///
    /// `confirmation_required`: how many consecutive stale ticks before a
    /// disconnected peer is confirmed silent. 1 = confirm on first stale check.
    #[must_use]
    pub fn new(confirmation_required: u32) -> Self {
        Self {
            watched: HashMap::new(),
            confirmation_required: confirmation_required.max(1),
            stale_counts: HashMap::new(),
            pending_confirmation: HashSet::new(),
        }
    }

    /// Register a contribution from a community peer. Called on each inbound
    /// WitnessEnvelope from a peer whose `effective_trust() >= Verified`.
    pub fn register_contribution(
        &mut self,
        peer_id: &MeshAddress,
        did: &Did,
        recording_id: &RecordingId,
    ) {
        let entry = self
            .watched
            .entry(peer_id.clone())
            .or_insert_with(|| WatchedPeer {
                did: did.clone(),
                last_contribution: Instant::now(),
                recordings: HashSet::new(),
            });
        entry.last_contribution = Instant::now();
        entry.recordings.insert(recording_id.clone());
    }

    /// Mark a peer as disconnected (pending confirmation).
    ///
    /// Does NOT immediately fire the canary. The peer must also be confirmed
    /// stale via `on_peer_stale` before the alert triggers. This prevents
    /// false positives from transient network blips.
    pub fn on_peer_disconnected(&mut self, peer_id: &MeshAddress) {
        if self.watched.contains_key(peer_id) {
            self.pending_confirmation.insert(peer_id.clone());
        }
    }

    /// Confirm a disconnected peer is stale (heartbeat grace expired).
    ///
    /// Returns `Some(CanaryState::Alert)` when the staleness threshold is met.
    /// This is the actual canary trigger — disconnect alone is not sufficient.
    pub fn on_peer_stale(&mut self, peer_id: &MeshAddress) -> Option<CanaryState> {
        if !self.pending_confirmation.contains(peer_id) {
            return None;
        }

        let count = self.stale_counts.entry(peer_id.clone()).or_insert(0);
        *count = count.saturating_add(1);

        if *count >= self.confirmation_required {
            Some(self.evaluate())
        } else {
            None
        }
    }

    /// Peer reconnected — cancel any pending confirmation.
    pub fn on_peer_reconnected(&mut self, peer_id: &MeshAddress) {
        self.pending_confirmation.remove(peer_id);
        self.stale_counts.remove(peer_id);
    }

    /// Clear all watched state. Called when the recording stops.
    pub fn clear(&mut self) {
        self.watched.clear();
        self.stale_counts.clear();
        self.pending_confirmation.clear();
    }

    /// True if at least one peer is being watched.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.watched.is_empty()
    }

    /// Evaluate current state: collect all confirmed-silent peers and build alert.
    fn evaluate(&self) -> CanaryState {
        let mut silent_peers = Vec::new();
        let mut recordings_at_risk = HashSet::new();

        for (peer_id, count) in &self.stale_counts {
            if *count >= self.confirmation_required {
                silent_peers.push(peer_id.clone());
                if let Some(wp) = self.watched.get(peer_id) {
                    recordings_at_risk.extend(wp.recordings.iter().cloned());
                }
            }
        }

        if silent_peers.is_empty() {
            return CanaryState::Normal;
        }

        let peers_remaining = self.watched.len().saturating_sub(silent_peers.len());

        CanaryState::Alert {
            silent_peers,
            recordings_at_risk,
            peers_remaining,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn net(s: &str) -> MeshAddress {
        MeshAddress(s.to_string())
    }

    fn did(s: &str) -> Did {
        Did::new(s)
    }

    fn rid(s: &str) -> RecordingId {
        RecordingId::new(s)
    }

    #[test]
    fn register_and_disconnect_triggers_alert_after_stale_confirmation() {
        let mut canary = CanaryMonitor::new(1);

        canary.register_contribution(&net("peer-a"), &did("did:a"), &rid("rec-1"));
        canary.register_contribution(&net("peer-b"), &did("did:b"), &rid("rec-2"));
        canary.register_contribution(&net("peer-c"), &did("did:c"), &rid("rec-1"));

        // Disconnect alone should not trigger
        canary.on_peer_disconnected(&net("peer-a"));
        // Not yet confirmed stale — no alert
        assert!(!canary.stale_counts.contains_key(&net("peer-a")));

        // Stale confirmation fires the canary
        let state = canary.on_peer_stale(&net("peer-a"));
        assert!(state.is_some());
        match state.unwrap() {
            CanaryState::Alert {
                silent_peers,
                recordings_at_risk,
                peers_remaining,
            } => {
                assert_eq!(silent_peers.len(), 1);
                assert!(recordings_at_risk.contains(&rid("rec-1")));
                assert_eq!(peers_remaining, 2);
            }
            CanaryState::Normal => panic!("Expected Alert"),
        }
    }

    #[test]
    fn reconnect_cancels_pending_confirmation() {
        let mut canary = CanaryMonitor::new(2);

        canary.register_contribution(&net("peer-a"), &did("did:a"), &rid("rec-1"));
        canary.on_peer_disconnected(&net("peer-a"));

        // First stale check — not yet at threshold (need 2)
        assert!(canary.on_peer_stale(&net("peer-a")).is_none());

        // Peer comes back
        canary.on_peer_reconnected(&net("peer-a"));
        assert!(!canary.pending_confirmation.contains(&net("peer-a")));
        assert!(!canary.stale_counts.contains_key(&net("peer-a")));

        // Further stale checks should not fire
        assert!(canary.on_peer_stale(&net("peer-a")).is_none());
    }

    #[test]
    fn non_watched_peer_disconnect_is_ignored() {
        let mut canary = CanaryMonitor::new(1);

        canary.register_contribution(&net("peer-a"), &did("did:a"), &rid("rec-1"));

        // Unknown peer disconnects
        canary.on_peer_disconnected(&net("peer-unknown"));
        assert!(canary.on_peer_stale(&net("peer-unknown")).is_none());
    }

    #[test]
    fn clear_resets_all_state() {
        let mut canary = CanaryMonitor::new(1);

        canary.register_contribution(&net("peer-a"), &did("did:a"), &rid("rec-1"));
        canary.on_peer_disconnected(&net("peer-a"));
        let _ = canary.on_peer_stale(&net("peer-a"));

        canary.clear();

        assert!(canary.watched.is_empty());
        assert!(canary.stale_counts.is_empty());
        assert!(canary.pending_confirmation.is_empty());
    }

    #[test]
    fn all_peers_dark_shows_zero_remaining() {
        let mut canary = CanaryMonitor::new(1);

        canary.register_contribution(&net("peer-a"), &did("did:a"), &rid("rec-1"));
        canary.register_contribution(&net("peer-b"), &did("did:b"), &rid("rec-2"));

        canary.on_peer_disconnected(&net("peer-a"));
        canary.on_peer_disconnected(&net("peer-b"));

        // Confirm both stale
        let _ = canary.on_peer_stale(&net("peer-a"));
        let state = canary.on_peer_stale(&net("peer-b"));

        match state.unwrap() {
            CanaryState::Alert {
                peers_remaining, ..
            } => {
                assert_eq!(peers_remaining, 0);
            }
            CanaryState::Normal => panic!("Expected Alert"),
        }
    }

    #[test]
    fn multiple_recordings_from_same_peer_all_at_risk() {
        let mut canary = CanaryMonitor::new(1);

        canary.register_contribution(&net("peer-a"), &did("did:a"), &rid("rec-1"));
        canary.register_contribution(&net("peer-a"), &did("did:a"), &rid("rec-2"));

        canary.on_peer_disconnected(&net("peer-a"));
        let state = canary.on_peer_stale(&net("peer-a")).unwrap();

        match state {
            CanaryState::Alert {
                recordings_at_risk, ..
            } => {
                assert!(recordings_at_risk.contains(&rid("rec-1")));
                assert!(recordings_at_risk.contains(&rid("rec-2")));
            }
            CanaryState::Normal => panic!("Expected Alert"),
        }
    }
}
