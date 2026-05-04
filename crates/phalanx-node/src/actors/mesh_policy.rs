// crates/phalanx-node/src/actors/mesh_policy.rs
//
// Boundary-policy thresholds for mesh-level actors. These are setpoints at the
// integral-to-actor boundary (where continuous homeostasis output discretises
// into actor decisions). They do NOT live inside the integral path itself —
// the project rule "no hardcoded thresholds in the integral path" is preserved.

use phalanx_proto::community::CommunityId;
use tokio::sync::watch;

/// Maximum simultaneous peers in the topology gate. Matches the libp2p
/// connection limit configured at the transport layer.
pub const TOPOLOGY_TOTAL_CAPACITY: usize = 192;

/// Maximum number of peers held as topology anchors at any time.
pub const TOPOLOGY_MAX_ANCHORS: usize = 4;

/// EclipseProbe history window: number of mesh-fingerprint snapshots retained.
/// 6 snapshots × 5-minute tick = 30-minute window.
pub const ECLIPSE_PROBE_WINDOW: usize = 6;

/// Consecutive stale ticks before a CanaryMonitor confirms a peer silent.
pub const CANARY_CONFIRM_TICKS: u32 = 2;

/// Cap on the per-peer first-seen timestamp map (reciprocity floor).
/// Oldest entry evicted on overflow.
pub const PEER_FIRST_SEEN_CAP: usize = 10_000;

/// Cap on the per-peer DID cache. Oldest entry evicted on overflow. Both
/// CanarySupervisor and EclipseRouter respect this cap on their respective
/// caches.
pub const PEER_DID_CACHE_CAP: usize = 10_000;

/// Eclipse remediation tick period (anchor promotion, eclipse detection,
/// re-bootstrap, reciprocity sweep).
pub const TOPOLOGY_TICK_SECS: u64 = 300;

/// Per-second rate limit on peer-discovery processing. Prevents CPU
/// exhaustion from PeerDiscovered floods.
pub const PEER_DISCOVERY_RATE_LIMIT_PER_SEC: u32 = 10;

/// Topology gate occupancy below this triggers re-bootstrap on the next
/// topology tick.
pub const RE_BOOTSTRAP_TRIGGER_PEER_COUNT: usize = 96;

// ── Helpers ────────────────────────────────────────────────────────────────

/// Compute the live community keyset by merging the registry watch snapshot
/// with the static-seed extras. Used by both `MeshSentinel`
/// (inbound heartbeat decryption) and `CanarySupervisor` (outbound canary
/// alert encryption). The two callers each hold their own clones of the
/// inputs — see plan §"Cross-actor shared state".
///
/// Watch-borrow discipline: the `Ref<'_, T>` returned by `borrow()` deadlocks
/// the watch system if held across `.await`. The single-statement `.clone()`
/// here releases the guard immediately.
#[must_use]
pub fn current_community_ids(
    rx: &watch::Receiver<Vec<CommunityId>>,
    extras: &[CommunityId],
) -> Vec<CommunityId> {
    let mut ids = rx.borrow().clone();
    for cid in extras {
        if !ids.contains(cid) {
            ids.push(*cid);
        }
    }
    ids
}
