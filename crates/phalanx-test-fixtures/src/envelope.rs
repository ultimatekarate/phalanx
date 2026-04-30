//! WitnessEnvelope, Evidence, and ForensicUnit fixtures.
//!
//! Composes Dictionary Nouns with Laboratory Verbs (WitnessAuthority)
//! to produce signed envelopes. Tests that need signed envelopes should
//! use these fixtures instead of calling sign_envelope() directly —
//! the signing call requires constructing valid Evidence first, which
//! is exactly the construction knowledge this crate encapsulates.

use phalanx_forensics::witness::WitnessAuthority;
use phalanx_proto::evidence::{Evidence, SignatureHash, WitnessEnvelope};
use phalanx_proto::identity::{PhalanxIdentity, RecordingId};
use phalanx_proto::time::{PhalanxTimestamp, SystemClock, TrustedClock};
use phalanx_proto::types::{ForensicUnit, Verified};

use crate::shards::video_shard_for_recording;

/// Signed WitnessEnvelope wrapping a synthetic VideoShard.
///
/// Returns the envelope AND the identity, because tests often need
/// both (e.g., to verify signatures or construct subsequent envelopes).
///
/// Uses an ephemeral identity, `SystemClock.now()` timestamp, no prev_hash.
#[allow(clippy::expect_used)]
pub fn witness_envelope_synthetic() -> (WitnessEnvelope, PhalanxIdentity) {
    let identity = PhalanxIdentity::new_ephemeral();
    let rid = RecordingId::new("synthetic");
    let now = SystemClock.now();
    let evidence = video_evidence_for_recording(&rid, 0, now);
    let env =
        WitnessEnvelope::sign_envelope(evidence, &identity, identity.witness_id.clone(), None)
            .expect("signing should not fail with synthetic evidence");
    (env, identity)
}

/// Signed WitnessEnvelope for a specific recording chain.
///
/// Replaces `sign_test_envelope()`, `mock_valid_envelope()`, and similar
/// helpers duplicated across test files. Uses `SystemClock.now()` for
/// temporal agreement with verification Verbs.
#[allow(clippy::expect_used)]
pub fn witness_envelope_for_recording(
    identity: &PhalanxIdentity,
    recording_id: &RecordingId,
    seq: u32,
    prev_hash: Option<SignatureHash>,
) -> WitnessEnvelope {
    let now = SystemClock.now();
    let evidence = video_evidence_for_recording(recording_id, seq, now);
    WitnessEnvelope::sign_envelope(evidence, identity, identity.witness_id.clone(), prev_hash)
        .expect("signing should not fail with synthetic evidence")
}

/// Evidence::Video for a specific recording.
///
/// Wraps `video_shard_for_recording` in the Evidence enum.
pub fn video_evidence_for_recording(
    recording_id: &RecordingId,
    seq: u32,
    timestamp: PhalanxTimestamp,
) -> Evidence {
    Evidence::Video(video_shard_for_recording(recording_id, seq, timestamp))
}

/// Verified ForensicUnit for recording chain tests.
///
/// Replaces `make_verified_unit()` 1:1. Designed for use in loops
/// (e.g., `0..100` sequences feeding a Crucible).
#[allow(clippy::expect_used)]
pub fn verified_unit_for_recording(
    identity: &PhalanxIdentity,
    recording_id: &RecordingId,
    seq: u32,
    prev_hash: Option<SignatureHash>,
) -> ForensicUnit<WitnessEnvelope, Verified> {
    let env = witness_envelope_for_recording(identity, recording_id, seq, prev_hash);
    ForensicUnit::<WitnessEnvelope, Verified>::new_verified(env)
}
