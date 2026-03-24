// crates/phalanx-forensics/src/corroboration.rs
//
// Gate 8: The Corroboration Gate (Multi-Device Independence)
//
// Laboratory layer — pure logic. No IO, no tokio, no libp2p.
// Takes N recordings and produces a CorroborationProof or rejects.

use std::collections::HashSet;
use std::time::Duration;

use phalanx_proto::corroboration::{
    CorroborationError, CorroborationProof, DeviceAttestation, EventWindow, PrnuProfile,
    ProximityWitness, SensorDivergence,
};
use phalanx_proto::evidence::{Evidence, Recording};
use phalanx_proto::identity::Did;
use phalanx_proto::time::PhalanxTimestamp;

use crate::crucible::EvidenceExt;

// ── Kolmogorov-Smirnov Test ─────────────────────────────────────────────

/// Two-sample Kolmogorov-Smirnov test.
/// Returns (D_n statistic, approximate p-value).
/// Pure math — no IO.
pub fn ks_two_sample(a: &mut [f64], b: &mut [f64]) -> (f64, f64) {
    a.sort_unstable_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
    b.sort_unstable_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));

    let n_a = a.len() as f64;
    let n_b = b.len() as f64;

    let mut i = 0usize;
    let mut j = 0usize;
    let mut d_max: f64 = 0.0;

    while i < a.len() && j < b.len() {
        if a[i] <= b[j] {
            i += 1;
        } else {
            j += 1;
        }
        let cdf_a = i as f64 / n_a;
        let cdf_b = j as f64 / n_b;
        let d = (cdf_a - cdf_b).abs();
        if d > d_max {
            d_max = d;
        }
    }

    // Approximate p-value via Kolmogorov distribution.
    // For large n, P(D > d) ≈ 2 * exp(-2 * (d * sqrt(n_eff))^2)
    // where n_eff = (n_a * n_b) / (n_a + n_b).
    let n_eff = (n_a * n_b) / (n_a + n_b);
    let lambda = d_max * n_eff.sqrt();
    let p_value = (-2.0 * lambda * lambda).exp() * 2.0;
    let p_value = p_value.clamp(0.0, 1.0);

    (d_max, p_value)
}

// ── PRNU Profiling ──────────────────────────────────────────────────────

/// Extract PRNU statistics from video frames within a time window.
fn extract_prnu_profile(
    recording: &Recording,
    overlap_start: u64,
    overlap_end: u64,
) -> (PrnuProfile, Vec<f64>) {
    let mut prnu_vars: Vec<f64> = Vec::new();
    let mut h_energies: Vec<f64> = Vec::new();
    let mut v_energies: Vec<f64> = Vec::new();

    for env in &recording.artifacts {
        let ts = env.evidence.timestamp(PhalanxTimestamp::default()).0;
        if ts < overlap_start || ts > overlap_end {
            continue;
        }
        if let Evidence::Video(ref shard) = env.evidence {
            let m = &shard.lens_metrics;
            prnu_vars.push(m.prnu_var as f64);
            h_energies.push(m.h_energy as f64);
            v_energies.push(m.v_energy as f64);
        }
    }

    let n = prnu_vars.len() as f32;
    let mean_prnu = if n > 0.0 {
        prnu_vars.iter().sum::<f64>() as f32 / n
    } else {
        0.0
    };
    let std_prnu = if n > 1.0 {
        let variance = prnu_vars
            .iter()
            .map(|&v| {
                let diff = v as f32 - mean_prnu;
                diff * diff
            })
            .sum::<f32>()
            / (n - 1.0);
        variance.sqrt()
    } else {
        0.0
    };
    let mean_h = if n > 0.0 {
        h_energies.iter().sum::<f64>() as f32 / n
    } else {
        0.0
    };
    let mean_v = if n > 0.0 {
        v_energies.iter().sum::<f64>() as f32 / n
    } else {
        0.0
    };

    let profile = PrnuProfile {
        mean_prnu_var: mean_prnu,
        std_prnu_var: std_prnu,
        mean_h_energy: mean_h,
        mean_v_energy: mean_v,
        sample_count: n as u32,
    };

    (profile, prnu_vars)
}

// ── Temporal Alignment ──────────────────────────────────────────────────

/// Compute the event window from N recordings.
/// Returns None if there's no temporal overlap.
fn compute_event_window(recordings: &[&Recording]) -> Option<EventWindow> {
    if recordings.is_empty() {
        return None;
    }

    let mut global_start = u64::MAX;
    let mut global_end = 0u64;
    let mut latest_start = 0u64;
    let mut earliest_end = u64::MAX;

    for rec in recordings {
        let (rec_start, rec_end) = recording_time_bounds(rec);
        if rec_start < global_start {
            global_start = rec_start;
        }
        if rec_end > global_end {
            global_end = rec_end;
        }
        if rec_start > latest_start {
            latest_start = rec_start;
        }
        if rec_end < earliest_end {
            earliest_end = rec_end;
        }
    }

    if latest_start >= earliest_end {
        return None; // No overlap
    }

    Some(EventWindow {
        start: PhalanxTimestamp(global_start),
        end: PhalanxTimestamp(global_end),
        overlap_start: PhalanxTimestamp(latest_start),
        overlap_end: PhalanxTimestamp(earliest_end),
    })
}

fn recording_time_bounds(recording: &Recording) -> (u64, u64) {
    let mut start = u64::MAX;
    let mut end = 0u64;
    for env in &recording.artifacts {
        let ts = env.evidence.timestamp(PhalanxTimestamp::default()).0;
        if ts < start {
            start = ts;
        }
        if ts > end {
            end = ts;
        }
    }
    (start, end)
}

// ── The Gate ────────────────────────────────────────────────────────────

/// Minimum frames per device for meaningful PRNU profiling.
const MIN_PRNU_FRAMES: u32 = 10;

/// Gate 8: The Corroboration Gate.
///
/// Analyzes N recordings and produces a `CorroborationProof` if:
/// 1. Temporal overlap >= min_overlap
/// 2. All DIDs are distinct
/// 3. All pairwise PRNU divergences have p-value < divergence_alpha
/// 4. All chains have intact integrity (head + tail hashes present)
///
/// Proximity witnesses are attached as supporting evidence — not required.
pub fn corroborate(
    recordings: &[&Recording],
    proximity_log: &[ProximityWitness],
    min_overlap: Duration,
    divergence_alpha: f64,
) -> Result<CorroborationProof, CorroborationError> {
    // 1. Need at least 2 recordings
    if recordings.len() < 2 {
        return Err(CorroborationError::InsufficientRecordings(recordings.len()));
    }

    // 2. All DIDs must be distinct
    let mut seen_dids = HashSet::new();
    for rec in recordings {
        if !seen_dids.insert(&rec.owner_did) {
            return Err(CorroborationError::DuplicateDid(rec.owner_did.clone()));
        }
    }

    // 3. Temporal alignment
    let event_window =
        compute_event_window(recordings).ok_or(CorroborationError::NoTemporalOverlap)?;

    let overlap = event_window.overlap_duration();
    if overlap < min_overlap {
        return Err(CorroborationError::OverlapTooShort(overlap, min_overlap));
    }

    // 4. PRNU profiling per device
    let overlap_start = event_window.overlap_start.0;
    let overlap_end = event_window.overlap_end.0;

    let mut attestations = Vec::new();
    let mut prnu_samples: Vec<(Did, Vec<f64>)> = Vec::new();

    for rec in recordings {
        let (profile, samples) = extract_prnu_profile(rec, overlap_start, overlap_end);

        if profile.sample_count < MIN_PRNU_FRAMES {
            return Err(CorroborationError::InsufficientFrames(
                rec.owner_did.clone(),
                profile.sample_count,
            ));
        }

        // Chain integrity: head and tail evidence hashes.
        // A recording with no artifacts cannot produce a valid attestation.
        let chain_head = rec
            .artifacts
            .first()
            .map(|e| e.evidence_hash)
            .ok_or_else(|| CorroborationError::ChainIntegrityFailure(rec.owner_did.clone()))?;
        let chain_tail = rec
            .artifacts
            .last()
            .map(|e| e.evidence_hash)
            .ok_or_else(|| CorroborationError::ChainIntegrityFailure(rec.owner_did.clone()))?;

        attestations.push(DeviceAttestation {
            did: rec.owner_did.clone(),
            recording_id: rec.id.clone(),
            frame_count: profile.sample_count,
            prnu_profile: profile,
            chain_head,
            chain_tail,
        });

        prnu_samples.push((rec.owner_did.clone(), samples));
    }

    // 5. Pairwise KS tests
    let mut divergences = Vec::new();
    for i in 0..prnu_samples.len() {
        for j in (i + 1)..prnu_samples.len() {
            let mut a = prnu_samples[i].1.clone();
            let mut b = prnu_samples[j].1.clone();
            let (ks_stat, p_value) = ks_two_sample(&mut a, &mut b);

            if p_value >= divergence_alpha {
                return Err(CorroborationError::InsufficientDivergence(
                    prnu_samples[i].0.clone(),
                    prnu_samples[j].0.clone(),
                    p_value,
                ));
            }

            divergences.push(SensorDivergence {
                device_a: prnu_samples[i].0.clone(),
                device_b: prnu_samples[j].0.clone(),
                ks_statistic: ks_stat,
                p_value,
            });
        }
    }

    // 6. Proximity matching (supporting evidence, not required)
    let proximity_evidence: Vec<ProximityWitness> = proximity_log
        .iter()
        .filter(|pw| pw.observed_at.0 >= overlap_start && pw.observed_at.0 <= overlap_end)
        .cloned()
        .collect();

    // 7. Assemble proof (signature and hash filled by the Stronghold's Hands layer)
    Ok(CorroborationProof {
        event_window,
        attestations,
        divergences,
        proximity_evidence,
        producer_did: Did::new("pending:stronghold-signs-this"),
        producer_signature: Vec::new(),
        proof_hash: [0u8; 32], // Computed by Stronghold after signing
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use phalanx_proto::evidence::*;
    use phalanx_proto::identity::RecordingId;

    fn make_recording(did: &str, base_prnu: f32, start_ms: u64, frame_count: u32) -> Recording {
        let mut artifacts = Vec::new();
        for i in 0..frame_count {
            let env = WitnessEnvelope {
                evidence: Evidence::Video(VideoShard {
                    timestamp: PhalanxTimestamp(start_ms + i as u64 * 33), // ~30fps
                    sequence_id: StorageSequence(i),
                    fps: phalanx_proto::types::Fps::new(30),
                    recording_id: RecordingId::new(format!("rec-{did}")),
                    payload: DataPayload::Clear(vec![0u8; 100]),
                    lens_metrics: ForensicMetrics {
                        prnu_var: base_prnu + (i as f32 * 0.1), // slight variation per frame
                        h_energy: 5.0,
                        v_energy: 3.0,
                        mean_luminance: 128.0,
                    },
                }),
                evidence_hash: {
                    let mut h = [0u8; 32];
                    h[0] = i as u8;
                    h[1] = did.as_bytes()[0];
                    h
                },
                witness_peer_id: phalanx_proto::identity::NetworkId(did.to_string()),
                witness_signature: vec![0u8; 64],
                did: Did::new(format!("did:key:{did}")),
                prev_hash: None,
            };
            artifacts.push(env);
        }
        Recording {
            id: RecordingId::new(format!("rec-{did}")),
            owner_did: Did::new(format!("did:key:{did}")),
            artifacts,
            gaps: vec![],
            is_complete: true,
        }
    }

    #[test]
    fn ks_test_identical_distributions_high_p() {
        let mut a: Vec<f64> = (0..100).map(|i| i as f64 * 0.1).collect();
        let mut b = a.clone();
        let (_, p) = ks_two_sample(&mut a, &mut b);
        assert!(
            p > 0.5,
            "Identical distributions should have high p-value, got {p}"
        );
    }

    #[test]
    fn ks_test_distinct_distributions_low_p() {
        let mut a: Vec<f64> = (0..100).map(|i| i as f64).collect();
        let mut b: Vec<f64> = (0..100).map(|i| (i as f64) + 500.0).collect();
        let (d, p) = ks_two_sample(&mut a, &mut b);
        assert!(
            d > 0.9,
            "Completely separated distributions should have D ≈ 1.0, got {d}"
        );
        assert!(
            p < 0.01,
            "Completely separated distributions should have low p-value, got {p}"
        );
    }

    #[test]
    fn corroborate_two_distinct_devices() {
        let rec_a = make_recording("alice", 150.0, 1000, 30);
        let rec_b = make_recording("bob", 220.0, 1100, 30); // different PRNU baseline

        let result = corroborate(&[&rec_a, &rec_b], &[], Duration::from_millis(100), 0.05);

        assert!(
            result.is_ok(),
            "Two distinct devices should corroborate: {:?}",
            result.err()
        );
        let proof = result.unwrap();
        assert_eq!(proof.attestations.len(), 2);
        assert_eq!(proof.divergences.len(), 1);
        assert!(proof.divergences[0].p_value < 0.05);
    }

    #[test]
    fn corroborate_rejects_single_recording() {
        let rec = make_recording("alice", 150.0, 1000, 30);
        let result = corroborate(&[&rec], &[], Duration::from_millis(100), 0.05);
        assert!(matches!(
            result,
            Err(CorroborationError::InsufficientRecordings(1))
        ));
    }

    #[test]
    fn corroborate_rejects_no_overlap() {
        let rec_a = make_recording("alice", 150.0, 1000, 30);
        let rec_b = make_recording("bob", 220.0, 50000, 30); // far in the future

        let result = corroborate(&[&rec_a, &rec_b], &[], Duration::from_millis(100), 0.05);
        assert!(matches!(result, Err(CorroborationError::NoTemporalOverlap)));
    }

    #[test]
    fn corroborate_rejects_duplicate_did() {
        let rec_a = make_recording("alice", 150.0, 1000, 30);
        let rec_b = make_recording("alice", 220.0, 1100, 30); // same DID!

        let result = corroborate(&[&rec_a, &rec_b], &[], Duration::from_millis(100), 0.05);
        assert!(matches!(result, Err(CorroborationError::DuplicateDid(_))));
    }

    #[test]
    fn corroborate_includes_proximity_within_window() {
        let rec_a = make_recording("alice", 150.0, 1000, 30);
        let rec_b = make_recording("bob", 220.0, 1100, 30);

        let proximity = vec![
            ProximityWitness {
                local_did: Did::new("did:key:alice"),
                remote_did: Did::new("did:key:bob"),
                recording_id: RecordingId::new("rec-alice"),
                observed_at: PhalanxTimestamp(1150), // within overlap
                transport: phalanx_proto::topology::TransportClass::LocalMesh,
            },
            ProximityWitness {
                local_did: Did::new("did:key:alice"),
                remote_did: Did::new("did:key:carol"),
                recording_id: RecordingId::new("rec-alice"),
                observed_at: PhalanxTimestamp(99999), // outside overlap
                transport: phalanx_proto::topology::TransportClass::LocalMesh,
            },
        ];

        let proof = corroborate(
            &[&rec_a, &rec_b],
            &proximity,
            Duration::from_millis(100),
            0.05,
        )
        .unwrap();

        assert_eq!(
            proof.proximity_evidence.len(),
            1,
            "Only the witness within the overlap window should be included"
        );
    }
}
