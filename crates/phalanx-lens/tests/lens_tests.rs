//! Integration tests for phalanx-lens forensic sensor fingerprinting.
//!
//! These tests verify that ScalarLens produces expected metrics for
//! known input patterns, establishing baseline behavior for the
//! forensic evidence provenance pipeline.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)] // Test pixel buffers — bounds governed by loop invariants.

use phalanx_lens::ForensicLens;
use phalanx_lens::scalar::ScalarLens;
use phalanx_proto::types::BlackLevel;

const CROP_SIZE: usize = 256;

// ─── Baseline Tests ───────────────────────────────────────────────────────

#[test]
fn uniform_frame_low_energy() {
    // A constant-value frame should have near-zero energy and PRNU
    let width = CROP_SIZE;
    let height = CROP_SIZE;
    let y_plane = vec![128u8; width * height];

    let lens = ScalarLens;
    let metrics = lens.analyze(&y_plane, width, height, BlackLevel::default());

    assert!(
        metrics.h_energy.abs() < 1.0,
        "Uniform frame h_energy should be near zero, got {}",
        metrics.h_energy
    );
    assert!(
        metrics.v_energy.abs() < 1.0,
        "Uniform frame v_energy should be near zero, got {}",
        metrics.v_energy
    );
    assert!(
        metrics.prnu_var.abs() < 1.0,
        "Uniform frame prnu_var should be near zero, got {}",
        metrics.prnu_var
    );
}

#[test]
fn edge_pattern_produces_energy() {
    // A pattern with sharp edges (alternating black/white stripes) should produce
    // detectable Laplacian energy — smooth gradients have zero second derivative.
    let width = CROP_SIZE;
    let height = CROP_SIZE;
    let mut y_plane = vec![0u8; width * height];
    for row in 0..height {
        for col in 0..width {
            // Alternating 8-pixel-wide black and white vertical stripes
            y_plane[row * width + col] = if (col / 8) % 2 == 0 { 0 } else { 255 };
        }
    }

    let lens = ScalarLens;
    let metrics = lens.analyze(&y_plane, width, height, BlackLevel::default());

    // Sharp edges produce non-zero Laplacian response
    let total_energy = metrics.h_energy + metrics.v_energy;
    assert!(
        total_energy > 0.0,
        "Edge pattern should produce positive energy, got h={} v={}",
        metrics.h_energy,
        metrics.v_energy
    );
}

#[test]
fn random_noise_high_prnu_var() {
    // Random pixel values should produce higher PRNU variance than uniform
    let width = CROP_SIZE;
    let height = CROP_SIZE;

    // Deterministic pseudo-random using simple LCG
    let mut y_plane = vec![0u8; width * height];
    let mut seed: u64 = 12345;
    for pixel in y_plane.iter_mut() {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        *pixel = (seed >> 33) as u8;
    }

    let lens = ScalarLens;
    let noisy_metrics = lens.analyze(&y_plane, width, height, BlackLevel::default());

    // Compare against uniform
    let uniform_plane = vec![128u8; width * height];
    let uniform_metrics = lens.analyze(&uniform_plane, width, height, BlackLevel::default());

    assert!(
        noisy_metrics.prnu_var > uniform_metrics.prnu_var,
        "Random noise prnu_var ({}) should exceed uniform ({})",
        noisy_metrics.prnu_var,
        uniform_metrics.prnu_var
    );
}

// ─── Defense: Edge Cases ──────────────────────────────────────────────────

#[test]
fn undersized_frame_no_panic() {
    // Frame smaller than ANALYSIS_CROP_SIZE should return gracefully
    let width = 64;
    let height = 64;
    let y_plane = vec![128u8; width * height];

    let lens = ScalarLens;
    let metrics = lens.analyze(&y_plane, width, height, BlackLevel::default());

    // Should return default/zero metrics without panicking
    // The exact values don't matter — the test is that it doesn't crash
    let _ = metrics;
}
