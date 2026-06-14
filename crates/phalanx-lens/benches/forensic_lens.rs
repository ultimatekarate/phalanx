// crates/phalanx-lens/benches/forensic_lens.rs
//
// Criterion benchmarks for ForensicLens throughput.
// The analyze() method runs pre-encryption on every camera frame — this
// measures the actual cost on the hot path.
//
// Run: cargo bench -p phalanx-lens
#![allow(
    clippy::indexing_slicing,        // Pixel buffer indexing — bounds governed by loop invariants.
    clippy::cast_possible_truncation, // Deliberate u8 truncation for pixel generation.
    clippy::arithmetic_side_effects  // Bench arithmetic — not production code.
)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use phalanx_lens::ForensicLens;
use phalanx_lens::scalar::ScalarLens;
use phalanx_proto::types::BlackLevel;

const WIDTH_1080P: usize = 1920;
const HEIGHT_1080P: usize = 1080;

/// Generate a checkerboard noise pattern (worst-case Laplacian energy).
fn make_noise_frame(width: usize, height: usize) -> Vec<u8> {
    let mut buf = vec![0u8; width * height];
    for y in 0..height {
        for x in 0..width {
            buf[y * width + x] = if (x + y) % 2 == 0 { 0 } else { 255 };
        }
    }
    buf
}

/// Generate a constant frame (all pixels = value).
fn make_constant_frame(width: usize, height: usize, value: u8) -> Vec<u8> {
    vec![value; width * height]
}

/// Generate a horizontal linear gradient.
fn make_gradient_frame(width: usize, height: usize) -> Vec<u8> {
    let mut buf = vec![0u8; width * height];
    for y in 0..height {
        for x in 0..width {
            buf[y * width + x] = (x * 255 / (width - 1)) as u8;
        }
    }
    buf
}

fn bench_analyze_1080p(c: &mut Criterion) {
    let lens = ScalarLens;
    let frame = make_noise_frame(WIDTH_1080P, HEIGHT_1080P);
    let bl = BlackLevel(16.0);

    c.bench_function("analyze_1080p_noise", |b| {
        b.iter(|| {
            black_box(lens.analyze(
                black_box(&frame),
                black_box(WIDTH_1080P),
                black_box(HEIGHT_1080P),
                black_box(bl),
            ))
        });
    });
}

fn bench_data_patterns(c: &mut Criterion) {
    let lens = ScalarLens;
    let bl = BlackLevel(16.0);

    let constant = make_constant_frame(WIDTH_1080P, HEIGHT_1080P, 128);
    let gradient = make_gradient_frame(WIDTH_1080P, HEIGHT_1080P);
    let noise = make_noise_frame(WIDTH_1080P, HEIGHT_1080P);

    let mut group = c.benchmark_group("data_patterns_1080p");

    group.bench_function("constant", |b| {
        b.iter(|| {
            black_box(lens.analyze(
                black_box(&constant),
                black_box(WIDTH_1080P),
                black_box(HEIGHT_1080P),
                black_box(bl),
            ))
        });
    });

    group.bench_function("gradient", |b| {
        b.iter(|| {
            black_box(lens.analyze(
                black_box(&gradient),
                black_box(WIDTH_1080P),
                black_box(HEIGHT_1080P),
                black_box(bl),
            ))
        });
    });

    group.bench_function("noise", |b| {
        b.iter(|| {
            black_box(lens.analyze(
                black_box(&noise),
                black_box(WIDTH_1080P),
                black_box(HEIGHT_1080P),
                black_box(bl),
            ))
        });
    });

    group.finish();
}

criterion_group!(benches, bench_analyze_1080p, bench_data_patterns);
criterion_main!(benches);
