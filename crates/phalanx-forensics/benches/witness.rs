// crates/phalanx-forensics/benches/witness.rs
//
// Criterion benchmarks for the witness signing / verification hot path.
//
// `sign_envelope` runs on every published evidence shard and is the known
// publisher-side bottleneck (Ed25519). The sub-step benchmarks (serialize /
// hash / sign) quantify how much of `sign_envelope` is the Ed25519 signature,
// so the attribution can be confirmed and tracked across changes.
//
// Run: cargo bench -p phalanx-forensics
#![allow(clippy::expect_used)] // Bench setup — not production code.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use ed25519_dalek::Signer;

use phalanx_forensics::witness::WitnessAuthority;
use phalanx_proto::evidence::{Evidence, WitnessEnvelope};
use phalanx_proto::identity::{PhalanxIdentity, RecordingId};
use phalanx_proto::time::{SystemClock, TrustedClock};
use phalanx_test_fixtures::shards::video_shard_for_recording;

fn crypto_benches(c: &mut Criterion) {
    let identity = PhalanxIdentity::new_ephemeral();
    let rid = RecordingId::new("bench-recording");

    // `sign_envelope` consumes `Evidence` by value, so each iteration gets a
    // fresh one built in the (untimed) batched setup.
    c.bench_function("sign_envelope", |b| {
        b.iter_batched(
            || Evidence::Video(video_shard_for_recording(&rid, 0, SystemClock.now())),
            |ev| WitnessEnvelope::sign_envelope(ev, &identity, identity.witness_id.clone(), None),
            BatchSize::SmallInput,
        );
    });

    // A representative evidence + its serialization, reused by the read-only
    // benches below.
    let evidence = Evidence::Video(video_shard_for_recording(&rid, 0, SystemClock.now()));
    let serialized = postcard::to_allocvec(&evidence).expect("serialize evidence");
    let envelope = WitnessEnvelope::sign_envelope(
        Evidence::Video(video_shard_for_recording(&rid, 0, SystemClock.now())),
        &identity,
        identity.witness_id.clone(),
        None,
    )
    .expect("sign envelope");

    c.bench_function("verify_envelope", |b| {
        b.iter(|| envelope.verify_envelope());
    });

    // Sub-steps of `sign_envelope` — the Ed25519 signature is the expected
    // dominant fraction.
    c.bench_function("sign.serialize", |b| {
        b.iter(|| postcard::to_allocvec(black_box(&evidence)));
    });
    c.bench_function("sign.hash", |b| {
        b.iter(|| blake3::hash(black_box(&serialized)));
    });
    c.bench_function("sign.ed25519", |b| {
        b.iter(|| identity.keypair.sign(black_box(&serialized)));
    });
}

criterion_group!(benches, crypto_benches);
criterion_main!(benches);
