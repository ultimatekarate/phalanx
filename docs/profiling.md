# Profiling & Performance Instrumentation

How to measure Phalanx's performance: where CPU time goes, where the async
event loop stalls, and whether a change regressed a hot path.

## Scope

This covers **development-time profiling** and a **manual CI benchmark
comparison**. Production / field telemetry is deliberately out of scope —
performance traces are activity metadata, and on a seizable mobile device that
is a forensic liability. A field-telemetry design needs its own opt-in,
aggregated, encrypted-sink treatment.

Tooling, by question:

| Question | Tool | Where |
|---|---|---|
| Where is CPU time going? | `simpleperf` (device), `samply` (host) | device + host |
| Where does the event loop stall? | Perfetto + ATrace track events | device |
| Did a change regress a hot function? | `criterion` + `critcmp` | host / CI |

eBPF is **not** used: on Android it needs root and a custom kernel, and it
cannot attribute userspace CPU inside the tokio runtime.

## The in-code instrument: `tracing` spans

Instrumentation is `tracing` spans, compiled in unconditionally and gated at
runtime by the subscriber's filter — a disabled span costs an atomic load.

Instrumented today:

- **Crypto hot path** (`phalanx-forensics`, `sign_envelope` / `verify_envelope`)
  — TRACE level, plus three sub-step spans `sign.serialize`, `sign.hash`,
  `sign.ed25519`.
- **Event loop** (`phalanx-node`, `handle_network_event`,
  `handle_data_received`) and **transport** (`Libp2pAdapter::publish`) — DEBUG.
- **Homeostasis** (`phalanx-node`, `update_vitals`, `composite_stress`,
  `integral_summary`) — DEBUG.

Span names bridged to Android Perfetto are listed in
`phalanx_proto::telemetry::spans::BRIDGED`. To instrument a new scope, add a
`#[tracing::instrument]` / `trace_span!`, and — if it should appear in Perfetto —
add its name there.

### Subscribers

- **Host** (`sentinel`, `phalanx-sim`, tests): `phalanx_node::vitals::init_observability()`
  — console + JSON file (`logs/guardian.log`), with span close-durations.
- **Android** (`phalanx-ffi`): `init_android_observability()`, installed by the
  FFI bootstrap — events to logcat, the `BRIDGED` crypto spans to ATrace/Perfetto.
  No file layer (no plaintext perf log on a seizable device).

## Host profiling (Windows / desktop) — `samply`

`samply` is a sampling CPU profiler with a Firefox-Profiler UI. Release builds
keep DWARF symbols (`[profile.release] debug = true`), so Rust frames resolve.

```
cargo install samply
```

Profile the **crypto microbenchmark** (drives `sign_envelope` in a tight loop):

```
cargo bench --no-run -p phalanx-forensics
# the build prints the bench exe path, e.g. target/release/deps/witness-<hash>
samply record target/release/deps/witness-<hash>
```

Profile the **mesh under load** via the simulation harness — `phalanx-sim` is a
library, so profile its test binary:

```
cargo test --release --no-run -p phalanx-sim
samply record target/release/deps/<phalanx_sim-test-exe>
```

A lone `sentinel` node is idle — drive load through `phalanx-sim` or the bench.

## On-device profiling — retail phone (non-rooted)

1. Stage the release `libphalanx_ffi.so` into the app's `jniLibs` (the existing
   `cargo-ndk` / `scripts/build_mobile.sh` step).
2. `cd flutter_app && flutter run --profile` — profile mode produces a
   *profileable* APK, which `simpleperf` and Perfetto can attach to without root.
   If attach is refused, add `<profileable android:shell="true"
   tools:targetApi="29"/>` to
   `flutter_app/android/app/src/profile/AndroidManifest.xml`.

**CPU sampling — `simpleperf`** (ships in the NDK):

```
python $ANDROID_NDK_HOME/simpleperf/app_profiler.py \
  -p com.phalanx.app -r "-e cpu-clock -f 4000 -g --duration 20"
python $ANDROID_NDK_HOME/simpleperf/report_html.py
```

Exercise a recording session during the 20 s capture so the publish path is
in-frame. Rust symbols resolve from the unstripped `arm64-v8a/libphalanx_ffi.so`.

**Timeline — Perfetto:** open <https://ui.perfetto.dev>, *Record new trace*,
enable the **atrace "app"** category, target `com.phalanx.app`. The bridged
crypto spans (`sign_envelope`, `sign.ed25519`, …) appear as named slices.

## On-device profiling — emulator

`adb root` works on AOSP emulator images, so Perfetto can capture a full
**system** trace (scheduler, ftrace) — useful for lock-contention shape and
wakeup patterns. Use an **arm64 system image** so the existing `aarch64` `.so`
runs. Emulator timing is host-distorted: use it for structure, the retail phone
for absolute numbers.

## Microbenchmarks — `criterion`

```
cargo bench -p phalanx-forensics      # sign/verify + crypto sub-steps
cargo bench -p phalanx-lens           # ForensicLens::analyze
```

Reports land in `target/criterion/`. To compare against a baseline:

```
cargo bench -p phalanx-forensics -- --save-baseline before
# ...make a change...
cargo bench -p phalanx-forensics -- --save-baseline after
critcmp before after
```

The CI `bench` job (manual `workflow_dispatch`) does this against `main` and
prints the table to the run summary. It is **informational** — GitHub-hosted
runners are too noisy (5–15 %+ variance) for a hard regression gate.

## Interpreting results

The known bottleneck is **publisher-side Ed25519 signing**. The current implementation with bundling and increased raptor symbol size is probably as efficient as it gets.

For latency rather than CPU, read the Perfetto timeline — a wide `publish` slice
with the thread descheduled points at transport back-pressure, not crypto.

## Future work

- Production / field telemetry (opt-in, aggregated, encrypted sink).
- Bridging the async event-loop spans to Perfetto via ATrace async cookies.
- A second criterion bench for whatever the first profiling pass identifies as
  the next hotspot.
- A hard CI regression gate (needs a `pull_request` trigger + a pinned runner).
