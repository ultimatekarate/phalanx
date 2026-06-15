# Phalanx

[![CI](https://github.com/ultimatekarate/phalanx/actions/workflows/ci.yml/badge.svg)](https://github.com/ultimatekarate/phalanx/actions/workflows/ci.yml)

Phalanx is a mobile app that records video, proves it hasn't been tampered with, and distributes it so that destroying the device doesn't destroy the footage — without trusting any server, any network, or any other person. That problem touches cryptography, distributed systems, control theory, signal processing, and adversarial security simultaneously. You can't drop any of them and still solve it. Every subsystem exists because the problem required it. Nothing here is for show.

> **Status (June 2026):** the Rust engine — capture forensics, encryption, signing, fountain-coding, mesh transport, vault, communities, recovery — is real and tested. A functional Android app builds from source (development build); the Stronghold custody server works, including C2PA export. There is no iOS app, no app-store presence, and no field deployment yet. License: TBD. The candid inventory of what exists is [docs/stewardship.md](docs/stewardship.md); the case for adoption is [PITCH.md](PITCH.md).

## Where to start

| You are | Read |
| --- | --- |
| Deciding whether to adopt or fund this | [PITCH.md](PITCH.md), then [docs/stewardship.md](docs/stewardship.md) |
| Evaluating the technology | [docs/architecture.md](docs/architecture.md) → [docs/network.md](docs/network.md) → [docs/trust.md](docs/trust.md) |
| Deploying it for an organization | [docs/operations.md](docs/operations.md) |
| Auditing security | [docs/threat-model.md](docs/threat-model.md) + [docs/trust.md](docs/trust.md) + [docs/network.md](docs/network.md) |
| Contributing or inheriting the code | [CONTRIBUTING.md](CONTRIBUTING.md), [linguistic-code-model.md](linguistic-code-model.md), [docs/subsystems.md](docs/subsystems.md), [docs/actors.md](docs/actors.md) |

## How It Works

Phalanx is deliberately designed to look boring. When you open it, it looks like a basic recording application. The moment you hit record, every frame is checked against the physics of a real camera sensor, encrypted, digitally signed, fountain-coded into redundant fragments, and broadcast to peers — while recording is still in progress. You are the only person who decides who gets to see it. If your device is seized or destroyed, the fragments that already left it survive, and your 12-word recovery phrase regenerates your identity and the keys to every recording you ever made — BIP39 mnemonics aren't just for cryptobros anymore. Phalanx also creates a digital chain of custody: it lets a court trust that a video came from a real camera, without trusting the person who recorded it. The full story, told plainly, is [PITCH.md](PITCH.md); the technical version is [docs/architecture.md](docs/architecture.md).

## Capabilities

- **Real-time capture-to-mesh pipeline** — The moment you hit record, every frame is analyzed for authenticity, encrypted, split into redundant shards, and distributed across the mesh. The pipeline adapts frame rate to device load, shedding capture rate rather than captured evidence
- **Ad hoc mesh network** — Devices form a self-organizing peer-to-peer network over QUIC and TCP: zero-config on a shared LAN (mDNS), configured bootstrap peers across the internet. A Bluetooth/WiFi-Direct integration seam exists; the radios themselves are not yet implemented ([docs/network.md §6](docs/network.md#6-local-mesh-ble--wifi-direct))
- **Trusted communities** — Groups of people who vouch for each other. A quorum of existing members must approve new members. Communities expire automatically and leave no trace when dissolved
- **Selective sharing** — You control who can view your recordings. Access is granted per-recipient through key exchange — no central server decides who sees what. Data is encrypted separately in transit and at rest
- **Fountain-coded sharding** — Recordings are split into redundant pieces so that any sufficient subset can reconstruct the original. That reconstruction is order-independent — formally proven in Lean 4
- **Cryptographic forgetting** — When you delete a recording, it is gone forever. The encryption key is destroyed before the data is removed — if the device dies mid-deletion, the key is already gone and the ciphertext is permanently unreadable. Deletion is designed to propagate across the mesh (see [docs/network.md §3](docs/network.md#3-topics-who-publishes-who-listens) for a current default-config caveat)
- **Silent Canary** — A dead man's switch for your community. If members go dark, the node identifies locally which peers disappeared and which recordings may be at risk; the encrypted alert it broadcasts is deliberately content-free. A seized device cannot reveal the community roster
- **Adaptive resource management** — The system continuously monitors CPU, memory, bandwidth, storage, and battery. When any resource is strained, it gracefully reduces throughput rather than crashing or dropping data
- **Byzantine peer detection** — Nodes that lie about their state are exposed by behavioral consistency checks: the system's resource signals are coupled, so dishonest claims contradict observed behavior
- **Certified stability** — The adaptive control system's boundedness is numerically certified by an SDP-derived Lyapunov analysis ([docs/contractivity-proof.md](docs/contractivity-proof.md) — a strong computational artifact, not a machine-checked proof)
- **Compile-time evidence integrity** — Evidence passes through verified → sealed states enforced by the type system. Code that skips a verification step does not compile
- **Formal verification** — Lean 4 proof that evidence reconstruction produces identical output regardless of the order pieces arrive

## Security Posture

Phalanx assumes zero trust at every boundary: every envelope is Ed25519-signed and re-verified by every receiver, every payload is encrypted in transit and at rest, and trust is earned locally per-peer and never gossiped. The full identity-and-trust model is [docs/trust.md](docs/trust.md); the attack-by-attack catalog is [docs/threat-model.md](docs/threat-model.md).

## Emergent Properties

The adaptive control system produces behaviors that were never explicitly programmed — self-healing recovery as pressure decays, load shedding that sacrifices untrusted peers first, Sybil resistance with diminishing returns for each fake identity. The full list, with mechanisms, is [docs/homeostasis.md](docs/homeostasis.md).

## Architecture

The codebase is governed by a [Linguistic Code Model](linguistic-code-model.md) and composed of [37 subsystems](docs/subsystems.md) spanning evidence lifecycle, cryptography, trust, adaptive control, corroboration, and infrastructure. The crate-by-crate map, node taxonomy, and the life of a frame from sensor to custody are in [docs/architecture.md](docs/architecture.md).

## Contributing

Phalanx is conceptually dense. I have gone to great lengths to ensure that you do not need to understand all of it to contribute to any of it. If you are interested, please read [the friendly manual](CONTRIBUTING.md). There you will find the code base broken down by technical specialty with a list of files and a brief summary of what each file does.

I'm not an expert in cryptography, control theory, networking, or any of the other fields represented here. I RTFM, implemented what made sense to me, and tried to get it right. If you are an expert and something I did gives you pause — a non-standard key derivation, an assumption that doesn't hold, an edge case I didn't consider — that is the most valuable contribution you can make. You don't need to fix it. Just telling me what's wrong and why is enough — I love to learn new ideas. Or you could fix it, that's kind of the point of open source, right?

---

## Build

I want to preface this section with the fact that I am not a DevOps expert. If you are a DevOps expert I would love your help. Please.

Minimum Rust version: **1.93.1**

### Dev Container (recommended)

The fastest way to build — especially on Windows. Everything is pre-installed: Rust, nasm, CMake, Android NDK, Flutter, cargo-ndk, cbindgen. I recommend doing this; do not repeat my mistakes.

Open this repo in [VS Code with the Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) or in [GitHub Codespaces](https://codespaces.new). The container builds, `cargo fetch` runs, and you're ready:

```bash
cargo build --workspace
cargo test --workspace
```

### Native Build

If you're not using the dev container, you can build on the host directly. Three crates (`turbojpeg`, `openh264`, `fdk-aac`) compile C/C++ from source, so you need a C/C++ compiler toolchain, CMake, and NASM.

**Windows:**

Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the "Desktop development with C++" workload. This provides the MSVC compiler, linker, and Windows SDK. Then install CMake and NASM:

```bash
# scoop:
scoop install cmake nasm
# or choco:
choco install cmake nasm
```

Ensure `cmake` and `nasm` are on your PATH. You may need to open a new terminal after installation. Build from a **Developer Command Prompt** or a terminal where `cl.exe` is on PATH (e.g., via `vcvarsall.bat`).

**macOS:**

```bash
xcode-select --install   # provides clang
brew install cmake nasm
```

**Ubuntu/Debian:**

```bash
sudo apt-get install build-essential cmake nasm
```

**Then build:**

```bash
cargo build --workspace
cargo test --workspace
```

If a `*-sys` crate fails to build (e.g. `turbojpeg-sys` or `fdk-aac-sys`), it's almost always CMake not finding the C compiler. Run `cmake --version` and `cl --version` (Windows) or `cc --version` (Linux/macOS) to confirm they're on PATH. If host setup keeps fighting you, use the dev container above — it has the full toolchain preinstalled.

The Stronghold server binary:

```bash
cargo build -p phalanx-stronghold --bin stronghold --release
```

### Mobile (Android + iOS + Flutter)

The full mobile pipeline — Rust FFI cross-compilation, native library placement, header generation, and Flutter APK/iOS build — is handled by a single script:

```bash
./scripts/build_mobile.sh           # Both platforms
./scripts/build_mobile.sh android   # Android only
./scripts/build_mobile.sh ios       # iOS only (macOS required)
```

Prerequisites:

```bash
# Rust cross-compilation targets
cargo install cargo-ndk
rustup target add aarch64-linux-android x86_64-linux-android
rustup target add aarch64-apple-ios aarch64-apple-ios-sim   # macOS only
cargo install cbindgen                                       # C header generation

# Android SDK + NDK (the script auto-detects the latest installed NDK)
# Flutter SDK ≥3.16.0 in PATH
```

The script handles the details that are easy to get wrong: NDK toolchain detection, AOSP log stub headers for `fdk-aac-sys`, Ninja generator override on Windows, copying `.so` files into `flutter_app/android/app/src/main/jniLibs/`, copying `.a` files into `flutter_app/ios/Frameworks/`, and generating `phalanx.h` for Swift bridging.

Note: 32-bit ARM (`armeabi-v7a`) is disabled — `raptorq` 2.0.1 uses NEON intrinsics that are unstable on 32-bit ARM (`rust-lang/rust#111800`).

### Lean 4 Proofs (optional)

The `proofs/` directory contains Lean 4 formal verification of fountain code reconstruction. Not required for runtime — verification only.

```bash
cd proofs
lake build
```

## Test

```bash
cargo test --workspace
```

## Lint Governance

The workspace enforces deny-level clippy lints across all crates — `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`, `cast_possible_truncation`, `cast_sign_loss`, `cast_possible_wrap`, `float_cmp`, `await_holding_lock`, and `undocumented_unsafe_blocks`. See [`linguistic-code-model.md` § II](linguistic-code-model.md#ii-structural-enforcement) for the full annotated list and `Cargo.toml` for the source of truth.

## License

License: TBD. Phalanx will always be open source and free. The decision path and constraints are tracked in [docs/stewardship.md](docs/stewardship.md).
