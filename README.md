# Phalanx

[![Android](https://github.com/ultimatekarate/phalanx/actions/workflows/android-build.yml/badge.svg)](https://github.com/ultimatekarate/phalanx/actions/workflows/android-build.yml)
[![iOS](https://github.com/ultimatekarate/phalanx/actions/workflows/ios-build.yml/badge.svg)](https://github.com/ultimatekarate/phalanx/actions/workflows/ios-build.yml)

Phalanx is a mobile-first, peer-to-peer forensic evidence system that makes the truth expensive to suppress and dignity expensive to violate.

## How It Works

Phalanx is deliberately designed to look boring. When you open it, it will look like a basic recording application. It functions exactly as you would expect it to, except it is much more robust and secure. The moment you hit record your data is being encrypted, digitally signed, sharded and stored in a distributed file system. You are the only person who decides who gets to see it. You don't have to worry if your device is seized or destroyed. You will always be able to recover your data — BIP39 mnemonics aren't just for cryptobros anymore. Phalanx also creates a digital chain of custody. It allows you to trust that the video you are seeing is true, not an AI deep fake, without trusting the person who recorded it.

## Capabilities

- **Real-time capture-to-mesh pipeline** — The moment you hit record, every frame is analyzed for authenticity, encrypted, split into redundant shards, and distributed across the mesh. The pipeline adapts frame rate to device load so it never drops evidence under pressure
- **Ad hoc mesh network** — Devices form a self-organizing peer-to-peer network over QUIC, Bluetooth, and WiFi Direct with no infrastructure dependency
- **Trusted communities** — Groups of people who vouch for each other. A quorum of existing members must approve new members. Communities expire automatically and leave no trace when dissolved
- **Selective sharing** — You control who can view your recordings. Access is granted per-recipient through key exchange — no central server decides who sees what. Data is encrypted separately in transit and at rest
- **Fountain-coded sharding** — Recordings are split into redundant pieces so that any sufficient subset can reconstruct the original. Pieces can arrive in any order — formally proven in Lean 4
- **Cryptographic forgetting** — When you delete a recording, it is gone forever. The encryption key is destroyed before the data is removed — if the device dies mid-deletion, the key is already gone and the ciphertext is permanently unreadable. Deletion propagates across the entire mesh
- **Silent Canary** — A dead man's switch for your community. If members go dark, encrypted alerts notify the group about which peers disappeared and which recordings may be at risk. A seized device cannot reveal the community roster
- **Adaptive resource management** — The system continuously monitors CPU, memory, bandwidth, storage, and battery. When any resource is strained, it gracefully reduces throughput rather than crashing or dropping data
- **Byzantine peer detection** — Nodes that lie about their state are mathematically detectable. The system's resource signals are coupled in a way that cannot be independently faked — dishonest claims are internally inconsistent
- **Proven stability** — The adaptive control system is formally proven to remain bounded under adversarial conditions. No combination of malicious input can drive a node into an unstable state
- **Compile-time evidence integrity** — Evidence passes through verified → sealed states enforced by the type system. Code that skips a verification step does not compile
- **Formal verification** — Lean 4 proof that evidence reconstruction produces identical output regardless of the order pieces arrive

## Security Posture

Phalanx assumes zero trust at every boundary. No peer, device, or network path is trusted by default.

- **Every envelope is signed and verified** — evidence carries Ed25519 signatures from capture through reassembly. Nothing is accepted on claim alone.
- **Every payload is encrypted in transit and at rest** — two independent XChaCha20-Poly1305 layers with distinct keys
- **Every peer earns trust** — reputation scoring tracks invalid signatures, quota violations, and protocol deviations. Misbehaving peers are demoted or blocked.
- **Byzantine actors are mathematically detectable** — fabricated state is exposed via Jacobian analysis of the coupled integral system
- **Key material is ephemeral where possible** — ECDH grants use per-session derivation, stack intermediates are zeroized, community keys dissolve on expiration
- **The compiler enforces the posture** — workspace deny lints eliminate `unwrap`, `panic`, unchecked indexing, arithmetic overflow, and lock-holding-across-await at compile time. These are not conventions — they are build failures.

## Emergent Properties

The adaptive control system produces behaviors that were never explicitly programmed:

- **Self-healing** — There is no recovery logic. When load drops, the system naturally returns to full throughput on its own. Recovery is a side effect of how pressure decays over time.
- **Natural load shedding order** — Under stress, untrusted peers are shed first, then bandwidth-heavy work, then memory, then storage, then CPU. Nobody wrote this priority list — it falls out of how the resource signals are coupled to each other.
- **Sybil resistance with diminishing returns** — Each additional fake peer an attacker adds is less effective than the last. Overwhelming the system requires flooding bandwidth, not just creating identities.
- **Anticipatory memory pressure** — When storage backs up, memory pressure rises even before anything new is allocated. The system senses that writes are queuing and preemptively constrains upstream work.
- **Thermal throttling as a natural consequence** — Heat enters the same pressure system that governs everything else. A phone that overheats throttles itself the same way it throttles a network attack.

## Architecture

The codebase is governed by a [Linguistic Code Model](linguistic-code-model.md) that partitions all code by linguistic role. It's essentially what happens when you combine functional core, imperative shell with Apollo-era DSKY applied to architecture — and use the Rust compiler to give it actual teeth. Crate boundaries are structural — the compiler enforces them, not convention.

| Crate | Role | Description |
| --- | --- | --- |
| `phalanx-proto` | Dictionary (Nouns) | Data types, trait contracts, error types. No IO. |
| `phalanx-forensics` | Laboratory (Verbs) | Verification, validation, state machines, crypto. No `tokio::fs`. |
| `phalanx-transport` | Post Office (Prepositions) | Network adapters, routing, peer mapping, wire codecs. |
| `phalanx-node` | Sentence | Actors, persistence, orchestration. Environment-dependent. |
| `phalanx-lens` | Optics | Camera and media capture pipeline. |
| `phalanx-ffi` | FFI Bridge | C ABI surface for iOS and Android. |
| `phalanx-stronghold` | Vault | At-rest encrypted storage for witness envelopes. |
| `phalanx-sim` | Simulator | Network simulation and adversarial testing. |
| `phalanx-test-fixtures` | Phrasebook | Synthetic test data satisfying validation preconditions. |

## Lint Governance

The workspace enforces deny-level clippy lints across all crates — `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`, `cast_possible_truncation`, `cast_sign_loss`, `cast_possible_wrap`, `float_cmp`, `await_holding_lock`, and `undocumented_unsafe_blocks`. See [`linguistic-code-model.md` § II](linguistic-code-model.md#ii-structural-enforcement) for the full annotated list and `Cargo.toml` for the source of truth.

## Contributing

Phalanx is conceptually dense. I have gone to great lengths to ensure that you do not need to understand all of it to contribute to any of it. If you are interested, please read [the guide for contributing](CONTRIBUTING.md). There you will find the code base broken down by technical specialty with a list of files and a brief summary of what each file does.

## Build

```bash
cargo build --workspace
```

Minimum Rust version: **1.93.1**

## Test

```bash
cargo test --workspace
```

## Background

This is started as a way to use AI tools to learn Rust and it rapidly got out of hand. This is also my first mobile application. I cut my teeth learning QBASIC and writing C++ in notepad- not because I'm especially hardcore, but because it was what was available to me at the time. I've spent the past few year writing Python code professionally. I wouldn't describe myself as a 10x engineer. Truth be told, I am jealous of those that can whip through code at lightning speed with VIM keybindings. I wish I could but I've broken, dislocated, or sprained every single one of my fingers- it's the price you pay to be a middle blocker in volleyball. I call my right index finger my "weather finger." My bottleneck has never been ideas. It's always been syntax and keystrokes. Phalanx is 100% my ideas and roughly 10% of my keystrokes.

I'm not an expert in any of the fields you see in this repo (Well, I do have a PhD in numerical analysis so there's that) but I don't have to be because I can RTFM. The nerds of yore knew that there would come a time when someone else would need invoke the deep magic. That's why they wrote it down. There are some genuinely novel ideas in this code base, but for the most part it is an act of synthesis that is heavily influenced by Grace Hopper and Margaret Hamilton.

Grace Hopper believed that the language should be the logic. She dared to believe that the machines should meet the humans where they are- that's why we have compilers. Margaret Hamilton, the woman who coined the phrase 'software engineering', believed that software deserved the same level of rigor as the hardware that it ran on. Both were dismissed and they built the thing anyway- and they were right to do it. I'm not Grace Hopper. I'm not Margaret Hamilton. I'm just someone that had an idea that they wanted to try out- and now the world has Phalanx. Use it or don't. Hopefully, at least one person will find it useful.

## License

Patent pending.
