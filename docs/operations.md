# Phalanx Operations — deploying and running it

This is the operator's manual: what runs today, how to stand up a [Stronghold](architecture.md#glossary), how to run
community ceremonies, what a phone fleet needs before production, and how to acceptance-test a deployment. It assumes
you have read [architecture.md](architecture.md) for vocabulary, [network.md](network.md) for topology and wire
behavior, and [trust.md](trust.md) for identity and key mechanics. Like those documents, every operational claim here
is anchored to source; design decisions are stated as decisions, and development placeholders are listed as checklist
items, not alarms.

## 1. What you can run today

**Platform matrix:**

| Platform | State | Anchors |
|---|---|---|
| Android phone app | **Works — build from source only.** No published APK; release builds are currently signed with the debug key. A fresh clone cannot build the app without help: `.gitignore` line 17 (`flutter_app/*`) leaves only 21 of the app's files tracked, and the tracked `main.dart` imports screens and services that are not in the repository. | `flutter_app/android/app/build.gradle:57-61`, `.gitignore:17`, `flutter_app/lib/main.dart:11-27` |
| iOS | **A library without an app.** The build script produces static libraries for `aarch64-apple-ios` (+ simulator) on macOS, and the FFI loader supports iOS via `DynamicLibrary.process()` — but only `flutter_app/ios/build_rust.sh` is git-tracked; the Xcode Runner project exists only on the author's machine. Deployment-target metadata also disagrees (`build_rust.sh` says iOS 14+, CI sets 15.0). | `scripts/build_mobile.sh:116-121`, `flutter_app/lib/ffi/library_loader.dart:8-18`, `flutter_app/ios/build_rust.sh:10`, `.github/workflows/ci.yml:104` |
| Desktop `sentinel` | **Headless node with stubbed capture.** The full transport, storage, homeostasis, and actor stack is real; the camera driver is an explicit `[STUB]` mock that synthesizes 640×480 noise frames (the comment names `nokhwa` as the intended real backend). Useful for mesh/custody plumbing tests, not for capturing real evidence. | `crates/phalanx-node/src/hardware/camera.rs:130-146` |
| Stronghold (`stronghold` CLI) | **Works.** The custody/corroboration/export daemon this document centers on (§2). | `crates/phalanx-stronghold/src/bin/stronghold.rs` |
| Stronghold GUI (`stronghold-gui`) | Builds behind the non-default `gui` feature (`cargo build -p phalanx-stronghold --features gui`); diverges from the CLI in config handling (§2). | `crates/phalanx-stronghold/Cargo.toml:15-18` |

**Connectivity matrix** — the full deployment-shape analysis is [network.md §8](network.md#8-deployment-shapes); this
table adds only the operational caveats:

| Deployment | Status | Operational caveats |
|---|---|---|
| Solo phone | Works | Capture, verification, encrypted local vault, signed envelope chain. No replication — see §6 and §8 for what that means. |
| Phones on one LAN | Works on a desktop/laptop network; **UNTESTED on Android** | Discovery is mDNS-only. The Android manifest omits `CHANGE_WIFI_MULTICAST_STATE` (`flutter_app/android/app/src/main/AndroidManifest.xml:5-21`), which Android generally requires to receive multicast packets — so on-device mDNS discovery is likely non-functional; the permission absence is verified, the runtime consequence has not been tested on a device. (`AndroidManifest.xml:5-16`) |
| Phones + Stronghold | **Blocked from the shipped app; works via the desktop sentinel** | Directed archive push requires `[[network.archival_peers]]` in the node's TOML, but the shipped app never loads a config file — `main.dart` calls the bridge without the optional `configPath`, so the engine always runs compiled defaults (`flutter_app/lib/main.dart:116`, `crates/phalanx-ffi/src/handle.rs:211-227`). Passive gossip collection works at compiled defaults since the June 2026 topic-alignment fix (§5); directed push still requires the config block. Today this shape is exercised with a `sentinel` node configured via `PHALANX_CONFIG`, or after a one-line app change to pass `configPath`. |
| Cross-network | Works with explicit addresses | No automatic NAT traversal ([network.md §2](network.md#2-transports)); at least one side needs a reachable address. |
| Background recording on Android | **Out of scope — by design** | Capture is foreground/screen-on only. Backgrounding drops the node to Dormant — the intended homeostatic response (`flutter_app/lib/main.dart:270-286`). Screen-off "record from the pocket" would require a foreground service, whose mandatory persistent notification undercuts the very discretion it would serve, so it was deliberately not built and the unused `FOREGROUND_SERVICE*` permissions were dropped from the manifest. |
| BLE / WiFi-Direct off-grid mesh | Not implemented | The Rust seam is complete and tested — recording-bound BLE auth, an anti-sybil admission cap, and proximity-to-corroboration egress — but no radio code exists on the Flutter side ([network.md §6](network.md#6-local-mesh-ble--wifi-direct)). |

## 2. The Stronghold runbook

The Stronghold is the wall-powered custody and export node — the durable leg of the
[seizure asymmetry](architecture.md#the-seizure-asymmetry). One binary, eight subcommands
(`crates/phalanx-stronghold/src/bin/stronghold.rs:41-118`): `run`, `import-community`, `communities`, `recordings`,
`corroborate`, `vouch`, `export`, `create-community`. Global flags: `-c/--config` (default `stronghold.toml`) and
`--data-dir` (highest-precedence data-root override).

**Prerequisites.** A Rust toolchain ([README § Build](../README.md#build)); a host with disk for the evidence quotas
you configure (compiled default cap: 100 GiB); a stable, reachable listen address if phones will push to it. The
Stronghold always builds `phalanx-forensics` with the `software-transcode` feature
(`crates/phalanx-stronghold/Cargo.toml:25-26`), so its exports work on every platform — no codec caveats here, unlike
mobile (§4).

### The passphrase

`PHALANX_IDENTITY_PASSPHRASE` is required by exactly the subcommands that touch the sealed identity — `run`,
`corroborate`, `vouch`, `export`. Without it they fail with `PHALANX_IDENTITY_PASSPHRASE not set. Export it before
running.` (`bin/stronghold.rs:650-654`). `import-community`, `communities`, `recordings`, and `create-community`
never load the identity and work without it (`bin/stronghold.rs:147-231`). Use a systemd `EnvironmentFile` or a
secrets manager; do not put it in shell history.

**First run** generates a fresh identity (`PhalanxIdentity::new_ephemeral()`), seals it with Argon2 +
XChaCha20-Poly1305 to `{vault}/stronghold_identity.bin`, and prints `New identity generated: did:key:...`
(`bin/stronghold.rs:658-676`). Record that DID — phones reference it as `stronghold_did`. On later runs a wrong
passphrase fails with `Failed to decrypt identity: ...`.

**Losing the passphrase is losing the identity.** Unlike the phone, the Stronghold identity has no recovery mnemonic
— `new_ephemeral()` produces none. A re-generated identity is a new DID: every phone config naming the old
`stronghold_did` goes stale, export grants sealed to the old DID can never be unlocked, and old custody receipts
remain verifiable but the daemon can no longer act on the holdings they describe. Back the passphrase up with the
same care as the vault.

### Annotated `stronghold.toml`

A Stronghold config is a `profile` selector plus optional `[instance.*]` tables
(`crates/phalanx-stronghold/src/config.rs`). A **missing file** falls back to the default Stronghold profile
(`community_with_stronghold`) with a stderr note; a **present-but-invalid or incoherent** file is a hard error — the
same loud polarity as the node ([network.md §9](network.md#9-config-truth-table)). A profile with no Stronghold role
(e.g. `solo_device`) is rejected with a named error (`ProfileHasNoStrongholdRole`). All tables use
`deny_unknown_fields`, so a typo — or a profile-pinned key such as `protocol_version` placed under
`[instance.network]` — is a parse error, not a silent revert. The pinned values (topics, protocol version, PSK
posture) are projected from the profile and are not settable here.

```toml
# stronghold.toml — complete annotated example.
# Field semantics: crates/phalanx-stronghold/src/config.rs

# The deployment topology. Omitted => community_with_stronghold. Must be a
# Stronghold-bearing profile; solo_device / affinity_group_lan are rejected.
profile = "community_with_stronghold"

[instance.storage]
# Optional, default "./stronghold-data" (treated as *unset* by the path
# resolver). Root for identity, communities, evidence, custody, proofs, exports.
# Overridden by --data-dir and PHALANX_STRONGHOLD_HOME (precedence below).
vault_path = "/srv/phalanx/stronghold"
# Optional, default 100 GiB. Global evidence cap in bytes.
max_storage_bytes = 107374182400
# Optional, default 20 GiB. Per-community quota.
max_per_community_bytes = 21474836480
# Optional, default 2147483648 (2 GiB): absolute per-owner custody ceiling.
max_bytes_per_owner = 2147483648
# Optional, default 0.25. Effective per-owner share under contention =
# min(max_bytes_per_owner, max_per_community_bytes * owner_fair_share_ratio).
owner_fair_share_ratio = 0.25
# Optional, default 604800 (7 days): how long a directed-push recording is held
# before the custody sweep may reclaim it. Values below 60 are clamped up at
# load with a stderr warning ("Config: custody_ttl_secs below its minimum —
# clamped to the safe floor."). The GUI skips this clamp (divergence below).
custody_ttl_secs = 604800
# Optional, default 120: a grant-bearing recording is auto-exported once no new
# push for it has arrived for this many seconds. 0 DISABLES autonomous export.
export_quiescence_secs = 120
# Optional, default unset => {vault}/exports. Point at an archival mount in
# production; the sink is deliberately a sibling of evidence/, never under it,
# so custody reclaim can never delete a delivered artifact.
export_path = "/mnt/archive/phalanx-exports"
# Optional, default false: reclaim the custody copy early after a successful
# autonomous export instead of holding to TTL.
release_custody_after_export = false

[instance.network]
# Optional, default "/ip4/0.0.0.0/tcp/0". Pin a port: the ephemeral default
# changes every restart and is useless as a push target — a custody-bearing
# profile warns when it sees only an ephemeral listen port. Default is TCP-only;
# add a /udp/<port>/quic-v1 address to accept inbound QUIC (network.md §8).
listen_addresses = ["/ip4/0.0.0.0/tcp/4001"]
# Optional, default []. Dialed once at startup, best-effort.
bootstrap_peers = []
# NOTE — there are no video_topic/audio_topic/protocol_version keys. They are
# PROFILE-PINNED (projected from the DeploymentProfile, identical to the node)
# and structurally absent here; setting one is a deny_unknown_fields parse
# error. The mesh runs a small fixed set of well-known topics by design.
# See network.md §3, §5.

[instance.corroboration]
# Optional, default 5000. Minimum temporal overlap between recordings, ms.
min_overlap_ms = 5000
# Optional, default 0.05. KS-test alpha for divergence detection.
divergence_alpha = 0.05
# Optional pair: CA-issued C2PA signing material. BOTH must be set, or the
# export signer falls back to a self-signed X.509 cert built from the
# Stronghold's identity key — validators report it as untrusted, which is
# honest: the forensic data, not a CA, is the trust anchor
# (crates/phalanx-stronghold/src/signing.rs:15-53). NOTE: these files are
# honored only by the CLI `stronghold export` path; the AUTONOMOUS export path
# always signs with the identity-derived self-signed cert
# (crates/phalanx-stronghold/src/ops/export.rs:26, src/actors/aggregation.rs:1160-1175).
# c2pa_cert_path = "/etc/phalanx/c2pa.crt"
# c2pa_key_path  = "/etc/phalanx/c2pa.key"
```

### Data root, addresses, and layout

**Data-root precedence** (`crates/phalanx-stronghold/src/paths.rs:18-75`), highest first: `--data-dir` flag →
`PHALANX_STRONGHOLD_HOME` → config `vault_path` *if it differs from the dev default* `./stronghold-data` → the
OS-correct platform data directory (`ProjectDirs("app","Phalanx","phalanx-stronghold")`, local — not roaming — data
dir). It fails loudly rather than falling back to the working directory.

**GUI divergence** — the GUI binary does *not* use this resolver: `DaemonBridge::launch` takes `vault_path` literally
(CWD-relative for the default), ignores `PHALANX_STRONGHOLD_HOME`, has no `--data-dir`, and falls
back to the default Stronghold profile when the file is missing (`crates/phalanx-stronghold/src/gui/bridge.rs:52-54`,
`:112-120`). It now goes through the same `assemble` path as the CLI, so the `custody_ttl_secs` clamp is applied (the
earlier divergence where the GUI skipped it is closed). A CLI-managed vault and a GUI-managed vault on the same machine are not the same directory unless you
make them so. The GUI also pre-fills (but does not require) the passphrase env var and wipes the typed buffer after
launch (`crates/phalanx-stronghold/src/gui/mod.rs:24-37`).

**The address phones must pin.** A phone (or sentinel) targets the Stronghold with a multiaddr that **must** end in
`/p2p/<peer-id>` — without that tail, `ArchivalPeer::peer_id()` returns `None` and the push is skipped with a warning
(`crates/phalanx-node/src/config.rs:112-122`, `crates/phalanx-node/src/actors/archive_coordinator.rs:152-158`). The
PeerId is derived from the same sealed Ed25519 identity (`crates/phalanx-transport/src/identity_ext.rs:16-23`), so it
is stable for the life of the identity — but no subcommand prints it today (a neutral checklist item; capture it once
from verbose libp2p logging or a peer's discovery output). Set `stronghold_did` alongside the address if you want
autonomous export: with the DID the publisher seals an export grant to the Stronghold; without it the push is
custody-only and the Stronghold holds ciphertext it cannot export (`config.rs:96-103`).

**On-disk layout** (`crates/phalanx-stronghold/src/persistence/evidence_store.rs:22-70`,
`src/persistence/proof_store.rs:43-57`):

```
{vault}/
  stronghold_identity.bin                      # Argon2-sealed identity
  communities/{community_hex}.community.bin    # imported rosters (envelope-wrapped)
  evidence/{community_hex}/{blake3(recording_id)}/shards/{seq}.bin
  custody/{blake3(recording_id)}.bin           # custody sidecars (written BEFORE shards)
  revoked.bin                                  # revoked-recording set (checked before any persist)
  proofs/{community_hex}/{proof_hash_hex}.bin
  exports/{blake3(recording_id)}.mp4 + .receipt.bin
```

Directory names hash the recording id (safe filenames, not reversible); all writes are atomic temp+rename
(`evidence_store.rs:98-119`). Custody entries from directed pushes expire after `custody_ttl_secs` and are reclaimed
by a 60-second maintenance sweep; gossip-collected recordings are retained indefinitely (held_until = `u64::MAX`) and
governed only by the fairness caps (`crates/phalanx-stronghold/src/actors/aggregation.rs:797-817`). Eviction is not
revocation — a reclaimed recording may be re-pushed.

**Logging:** both binaries log to stderr via `RUST_LOG` (`bin/stronghold.rs:122-126`). Ctrl-C on the CLI calls
`std::process::exit(0)` with no actor drain (`bin/stronghold.rs:264-269`) — acceptable because every persistence
write is atomic and reconciliation self-heals on the next boot (`aggregation.rs:471-562`).

## 3. Community operations

[Communities](trust.md#4-trusted-communities) are the routing and trust unit. The CLI lifecycle:

**1. Collect vouches.** Each member needs at least `quorum` vouches from *other* members. The Stronghold operator can
contribute its own with `stronghold vouch --member-did did:key:z... --community-id <64-hex> --joined-at <ms-epoch>
-o member.vouch` (requires the passphrase; prints `Vouch signed for ...` — `bin/stronghold.rs:594-625`).

**2. Assemble** with `stronghold create-community --name <1-64 chars> --quorum N --vouches vouches.toml
--joined-at 2026-06-12T17:00:00Z --expires-at 2026-07-12T17:00:00Z [--stronghold-did did:key:z...] -o community.bin`.
The vouches file shape (`bin/stronghold.rs:448-464`):

```toml
[[members]]
did = "did:key:z6Mk..."
[[members.vouches]]
voucher_did = "did:key:z6Mk..."
signature  = "<128 hex chars — 64-byte Ed25519 vouch signature>"
```

All invariants (quorum, expiry bounds, freshness, QR size budget) are enforced by
`phalanx_forensics::identity::assemble_community`; on success the CLI prints the community ID and **three share-ready
forms**: raw base64url, `phalanx://community/join#data=...`, and `https://phalanx.app/c/join#data=...`
(`bin/stronghold.rs:560-573`). Note the dependency: the Universal Link form only opens the app if **phalanx.app** is
reachable and serves the right `assetlinks.json`; otherwise Android degrades it to a non-verified chooser entry
(`flutter_app/android/app/src/main/AndroidManifest.xml:43-62`). The `phalanx://` custom scheme is registered only in
debug builds, deliberately (`flutter_app/android/app/src/debug/AndroidManifest.xml:1-27`). The payload rides in the
URI *fragment* so it never appears in server logs (`flutter_app/lib/services/community_link_service.dart:8-13`).

**3. Import everywhere.** Phones import via QR/link with a mandatory human-review confirm screen
(`flutter_app/lib/main.dart:173-236`); the Stronghold imports with `stronghold import-community -f community.bin`
(prints `Imported community: ...` — no passphrase needed). `stronghold communities` lists what is on disk.

> **The big caveat — import before you run.** The CLI daemon does **not** load communities from disk at boot:
> `cmd_run` has no import step, and the live `CommunityActor` starts with an empty map
> (`bin/stronghold.rs:238-275`, `src/actors/community.rs:93-102`). Only the **GUI** auto-imports
> (`src/gui/bridge.rs:84-89`, `:151-222`). A CLI daemon started before its communities are imported has an empty
> routing table: gossiped chunks from unknown DIDs are dropped and archive pushes are **Rejected**
> (`src/actors/aggregation.rs:369-376`). Correct order of operations: `import-community` (one process invocation per
> roster) → verify with `communities` → **then** `run`. After importing a *new* community, restart the daemon —
> nothing feeds the import into a running CLI process.

**The operations calendar:**

| Cadence | Task | Why |
|---|---|---|
| Monthly (or sooner) | Re-run the ceremony: new vouches, `create-community`, re-import everywhere, restart CLI daemons | Community lifetime is bounded at assembly — 5 minutes to **30 days** maximum. Expiry-as-rotation is the re-key mechanism, not an inconvenience ([trust.md §4](trust.md#4-trusted-communities)). |
| After any phone restart | Re-import the community token on that phone | Rosters are **RAM-only on mobile** by design — a seized phone's disk must not contain a who-knows-whom map (`crates/phalanx-node/src/trust.rs:186-188`, [trust.md §2](trust.md#2-the-key-hierarchy)). The token QR/link is the re-entry path. |
| On member compromise or device seizure | Dissolve and re-form with a fresh ceremony | Dissolution is local-only zeroization (`Community::dissolve()`); a past member can derive the old community's control-traffic keys forever from its static ID ([trust.md §10](trust.md#10-trust-boundaries)). The new ceremony — new ID, new keys, compromised member excluded — is the only true revocation of membership. |

## 4. The phone fleet

Build from source, per [README § Mobile](../README.md#mobile-android--ios--flutter) — not duplicated here. Two
build-environment notes: `scripts/build_mobile.sh:24` contains a hardcoded user-specific Flutter path you will need
to edit, and 32-bit ARM (`armeabi-v7a`) is deliberately excluded because `raptorq`'s NEON intrinsics are unstable
there (`flutter_app/android/app/build.gradle:82-119`). And the fresh-clone gap from §1 applies: most of the app's
Dart files are not in the repository.

**The production checklist** — current states are verified in source; none is hidden, all are TODO-marked or
documented decisions:

| Item | Current state | Production requirement |
|---|---|---|
| Identity-at-rest passphrase | Hardcoded `static const _devPassphrase = 'phalanx-mobile-dev'` (`flutter_app/lib/main.dart:62`), used for create, load, and restore flows. The TODO above it names the fix. | Hardware-keystore-backed key (Android Keystore / iOS Keychain via `flutter_secure_storage`). Until then, identity-at-rest encryption is only as strong as a string printed in this document. |
| `trust_registry.bin` | **Plaintext** postcard: peer DIDs, pet names, trust levels, reputation, blacklist (`crates/phalanx-node/src/trust.rs:509-518`). A deliberate, documented decision — persisted reputation is classified seizure-tolerable ([trust.md §2](trust.md#2-the-key-hierarchy)). | None required by the design. Review against your own threat model; coach users to choose non-identifying pet names (§8). |
| `swarm.key` (private TCP swarm) | Raw 32-byte file at `{base}/swarm.key`; wrong length is logged and **ignored**; missing means public swarm. A `generate_swarm_key` helper exists but nothing calls it (`crates/phalanx-node/src/psk.rs:1-42`). | Provision the 32-byte file out-of-band; set `require_psk = true` so a missing key is a startup failure, not a silent public fallback (`crates/phalanx-transport/src/factory.rs:61-69`). Remember the PSK covers only the TCP path ([network.md §2](network.md#2-transports)). |
| On-device C2PA export | Returns `NoEncoder` (−23): `software-transcode` is default-off in `phalanx-ffi` and **no build path enables it** — not `build_mobile.sh`, not gradle, not CI (`crates/phalanx-ffi/src/export.rs:232-237`, `crates/phalanx-ffi/Cargo.toml:45-52`). Fail-closed by design: the patent-encumbered codecs can never land in a FOSS build by accident (`crates/phalanx-forensics/Cargo.toml:50-64`). | Export via the Stronghold (which always has the feature), or build the FFI with `--features software-transcode`, or wire the planned platform-encoder path (MediaCodec/VideoToolbox). The UI already has a stable error code to say "export not available on this build". |
| Release signing | `signingConfig signingConfigs.debug // TODO: production signing key` (`flutter_app/android/app/build.gradle:57-61`) | A real keystore and signing config. |
| Background capture | Out of scope by design — foreground/screen-on capture only; the unused `FOREGROUND_SERVICE*` permissions were dropped from the manifest (§1) | None — deliberate. Discreet screen-off capture would need a foreground service, whose mandatory notification undercuts the discretion it would serve. |
| Android mDNS | `CHANGE_WIFI_MULTICAST_STATE` absent; no MulticastLock acquired — LAN discovery likely dead on Android (UNTESTED at runtime, §1) | Add the permission + MulticastLock, then verify two physical phones discover each other. |
| Thermal signal | Hardcoded 25 °C — "Default to 25C if unavailable" (`flutter_app/lib/main.dart:248-268`); device-RAM setter exists in the C ABI but is never called, so memory integrals use the reference-device fallback (`crates/phalanx-ffi/src/status.rs:139-159`) | Wire real thermal and RAM sources so the [homeostatic](homeostasis.md) integrals see the actual device. |
| `phalanx.app` domain | App Links (`autoVerify`) and the share-link forms assume the domain serves `assetlinks.json` (§3) | Host the domain artifacts, or strip the Universal Link form from training materials. |

## 5. Config-alignment footgun checklist

One consolidated table for the topic/protocol misalignments. Full mechanics:
[network.md §3](network.md#3-topics-who-publishes-who-listens) and [§5](network.md#5-the-dht). What remains:

| # | Footgun | Symptom | Remedy |
|---|---|---|---|
| 1 | `/phalanx/mesh/1.0.0` (Silent Canary alerts) is **deliberately publish-only** — no inbound alert handler exists yet, so it is in no subscribe list (doc comment on `orchestrator::subscribe_topics`, `crates/phalanx-node/src/network/orchestrator.rs`) | Canary *detection* is local and works; the encrypted alert *broadcast* is not received by anyone | None yet — the topic must be subscribed together with its handler. 
| 2 | Overriding `revocation_topic`: the field steers the subscribe list and inbound comparison, but publish sites hardcode `MeshTopic::revocation()` ([network.md §3](network.md#3-topics-who-publishes-who-listens)) | A custom value splits publish and receive onto different topics | Leave at default |
| 3 | Node TOML `deny_unknown_fields`: a typo, or a profile-pinned key under `[instance]`, is a parse error | **Resolved polarity**: a set-but-invalid `PHALANX_CONFIG` now **fails the node loudly** (no silent revert to defaults); unset selects the default profile | Validate the TOML; a malformed file aborts startup rather than silently diverging ([network.md §9](network.md#9-config-truth-table)) |


## 6. Failure modes as the user sees them

**"I recorded and nothing replicated."** Recording alone works by design — capture, verification, the encrypted
vault, and the signed envelope chain are all local. With no peers subscribed, every publish increments the
`no_peers_subscribed` counter and each failed bundle's symbols persist to the outbound WAL (16 MiB cap, 10 attempts,
recovered on restart — [network.md §7](network.md#7-delivery-semantics)). The evidence exists; it is just on one
seizable device (§8).

**"The frame rate dropped mid-recording."** That is the system working, not failing. Capture FPS is governed by the
[Volterra homeostasis integrals](architecture.md#glossary) — storage pressure, bandwidth, battery, thermal all lower
the target FPS so the device degrades smoothly instead of crashing ([homeostasis.md — the FPS self-regulation
loop](homeostasis.md#the-fps-self-regulation-loop)). Dropped inbound chunks under pressure are likewise counted
shedding, never blocking ([network.md §7](network.md#7-delivery-semantics)).

**"Is my recording safe yet?"** "Safe" means custody receipts. The archive coordinator records each verified signed
receipt against the recording and logs `Archive: custody confirmed at a Stronghold` with `replicas=N target=K`
(`crates/phalanx-node/src/actors/archive_coordinator.rs:178-200`). `target_replica_count` is profile-pinned —
`community_with_stronghold` sets K=1 (the single-Stronghold case), `high_risk_cross_border` sets K=2 — so it matches
the topology by construction rather than needing a hand-set value. Until that log line (or its UI surface) appears,
treat the recording as unreplicated.

**"The mesh looks healthy but nothing is arriving."** Publish failures are silent at the API — `publish()` returns
`Ok` on enqueue — and loud only in the always-on counters: `duplicate`, `signing_error`, `no_peers_subscribed`,
`message_too_large`, `transform_failed`, `all_queues_full`
(`crates/phalanx-transport/src/adapters/libp2p.rs:117-138`). Those counters are the operator's primary signal; they
also feed the homeostatic governor, so sustained transport loss shows up as reduced FPS. `no_peers_subscribed`
climbing on a topic that should have listeners is the signature of a §5 misalignment.

**"The Stronghold is up but rejects every push."** Almost always §3's big caveat: communities were not imported
before `run`. Unknown-DID chunks are dropped at the routing gate and pushes come back `Rejected`
(`aggregation.rs:608-660`, `:351-400`). Second suspect: the push multiaddr lacks its `/p2p/` tail (§2). Under genuine
overload, the Stronghold sheds instead of failing: ingestion sleep-throttles, the inbound channel (capacity 512)
drops with a warning, and a storage-pressure soft gate can drop an assembled recording
(`crates/phalanx-stronghold/src/sentinel.rs:157-181`, `aggregation.rs:873-943`).

## 7. Acceptance testing

### What `phalanx-sim` already proves

`phalanx-sim` is a library crate whose scenarios run as ordinary integration tests — `cargo test -p phalanx-sim`
(included in `cargo test --workspace`). It spawns **real** `MeshSentinel` actor constellations per node with
ephemeral identities and tempdir vaults, wired to a virtual transport with deterministic virtual time
(`crates/phalanx-sim/src/harness.rs:548-676`). Injectable chaos per node: packet loss, high latency, Byzantine,
hyperactive, plus retrieval-boundary compromise (silent omission, stored-data corruption, two flavors of forgery).
The suites cover: evidence survival against k silent/corrupting/forging/colluding peers with forgery rejected at all
k (`tests/evidence_byzantine_tolerance.rs`); replay, spoofed-DID, flood, eclipse, identity-churn, and black-hole
adversaries (`tests/adversarial_tests.rs`); homeostasis under sustained load, bursts, per-integral pressure
isolation, Sybil endowment shrink, hysteresis, and recovery from critical (`tests/scenarios.rs`); clock-skew,
oversized-blob, and unknown-sender defenses (dedicated suites). Known limits: the sim's egress **no-ops the
DHT/retrieval surface** (`harness.rs:123-149`), and `cargo test --workspace` exercises neither `software-transcode`
codepaths nor the Lean proofs — so simulation passing says nothing about export or provider discovery.

### Hardware-in-the-loop: two phones and a Stronghold

Honest preconditions: the phone legs exercise capture, ceremony, and LAN witnessing; the custody/corroborate/export
legs need a **configured node**, which today means a desktop `sentinel` with `PHALANX_CONFIG` (the shipped app loads
no config — §1) — its stub camera produces synthetic frames that still exercise the full signing, fountain-coding,
push, and export plumbing (§1). Sentinel TOML: `profile = "community_with_stronghold"` plus
`[[instance.network.archival_peers]]` with the Stronghold's `/p2p/` address *and* `stronghold_did`. The replica
target and protocol version are pinned by the profile — no longer hand-set (§5).

| Step | Action | Expected output |
|---|---|---|
| 1. Ceremony | Collect vouches; `stronghold create-community ...` | `Community assembled and serialized.` + ID, member count, and the three share forms (§3) |
| 2. Import — Stronghold | `stronghold import-community -f community.bin`; then `stronghold communities` | `Imported community: <name>` with ID and member count; the list shows it. **Before** step 3 |
| 3. Start daemon | `PHALANX_IDENTITY_PASSPHRASE=... stronghold run` | First run: `New identity generated: did:key:...` (record it), then `Stronghold daemon online — listening for shards` |
| 4. Import — phones | Scan the QR / open the link on both phones | The confirm screen appears (import is never silent — human review is required, `flutter_app/lib/main.dart:173-236`) |
| 5. Record + witness | Record on both phones on one LAN | The peer appears on the peers screen; gossiped media flows phone↔phone at defaults. On Android treat discovery as UNTESTED (§1) — a desktop sentinel on the LAN is the control |
| 6. Archive push | Record on the configured sentinel (or push from it) | Node log: `Archive: custody confirmed at a Stronghold` with `replicas=1 target=1`; shards land under `{vault}/evidence/...` |
| 7. Inventory | `stronghold recordings -c <community-hex>` | `<recording-id> — N artifacts, complete` (`gaps` means symbols are still missing) |
| 8. Corroborate | `stronghold corroborate -c <hex> --grants g1.bin --recordings r1 r2` — **minimum two** recording ids (`num_args = 2..`, `bin/stronghold.rs:63-64`), overlapping by ≥ `min_overlap_ms` | `Corroboration proof produced:` with proof hash, attestation/divergence/proximity counts, producer DID |
| 9. Export | `stronghold export --community <hex> --proof <hash-hex> --grants g1.bin -o ./export` — or wait `export_quiescence_secs` for the autonomous path | CLI: `Exported N file(s) to ./export`. Autonomous: `{vault}/exports/{blake3}.mp4` + `.receipt.bin` (a signed receipt over the blake3 of the MP4 bytes, `aggregation.rs:1095-1229`) |
| 10. Verify artifact | Run a C2PA validator (e.g. `c2patool`) over the MP4 | A valid manifest signed by `Phalanx Self-Signed Signer` (O=Phalanx) reported as an **untrusted** CA — expected unless you provisioned `c2pa_cert_path`/`c2pa_key_path` and exported via the CLI (§2) |

A failure at step 6 with `Rejected` means step 2 was skipped or done after step 3 (§3). A silent failure at step 5
with healthy phones is the Android multicast gap (§1) or a topic override on one peer (§5 row 2).

## 8. Witness safety annex

> **Draft — needs review by field practitioners before use in training.** This section translates the technical
> state into operational guidance for people who may be detained and have devices seized. It describes both the
> system *today* (development placeholders in place) and at *design intent*; the difference matters for safety
> decisions. Companion reading: [trust.md §10](trust.md#10-trust-boundaries) and
> [threat-model.md §17](threat-model.md#17-device-seizure-and-role-asymmetry).

**What a seized phone reveals — today vs. design intent.** The design treats the phone as seizable and keeps the
dangerous things off its disk: community rosters, the canary watch set, and witness lists live in RAM only
(`crates/phalanx-node/src/trust.rs:186-188`, `crates/phalanx-node/src/vitals/canary.rs:9-10`,
`crates/phalanx-node/src/actors/recording_session.rs:23`); media on disk is ciphertext. That part is true today. What is *not*
yet true: the identity file is sealed under the hardcoded development passphrase (§4), which is public knowledge —
so **today**, an examiner who reads this repository can open `identity.bin`, derive the recording keys, and decrypt
**that phone's own recordings**. The peer registry (DIDs, trust levels, and the pet names the user typed) is
plaintext by documented decision. At design intent — hardware-keystore sealing — the phone's own recordings are
protected by the device's hardware security, and what remains visible is the pseudonymous peer registry. Practical
guidance today: treat anything recorded on a phone as readable by whoever seizes that phone, and choose pet names
that identify nobody ("blue jacket", not a real name).

**Mnemonic custody.** At first run the app shows a 12-word recovery phrase once (genesis screen, then verification —
`flutter_app/lib/main.dart:296-387`). That phrase is the identity: it restores the account on a new device *and* it
is the **only** source of the revocation signing key — deleting a recording from the mesh
(`phalanx_forget_recording`) requires typing all 12 words, and both sides zero the buffer after use
(`crates/phalanx-ffi/src/forget.rs:60`). Write it on paper. Never photograph it with the phone, never store it in
the phone's notes or cloud account — a seized phone with its own mnemonic forfeits both protections at once.
Consider a trusted custodian (counsel, a steward abroad) holding a copy: whoever holds the words can both resurrect
the identity and erase its recordings, so pick someone you would trust with both powers.

**Recording vs. recording safely.** Recording alone produces evidence that exists only on the seizable device (§6).
Recording *safely* means replication before seizure: witnesses on the same network receiving symbols, and a
Stronghold confirming custody with a signed receipt. The honest checklist: until "custody confirmed" (§6), assume
the footage is at risk; a phone seized mid-recording loses what had not yet left it — the [seizure
asymmetry](architecture.md#the-seizure-asymmetry) is the design, and the Stronghold is the durable leg.

**When a device is seized.** Three actions, with today's caveats stated plainly:

1. **Revoke if appropriate.** Whoever holds that phone's 12 words can issue revocations for its recordings from a
   restored identity. Strongholds that receive a token persist it before deleting shards and refuse re-persistence
   (`crates/phalanx-stronghold/src/actors/aggregation.rs:298-323`). Since the June 2026 topic-alignment fix,
   revocation tokens propagate via gossip to default-configured peers; peers that were offline catch up via the
   replay sent on admission ([network.md §7](network.md#7-delivery-semantics)). Expect deletion to be eventual, not
   instantaneous, and weigh whether the footage should survive (revocation deletes evidence; sometimes the right
   call is the opposite one).
2. **Expect the canary to inform peers, not the world.** Devices that were watching the seized phone detect its
   disappearance locally and that detection works; the encrypted community-wide alert broadcast is deliberately
   publish-only until an inbound alert handler exists (§5 row 1). Pair the technical canary with a human protocol:
   a check-in schedule and a named person who acts when it is missed.
3. **Dissolve and re-form the community** (§3 calendar). The seized device held the roster in RAM — likely gone at
   power-off — but its membership token and control-traffic keys must be assumed compromised, and a past member can
   derive the old community's heartbeat/canary keys indefinitely ([trust.md §10](trust.md#10-trust-boundaries)). A
   fresh ceremony without the seized identity is the only clean cut.
