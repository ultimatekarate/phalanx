# Phalanx — Agent Context

## Architecture

Phalanx is a distributed forensic evidence provenance system. The codebase follows a linguistic model documented in `linguistic-code-model.md` at the repo root. Read it before making architectural decisions. The full crate inventory and role mapping is in [`README.md` § Architecture](README.md#architecture) and [`linguistic-code-model.md` § VIII](linguistic-code-model.md#viii-crate-reference). The key partition: **phalanx-proto** (Dictionary/Nouns, no IO) → **phalanx-forensics** (Laboratory/Verbs, no tokio::fs) → **phalanx-transport** (Post Office) → **phalanx-node** (Sentence, environment-dependent).

## Conventions

**Constructors use semantic suffixes.** `new_ephemeral()`, `new_verified()`, `new_validated()` are intentional — the suffix documents the construction invariant. Do not assume `new()` exists. Always read the actual method signature from the source file before referencing it in plans or code.

**Traits that define capabilities are Nouns.** `TransientJournal`, `TrustedClock`, `WireBound` live in phalanx-proto, not in the crates that implement them.

**The prelude contains only first-class Nouns.** Persistence contracts (`TransientJournal`), scheduling types (`PendingEgress`), and operational state are imported directly from their defining module, not via prelude.

## Working with this codebase

- Read `linguistic-code-model.md` for the full architectural governance rules.
- Always `cargo clippy --workspace --all-targets -- -D warnings` after structural changes.
- Always `cargo test --workspace` before considering work complete.
- When referencing a method signature in a plan, read the actual definition first. Do not infer constructor names from type names.
