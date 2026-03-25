//! # Phalanx Test Fixtures — The Phrasebook
//!
//! Pre-composed test Nouns for cross-crate testing. This crate composes
//! Dictionary Nouns with Laboratory Verbs so that tests in the Hands
//! don't need to know the Laboratory's validation preconditions.
//!
//! **Linguistic Model:** See §IX in `linguistic-code-model.md`.
//!
//! **Constraint:** Dev-dependency only. No IO. No new Verbs. No new domain types.

pub mod chunks;
pub mod envelope;
pub mod metrics;
pub mod shards;
