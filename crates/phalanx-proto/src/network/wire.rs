// crates/phalanx-proto/src/wire.rs
//
// Gate 0b: Wire Bound — Post-Deserialization Semantic Validation.
//
// Types received over the wire implement this trait to enforce structural
// invariants that survive deserialization: Vec length caps, value range
// checks, etc. A noun-level contract — "I know my own bounds."
//
// Composed with `unmarshal` via `unmarshal_checked` in the Laboratory
// (phalanx-forensics/src/gate.rs).

/// Structural self-validation for wire-deserialized types.
///
/// Implementors declare the invariants that raw deserialization cannot
/// enforce — e.g., maximum Vec lengths, value ranges, field consistency.
/// Called automatically by `unmarshal_checked` after postcard decoding.
pub trait WireBound {
    /// Enforce structural bounds, truncating or clamping as needed.
    /// This is a correction, not a rejection — the type is valid after
    /// this call, just trimmed to safe limits.
    fn enforce_wire_bounds(&mut self);
}
