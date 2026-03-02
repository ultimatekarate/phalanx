// crates/phalanx-transport/src/signaling.rs
//
// Re-export the canonical NetworkEvent from the Dictionary.
// Any transport-specific signaling extensions should be added here.
pub use phalanx_proto::network::NetworkEvent;
