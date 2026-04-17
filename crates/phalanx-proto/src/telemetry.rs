use crate::identity::NetworkId;
use crate::identity::RecordingId;
use crate::prelude::ShardChunk;
use crate::types::{ByteCapacity, UnitInterval, VitalityRate};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub enum ChaosMode {
    Stable,
    PacketLoss(f32),
    HighLatency(u64),
    Byzantine,
    Hyperactive,
    /// Peer stored data honestly but returns an empty set on retrieval.
    /// Models a peer that drops evidence on request (silent faulty).
    /// Applied at the retrieval boundary by the sim harness, not at
    /// the publish/route layer.
    OmitStored,
    /// Peer returns its real stored envelopes, but with the first byte
    /// of each envelope's `witness_signature` XOR'd. Models on-disk
    /// corruption or retrieval-path tampering. Applied at the retrieval
    /// boundary by the sim harness.
    CorruptStored,
    /// Peer returns **only** forged envelopes — no honest data — to
    /// maximise the attacker's chance of slipping a forgery past
    /// soundness checks. The helper returns two forgery flavours per
    /// retrieval (fresh-identity and identity-claim). Forger identities
    /// are generated per retrieval so tests don't need to plumb keys.
    /// Applied at the retrieval boundary by the sim harness.
    ForgeSigner,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum DiscoverySource {
    Bootstrap,
    Kademlia,
    Mdns,
    Identify,
    Quic,
    LocalMesh,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SimEvent {
    ChunkIngested {
        origin: NetworkId,
        chunk: ShardChunk,
    },
    Heartbeat {
        origin: NetworkId,
        uptime: u64,
        health: VitalityRate,
    },
    OffloadComplete {
        origin: NetworkId,
        target: NetworkId,
        size: ByteCapacity,
    },
    PeerDiscovered {
        peer: NetworkId,
        source: DiscoverySource,
        role: crate::identity::NodeRole,
    }, // Note: Role included for dashboard telemetry
    ShardProcessed {
        peer_id: NetworkId,
        byte_size: ByteCapacity,
    },
    CrucibleFinalized {
        recording_id: RecordingId,
    },
    AttackAttemptBlocked {
        attacker: NetworkId,
        target: NetworkId,
        reason: String,
    },
    SystemStressUpdate(UnitInterval),
    Shutdown,
    ChaosUpdate {
        target: NetworkId,
        mode: ChaosMode,
    },
    ShardPublished {
        origin: NetworkId,
        chunk: ShardChunk,
    },
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn chaos_mode_variants_are_distinguishable_in_serde() {
        // Regression guard: if someone accidentally adds #[serde(other)] or
        // duplicates a tag, CorruptStored and OmitStored would collapse into
        // one variant and chaos simulations would silently misfire.
        let corrupt_bytes = postcard::to_allocvec(&ChaosMode::CorruptStored).expect("ser corrupt");
        let omit_bytes = postcard::to_allocvec(&ChaosMode::OmitStored).expect("ser omit");
        assert_ne!(corrupt_bytes, omit_bytes);

        let corrupt_recovered: ChaosMode =
            postcard::from_bytes(&corrupt_bytes).expect("de corrupt");
        let omit_recovered: ChaosMode = postcard::from_bytes(&omit_bytes).expect("de omit");
        assert_eq!(corrupt_recovered, ChaosMode::CorruptStored);
        assert_eq!(omit_recovered, ChaosMode::OmitStored);
    }

    #[test]
    fn chaos_mode_packet_loss_fraction_roundtrips() {
        // Payload-carrying variants are the real regression risk — they roundtrip
        // the inner f32 through postcard, and a silent bincode/postcard mismatch
        // here would corrupt chaos injection.
        let original = ChaosMode::PacketLoss(0.37);
        let bytes = postcard::to_allocvec(&original).expect("serialize");
        let recovered: ChaosMode = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(recovered, original);
    }

    #[test]
    fn sim_event_heartbeat_preserves_origin_and_uptime() {
        use crate::types::VitalityRate;
        let origin = NetworkId("node-alpha".into());
        let original = SimEvent::Heartbeat {
            origin: origin.clone(),
            uptime: 9_999_u64,
            health: VitalityRate::new(5_000),
        };
        let bytes = postcard::to_allocvec(&original).expect("serialize Heartbeat");
        let recovered: SimEvent = postcard::from_bytes(&bytes).expect("deserialize Heartbeat");

        match recovered {
            SimEvent::Heartbeat {
                origin: recovered_origin,
                uptime,
                health: _,
            } => {
                assert_eq!(recovered_origin, origin);
                assert_eq!(uptime, 9_999_u64);
            }
            other => panic!("expected Heartbeat variant, got {other:?}"),
        }
    }
}
