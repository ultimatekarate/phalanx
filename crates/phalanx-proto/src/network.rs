use serde::{Deserialize, Serialize};

use crate::evidence::WitnessEnvelope;
use crate::identity::{Did, RecordingId};
use crate::prelude::{MeshTopic, NetworkId};
use crate::retrieval::RecordingRequest;
use crate::telemetry::DiscoverySource;
use crate::topology::{SubnetBucket, TransportClass};

pub const RETRIEVAL_PROTOCOL_ID: &str = "/phalanx/retrieval/1.0.0";
pub const DISCOVERY_TOPIC_ID: &str = "/phalanx/discovery/1.0.0";

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    DataReceived {
        origin: NetworkId,
        topic: MeshTopic,
        data: Vec<u8>,
    },
    /// A new peer was discovered on the mesh.
    /// `source` indicates HOW it was discovered — mDNS (local) vs Kademlia/Bootstrap (internet).
    /// `bucket` is the /16 subnet bucket (populated from Multiaddr by the Hands).
    /// `transport` classifies the discovery source as Internet or LocalMesh.
    /// The MeshSentinel uses this to enforce topology-aware admission via TopologyGate.
    PeerDiscovered {
        peer: NetworkId,
        source: DiscoverySource,
        bucket: SubnetBucket,
        transport: TransportClass,
    },
    RecordingRequested {
        origin: NetworkId,
        request: RecordingRequest,
        channel_id: String,
    },
    /// DHT providers discovered for a recording.
    ProvidersDiscovered {
        recording_id: RecordingId,
        providers: Vec<NetworkId>,
    },
    /// Shards received from a peer in response to a recording request.
    ShardResponseReceived {
        origin: NetworkId,
        envelopes: Vec<WitnessEnvelope>,
    },
    /// A previously-connected peer has disconnected.
    /// Emitted by transports that maintain persistent connections (e.g., QuicAdapter client).
    PeerDisconnected {
        peer: NetworkId,
    },
    Shutdown,
}

// ── BLE Mutual Authentication ───────────────────────────────────────────

/// BLE challenge: "I am A, prove you're B."
/// Sent as the first message in the 4-message handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BleChallenge {
    pub sender_did: Did,
    /// 32-byte random nonce for replay protection.
    pub nonce: [u8; 32],
}

/// BLE response: "I am B, here's proof."
/// Ed25519 signature over (responder_did || challenger_did || challenge_nonce).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BleResponse {
    pub responder_did: Did,
    /// Ed25519 signature proving DID ownership.
    /// Covers: (responder_did || challenger_did || challenge_nonce).
    pub signature: Vec<u8>,
}
