use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::evidence::WitnessEnvelope;
use crate::identity::{Did, RecordingId};
use crate::prelude::{MeshTopic, NetworkId};
use crate::retrieval::{RecordingRequest, RecordingResponse};
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
    /// BLE mutual auth: challenge received from a LocalMesh peer.
    /// MeshSentinel should verify and respond, or drop the connection.
    BleAuthChallengeReceived {
        peer: NetworkId,
        challenge: BleChallenge,
    },
    /// BLE mutual auth: response received from a LocalMesh peer.
    /// MeshSentinel should verify against the pending challenge nonce.
    BleAuthResponseReceived {
        peer: NetworkId,
        response: BleResponse,
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

// ── Transport Capability Contracts ────────────────────────────────────────
//
// These are Nouns (capability contracts) — they define the shape of network
// interaction. Implementations live in phalanx-transport (adapters) and
// phalanx-node (actors).

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("Network failure: {0}")]
    Network(String),

    #[error("Serialization failure: {0}")]
    Serialization(String),

    #[error("Protocol violation: {0}")]
    Protocol(String),

    #[error("Internal violation: {0}")]
    Internal(String),
}

#[async_trait]
pub trait IngressPort: Send {
    async fn next_event(&mut self) -> Option<NetworkEvent>;
}

#[async_trait]
pub trait EgressPort: Send + Sync + Clone {
    async fn publish(&self, topic: &MeshTopic, data: Vec<u8>) -> Result<(), String>;
    async fn ban_peer(&self, peer: &NetworkId);
    async fn send_response(
        &self,
        channel_id: &str,
        response: RecordingResponse,
    ) -> Result<(), String>;
    /// Announce this node as a provider for a specific recording on the DHT.
    async fn announce_recording(&self, recording_id: &RecordingId) -> Result<(), String>;
    /// Initiate a DHT query to find providers for a specific recording.
    async fn find_providers(&self, recording_id: &RecordingId) -> Result<(), String>;
    /// Send a shard retrieval request to a specific peer.
    async fn send_request(
        &self,
        target: &NetworkId,
        request: RecordingRequest,
    ) -> Result<(), String>;

    /// Disconnect a specific peer (eclipse remediation).
    /// Default: delegates to ban_peer (existing mechanism).
    async fn disconnect_peer(&self, peer: &NetworkId) {
        self.ban_peer(peer).await;
    }

    /// Re-dial bootstrap peers and trigger a Kademlia random walk.
    /// Default: no-op (transports that don't support this ignore the request).
    async fn rebootstrap(&self, _peers: &[String]) -> Result<(), String> {
        Ok(())
    }
}

/// Abstraction for local peer-to-peer transports (BLE, WiFi Direct).
///
/// For truly disconnected scenarios (no WiFi network — outdoors, disaster zone, protest),
/// each platform injects its own implementation via FFI during mobile integration.
/// Desktop and non-BLE platforms use NoOpLocalMesh (always unavailable).
#[async_trait]
pub trait LocalMeshPort: Send {
    /// Discover peers reachable via this local transport (BLE, WiFi Direct).
    async fn discover_peers(&mut self) -> Vec<NetworkId>;

    /// Send data directly to a specific peer via the local transport.
    async fn send_local(&self, target: &NetworkId, data: Vec<u8>) -> Result<(), TransportError>;

    /// Poll for the next inbound event from the local transport.
    async fn next_local_event(&mut self) -> Option<NetworkEvent>;

    /// Whether this local transport is available on the current platform.
    fn is_available(&self) -> bool;
}
