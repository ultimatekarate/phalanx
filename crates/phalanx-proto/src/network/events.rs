use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::archive::{ArchiveReceipt, ArchiveRequest};
use crate::evidence::WitnessEnvelope;
use crate::identity::{Did, RecordingId};
use crate::prelude::{MeshAddress, MeshTopic};
use crate::retrieval::{RecordingRequest, RecordingResponse};
use crate::revocation::RevocationToken;
use crate::telemetry::DiscoverySource;
use crate::topology::{SubnetBucket, TransportClass};

pub const RETRIEVAL_PROTOCOL_ID: &str = "/phalanx/retrieval/1.0.0";
/// Unicast request/response protocol for directed evidence PUSH to an archival
/// Stronghold (the custody tier). Distinct from the pull-only retrieval protocol.
pub const ARCHIVE_PROTOCOL_ID: &str = "/phalanx/archive/1.0.0";

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    DataReceived {
        origin: MeshAddress,
        topic: MeshTopic,
        data: Vec<u8>,
    },
    /// A new peer was discovered on the mesh.
    /// `source` indicates HOW it was discovered — mDNS (local) vs Kademlia/Bootstrap (internet).
    /// `bucket` is the /16 subnet bucket (populated from Multiaddr by the Hands).
    /// `transport` classifies the discovery source as Internet or LocalMesh.
    /// The MeshSentinel uses this to enforce topology-aware admission via TopologyGate.
    PeerDiscovered {
        peer: MeshAddress,
        source: DiscoverySource,
        bucket: SubnetBucket,
        transport: TransportClass,
    },
    RecordingRequested {
        origin: MeshAddress,
        request: RecordingRequest,
        channel_id: String,
    },
    /// An inbound directed PUSH of evidence to be taken into custody.
    /// The responder (a Stronghold) admits, persists, and replies with an
    /// `ArchiveReceipt` over `channel_id`.
    ArchiveRequested {
        origin: MeshAddress,
        request: ArchiveRequest,
        channel_id: String,
    },
    /// A custody receipt received in reply to a `send_archive_request`.
    ArchiveReceiptReceived {
        from: MeshAddress,
        receipt: ArchiveReceipt,
    },
    /// DHT providers discovered for a recording.
    ProvidersDiscovered {
        recording_id: RecordingId,
        providers: Vec<MeshAddress>,
    },
    /// Shards received from a peer in response to a recording request.
    ShardResponseReceived {
        origin: MeshAddress,
        envelopes: Vec<WitnessEnvelope>,
    },
    /// A previously-connected peer has disconnected.
    /// Emitted by transports that maintain persistent connections (e.g., QuicAdapter client).
    PeerDisconnected {
        peer: MeshAddress,
    },
    /// BLE mutual auth: challenge received from a LocalMesh peer.
    /// MeshSentinel should verify and respond, or drop the connection.
    BleAuthChallengeReceived {
        peer: MeshAddress,
        challenge: BleChallenge,
    },
    /// BLE mutual auth: response received from a LocalMesh peer.
    /// MeshSentinel should verify against the pending challenge nonce.
    BleAuthResponseReceived {
        peer: MeshAddress,
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

// ── Silent Canary ─────────────────────────────────────────────────────────
//
// Dead man's switch alert: community member(s) went dark during active recording.
// Broadcast encrypted with a key derived from CommunityId — only members can decrypt.

/// Count of community peers confirmed silent. Newtype prevents confusion
/// with other u32 quantities (sequence IDs, shard counts, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SilentCount(pub u32);

/// Anonymous alert: community member(s) went silent during active recording.
/// No identifying information about WHO went silent — just count and timestamp.
/// Encrypted with community-derived key before broadcast; non-members cannot decrypt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryAlert {
    pub silent_count: SilentCount,
    pub detected_at: crate::time::PhalanxTimestamp,
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
    async fn ban_peer(&self, peer: &MeshAddress);
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
        target: &MeshAddress,
        request: RecordingRequest,
    ) -> Result<(), String>;

    /// Disconnect a specific peer (eclipse remediation).
    /// Default: delegates to ban_peer (existing mechanism).
    async fn disconnect_peer(&self, peer: &MeshAddress) {
        self.ban_peer(peer).await;
    }

    /// Re-dial bootstrap peers and trigger a Kademlia random walk.
    /// Default: no-op (transports that don't support this ignore the request).
    async fn rebootstrap(&self, _peers: &[String]) -> Result<(), String> {
        Ok(())
    }

    /// Publish a revocation token to the revocation gossipsub topic.
    /// Default: serializes and publishes to `MeshTopic::revocation()`.
    async fn publish_revocation(&self, token: &RevocationToken) -> Result<(), String> {
        let data =
            postcard::to_allocvec(token).map_err(|e| format!("Revocation serialize: {e}"))?;
        self.publish(&MeshTopic::revocation(), data).await
    }

    /// Remove local provider records for a revoked recording from the DHT.
    /// Default: no-op (transports that don't maintain provider records ignore this).
    async fn withdraw_provider(&self, _recording_id: &RecordingId) -> Result<(), String> {
        Ok(())
    }

    /// Directed PUSH of a recording's envelopes to an archival peer (Stronghold).
    /// Default: unsupported (transports without the archive protocol ignore it).
    async fn send_archive_request(
        &self,
        _target: &MeshAddress,
        _request: ArchiveRequest,
    ) -> Result<(), String> {
        Err("archive protocol not supported by this transport".to_string())
    }

    /// Reply to an inbound archive push with a custody receipt over `channel_id`.
    /// Default: unsupported.
    async fn send_archive_response(
        &self,
        _channel_id: &str,
        _receipt: ArchiveReceipt,
    ) -> Result<(), String> {
        Err("archive protocol not supported by this transport".to_string())
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
    async fn discover_peers(&mut self) -> Vec<MeshAddress>;

    /// Send data directly to a specific peer via the local transport.
    async fn send_local(&self, target: &MeshAddress, data: Vec<u8>) -> Result<(), TransportError>;

    /// Poll for the next inbound event from the local transport.
    async fn next_local_event(&mut self) -> Option<NetworkEvent>;

    /// Whether this local transport is available on the current platform.
    fn is_available(&self) -> bool;
}
