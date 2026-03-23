//! Bridge from `TransportAdapter` (channel-based, `&self`) to `NetworkTransport` (`&mut self`, event-loop).
//!
//! The `Libp2pAdapter` implements `TransportAdapter`, which is the Hexagonal Port pattern
//! used by the production swarm actor. However, `MeshSentinel` consumes `NetworkTransport`,
//! which is the mutable event-driven trait used by the sentinel loop.
//!
//! This module bridges the two by extracting the ingress stream from the adapter
//! and forwarding commands through the channel-based interface.

use async_trait::async_trait;
use phalanx_proto::identity::RecordingId;
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::*;
use phalanx_transport::prelude::Libp2pAdapter;
use phalanx_transport::{EgressPort, IngressPort, NetworkTransport, TransportAdapter};
use tokio::sync::mpsc;

/// A wrapper that adapts `Libp2pAdapter` (implements `TransportAdapter`)
/// into the `NetworkTransport` trait required by `MeshSentinel`.
pub struct Libp2pBridge {
    adapter: Libp2pAdapter,
    ingress_rx: mpsc::Receiver<NetworkEvent>,
}

impl Libp2pBridge {
    /// Constructs a bridge from a pre-split adapter and ingress receiver.
    ///
    /// The factory returns `(Libp2pAdapter, Receiver<NetworkEvent>)` — pass
    /// both here. This avoids the one-shot Mutex extraction pattern.
    pub fn new(adapter: Libp2pAdapter, ingress_rx: mpsc::Receiver<NetworkEvent>) -> Self {
        Self {
            adapter,
            ingress_rx,
        }
    }
}

#[async_trait]
impl NetworkTransport for Libp2pBridge {
    async fn publish(&mut self, topic: &MeshTopic, data: Vec<u8>) -> Result<(), String> {
        self.adapter
            .publish(topic.clone(), data)
            .await
            .map_err(|e| e.to_string())
    }

    async fn next_event(&mut self) -> Option<NetworkEvent> {
        self.ingress_rx.recv().await
    }

    async fn ban_peer(&mut self, peer: &NetworkId) {
        if let Err(e) = self.adapter.ban_peer(peer).await {
            tracing::error!(
                target: "phalanx::bridge",
                "Failed to ban peer {}: {}",
                peer.0,
                e
            );
        }
    }

    async fn send_response(
        &mut self,
        _channel_id: &str,
        _response: RecordingResponse,
    ) -> Result<(), String> {
        // In the production Libp2p stack, retrieval responses are handled
        // directly by the swarm actor via request_response protocol.
        // This is a no-op bridge; the actual response routing happens
        // inside the Libp2pAdapter's spawned task.
        Ok(())
    }
}

// --- Actor-Oriented Split ---

pub struct BridgeIngress {
    ingress_rx: mpsc::Receiver<NetworkEvent>,
}

#[async_trait]
impl IngressPort for BridgeIngress {
    async fn next_event(&mut self) -> Option<NetworkEvent> {
        self.ingress_rx.recv().await
    }
}

#[derive(Clone)]
pub struct BridgeEgress {
    adapter: Libp2pAdapter,
}

#[async_trait]
impl EgressPort for BridgeEgress {
    async fn publish(&self, topic: &MeshTopic, data: Vec<u8>) -> Result<(), String> {
        self.adapter
            .publish(topic.clone(), data)
            .await
            .map_err(|e| e.to_string())
    }

    async fn ban_peer(&self, peer: &NetworkId) {
        if let Err(e) = self.adapter.ban_peer(peer).await {
            tracing::error!(target: "phalanx::bridge", "Failed to ban peer {}: {}", peer.0, e);
        }
    }

    async fn send_response(
        &self,
        _channel_id: &str,
        _response: RecordingResponse,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn announce_recording(&self, recording_id: &RecordingId) -> Result<(), String> {
        self.adapter
            .announce_recording(recording_id)
            .await
            .map_err(|e| e.to_string())
    }

    async fn find_providers(&self, recording_id: &RecordingId) -> Result<(), String> {
        self.adapter
            .find_providers(recording_id)
            .await
            .map_err(|e| e.to_string())
    }

    async fn send_request(
        &self,
        target: &NetworkId,
        request: phalanx_proto::retrieval::RecordingRequest,
    ) -> Result<(), String> {
        let data = postcard::to_allocvec(&request).map_err(|e| e.to_string())?;
        self.adapter
            .send_direct(target, data)
            .await
            .map_err(|e| e.to_string())
    }
}

impl Libp2pBridge {
    pub fn split(self) -> (BridgeIngress, BridgeEgress) {
        (
            BridgeIngress {
                ingress_rx: self.ingress_rx,
            },
            BridgeEgress {
                adapter: self.adapter,
            },
        )
    }
}
