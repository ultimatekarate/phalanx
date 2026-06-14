// crates/phalanx-transport/src/adapters/local_mesh.rs
//
// Local mesh transport adapters for truly disconnected scenarios.
//
// LocalMeshAdapter — Channel-bridged adapter for BLE/WiFi Direct. Flutter drives
// discovery and data transfer via platform SDKs, pushing events into Rust through
// C-ABI FFI functions. Outbound packets are polled by Flutter via FFI.
//
// NoOpLocalMesh — Default for desktop/non-BLE platforms. Always reports unavailable.

use async_trait::async_trait;
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::MeshAddress;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;

use phalanx_proto::network::{LocalMeshPort, TransportError};

/// Default local mesh for desktop/non-BLE platforms.
/// Always reports unavailable — no local transport exists.
pub struct NoOpLocalMesh;

#[async_trait]
impl LocalMeshPort for NoOpLocalMesh {
    async fn discover_peers(&mut self) -> Vec<MeshAddress> {
        Vec::new()
    }

    async fn send_local(
        &self,
        _target: &MeshAddress,
        _data: Vec<u8>,
    ) -> Result<(), TransportError> {
        Err(TransportError::Internal(
            "NoOpLocalMesh: local transport not available on this platform".to_string(),
        ))
    }

    async fn next_local_event(&mut self) -> Option<NetworkEvent> {
        // Block forever — no events will ever arrive on a no-op transport.
        // In practice, this arm will never be selected because is_available() returns false.
        std::future::pending().await
    }

    fn is_available(&self) -> bool {
        false
    }
}

/// Outbound packet queued by `send_local` for Flutter to poll via FFI.
pub struct OutboundLocalPacket {
    pub target: MeshAddress,
    pub data: Vec<u8>,
}

/// Channel-bridged local mesh adapter for BLE and WiFi Direct.
///
/// Flutter owns the platform transport (CoreBluetooth, Android BLE GATT,
/// WiFi Direct). It pushes inbound events into Rust via C-ABI FFI functions
/// and polls outbound packets via `phalanx_local_mesh_poll_outbound`.
///
/// This adapter is transport-agnostic — BLE, WiFi Direct, or any future
/// local transport all flow through the same channel bridge.
pub struct LocalMeshAdapter {
    inbound_rx: mpsc::Receiver<NetworkEvent>,
    outbound_tx: mpsc::Sender<OutboundLocalPacket>,
    available: Arc<AtomicBool>,
    known_peers: Vec<MeshAddress>,
}

impl LocalMeshAdapter {
    /// Create a new adapter and its channel endpoints.
    ///
    /// Returns `(adapter, inbound_tx, outbound_rx, available_flag)`:
    /// - `inbound_tx`: FFI functions push `NetworkEvent`s here
    /// - `outbound_rx`: Flutter polls outbound packets from here
    /// - `available_flag`: FFI toggles this to signal transport availability
    pub fn new(
        channel_capacity: usize,
    ) -> (
        Self,
        mpsc::Sender<NetworkEvent>,
        mpsc::Receiver<OutboundLocalPacket>,
        Arc<AtomicBool>,
    ) {
        let (inbound_tx, inbound_rx) = mpsc::channel(channel_capacity);
        let (outbound_tx, outbound_rx) = mpsc::channel(channel_capacity);
        let available = Arc::new(AtomicBool::new(false));

        let adapter = Self {
            inbound_rx,
            outbound_tx,
            available: Arc::clone(&available),
            known_peers: Vec::new(),
        };

        (adapter, inbound_tx, outbound_rx, available)
    }
}

#[async_trait]
impl LocalMeshPort for LocalMeshAdapter {
    async fn discover_peers(&mut self) -> Vec<MeshAddress> {
        self.known_peers.clone()
    }

    async fn send_local(&self, target: &MeshAddress, data: Vec<u8>) -> Result<(), TransportError> {
        let packet = OutboundLocalPacket {
            target: target.clone(),
            data,
        };
        self.outbound_tx.try_send(packet).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => {
                TransportError::Internal("local mesh outbound queue full".to_string())
            }
            mpsc::error::TrySendError::Closed(_) => {
                TransportError::Internal("local mesh outbound channel closed".to_string())
            }
        })
    }

    async fn next_local_event(&mut self) -> Option<NetworkEvent> {
        let event = self.inbound_rx.recv().await?;

        // Track peer state for discover_peers()
        match &event {
            NetworkEvent::PeerDiscovered { peer, .. } => {
                if !self.known_peers.contains(peer) {
                    self.known_peers.push(peer.clone());
                }
            }
            NetworkEvent::PeerDisconnected { peer } => {
                self.known_peers.retain(|p| p != peer);
            }
            _ => {}
        }

        Some(event)
    }

    fn is_available(&self) -> bool {
        self.available.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use phalanx_proto::telemetry::DiscoverySource;
    use phalanx_proto::topology::{SubnetBucket, TransportClass};

    #[tokio::test]
    async fn test_noop_local_mesh_unavailable() {
        let mesh = NoOpLocalMesh;
        assert!(
            !mesh.is_available(),
            "NoOpLocalMesh should never be available"
        );
    }

    #[tokio::test]
    async fn test_noop_discover_returns_empty() {
        let mut mesh = NoOpLocalMesh;
        let peers = mesh.discover_peers().await;
        assert!(peers.is_empty(), "NoOpLocalMesh should discover no peers");
    }

    #[tokio::test]
    async fn test_noop_send_returns_error() {
        let mesh = NoOpLocalMesh;
        let target = MeshAddress::new("test_peer".to_string());
        let result = mesh.send_local(&target, vec![0x42]).await;
        assert!(result.is_err(), "NoOpLocalMesh send should fail");
    }

    #[tokio::test]
    async fn test_adapter_availability_flag() {
        let (adapter, _tx, _rx, flag) = LocalMeshAdapter::new(16);
        assert!(!adapter.is_available());
        flag.store(true, Ordering::Relaxed);
        assert!(adapter.is_available());
        flag.store(false, Ordering::Relaxed);
        assert!(!adapter.is_available());
    }

    #[tokio::test]
    async fn test_adapter_inbound_event_flows_through() {
        let (mut adapter, tx, _rx, _flag) = LocalMeshAdapter::new(16);
        let peer = MeshAddress::new("ble-peer-1".to_string());

        tx.send(NetworkEvent::PeerDiscovered {
            peer: peer.clone(),
            source: DiscoverySource::LocalMesh,
            bucket: SubnetBucket::local_mesh(),
            transport: TransportClass::LocalMesh,
        })
        .await
        .unwrap();

        let event = adapter.next_local_event().await.unwrap();
        match event {
            NetworkEvent::PeerDiscovered { peer: p, .. } => assert_eq!(p, peer),
            _ => panic!("expected PeerDiscovered"),
        }
    }

    #[tokio::test]
    async fn test_adapter_tracks_known_peers() {
        let (mut adapter, tx, _rx, _flag) = LocalMeshAdapter::new(16);
        let peer_a = MeshAddress::new("peer-a".to_string());
        let peer_b = MeshAddress::new("peer-b".to_string());

        // Discover two peers
        tx.send(NetworkEvent::PeerDiscovered {
            peer: peer_a.clone(),
            source: DiscoverySource::LocalMesh,
            bucket: SubnetBucket::local_mesh(),
            transport: TransportClass::LocalMesh,
        })
        .await
        .unwrap();
        adapter.next_local_event().await;

        tx.send(NetworkEvent::PeerDiscovered {
            peer: peer_b.clone(),
            source: DiscoverySource::LocalMesh,
            bucket: SubnetBucket::local_mesh(),
            transport: TransportClass::LocalMesh,
        })
        .await
        .unwrap();
        adapter.next_local_event().await;

        assert_eq!(adapter.discover_peers().await.len(), 2);

        // Disconnect one
        tx.send(NetworkEvent::PeerDisconnected {
            peer: peer_a.clone(),
        })
        .await
        .unwrap();
        adapter.next_local_event().await;

        let peers = adapter.discover_peers().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0], peer_b);
    }

    #[tokio::test]
    async fn test_adapter_send_local_enqueues() {
        let (adapter, _tx, mut rx, _flag) = LocalMeshAdapter::new(16);
        let target = MeshAddress::new("target-peer".to_string());
        let data = vec![0xDE, 0xAD];

        adapter
            .send_local(&target, data.clone())
            .await
            .expect("send should succeed");

        let packet = rx.try_recv().expect("should have outbound packet");
        assert_eq!(packet.target, target);
        assert_eq!(packet.data, data);
    }

    #[tokio::test]
    async fn test_adapter_send_local_full_queue() {
        let (adapter, _tx, _rx, _flag) = LocalMeshAdapter::new(1);
        let target = MeshAddress::new("target".to_string());

        // Fill the queue
        adapter
            .send_local(&target, vec![1])
            .await
            .expect("first send should succeed");

        // Second send should fail (queue capacity = 1)
        let result = adapter.send_local(&target, vec![2]).await;
        assert!(result.is_err(), "send to full queue should fail");
    }

    #[tokio::test]
    async fn test_adapter_duplicate_peer_not_added_twice() {
        let (mut adapter, tx, _rx, _flag) = LocalMeshAdapter::new(16);
        let peer = MeshAddress::new("same-peer".to_string());

        // Discover same peer twice
        for _ in 0..2 {
            tx.send(NetworkEvent::PeerDiscovered {
                peer: peer.clone(),
                source: DiscoverySource::LocalMesh,
                bucket: SubnetBucket::local_mesh(),
                transport: TransportClass::LocalMesh,
            })
            .await
            .unwrap();
            adapter.next_local_event().await;
        }

        assert_eq!(adapter.discover_peers().await.len(), 1);
    }
}
