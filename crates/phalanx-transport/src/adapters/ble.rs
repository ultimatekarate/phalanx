// crates/phalanx-transport/src/adapters/ble.rs
//
// Phase 3c: Local mesh transport adapters for truly disconnected scenarios.
//
// BleAdapter — Structural stub for AArch64/mobile platforms. Real BLE/WiFi Direct
// implementation requires Android/iOS SDKs via FFI during mobile integration.
//
// NoOpLocalMesh — Default for desktop/non-BLE platforms. Always reports unavailable.

use async_trait::async_trait;
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::NetworkId;

use crate::{LocalMeshPort, TransportError};

/// Default local mesh for desktop/non-BLE platforms.
/// Always reports unavailable — no local transport exists.
pub struct NoOpLocalMesh;

#[async_trait]
impl LocalMeshPort for NoOpLocalMesh {
    async fn discover_peers(&mut self) -> Vec<NetworkId> {
        Vec::new()
    }

    async fn send_local(&self, _target: &NetworkId, _data: Vec<u8>) -> Result<(), TransportError> {
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

/// Structural stub for BLE/WiFi Direct local mesh transport.
///
/// Real implementation requires platform-specific SDKs:
/// - Android: BLE GATT via JNI/FFI callbacks
/// - iOS: CoreBluetooth via Swift FFI callbacks
///
/// The mobile runtime injects FFI callback handles during initialization.
/// Until mobile integration, this is a compile-target placeholder.
pub struct BleAdapter {
    // FFI callback handles will be injected by mobile runtime.
    // Placeholder fields for the structural stub.
    _available: bool,
}

impl BleAdapter {
    /// Create a new BLE adapter. Will be extended with FFI handles during mobile integration.
    pub fn new() -> Self {
        Self { _available: false }
    }
}

impl Default for BleAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LocalMeshPort for BleAdapter {
    async fn discover_peers(&mut self) -> Vec<NetworkId> {
        // STUB: Will be replaced with BLE GATT service discovery via FFI
        Vec::new()
    }

    async fn send_local(&self, _target: &NetworkId, _data: Vec<u8>) -> Result<(), TransportError> {
        // STUB: Will be replaced with BLE GATT characteristic write via FFI
        Err(TransportError::Internal(
            "BleAdapter: not yet connected to mobile FFI layer".to_string(),
        ))
    }

    async fn next_local_event(&mut self) -> Option<NetworkEvent> {
        // STUB: Will be replaced with FFI callback channel receiver
        std::future::pending().await
    }

    fn is_available(&self) -> bool {
        self._available
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let target = NetworkId("test_peer".to_string());
        let result = mesh.send_local(&target, vec![0x42]).await;
        assert!(result.is_err(), "NoOpLocalMesh send should fail");
    }

    #[tokio::test]
    async fn test_ble_adapter_default_unavailable() {
        let adapter = BleAdapter::new();
        assert!(
            !adapter.is_available(),
            "BleAdapter should be unavailable without FFI connection"
        );
    }

    #[tokio::test]
    async fn test_ble_adapter_send_returns_error() {
        let adapter = BleAdapter::new();
        let target = NetworkId("ble_peer".to_string());
        let result = adapter.send_local(&target, vec![0x42]).await;
        assert!(
            result.is_err(),
            "BleAdapter send should fail without FFI connection"
        );
    }
}
