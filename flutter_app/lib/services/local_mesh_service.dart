import 'dart:ffi';
import 'dart:typed_data';

import '../ffi/local_mesh_bridge.dart';

/// Thin orchestration over the local-mesh / BLE seam for the future BLE plugin
/// (#8) to drive.
///
/// Dependencies are injected so the service unit-tests with a fake
/// [LocalMeshApi] + a stub handle source — no `.so` required. App code wires
/// both from `phalanxProvider` (`PhalanxBridge.nativeHandle`). Each call sources
/// the engine handle fresh and guards on engine readiness (`nativeHandle`
/// returns `nullptr` once the engine is destroyed).
///
/// The plugin owns the radio (CoreBluetooth / Android BLE) and only relays the
/// opaque handshake blobs through here; Rust owns the crypto and the admission
/// trust boundary.
///
/// There is no outbound drive loop yet: `pollOutbound` is bound (completing the
/// API) but inert until the engine routes outbound to the local-mesh adapter,
/// so the `Timer` loop lands with that engine work — not here.
class LocalMeshService {
  final LocalMeshApi _api;
  final Pointer<Void> Function() _handleSource;

  LocalMeshService({
    required LocalMeshApi api,
    required Pointer<Void> Function() handleSource,
  })  : _api = api,
        _handleSource = handleSource;

  /// The current engine handle, or `null` if the engine is gone.
  Pointer<Void>? get _handle {
    final h = _handleSource();
    return h == nullptr ? null : h;
  }

  /// Whether the engine handle is currently live.
  bool get isEngineReady => _handle != null;

  /// Build a challenge for the engine's active recording (challenger
  /// initiation). Returns `null` if the engine is unavailable; throws
  /// [PhalanxException] if no recording is active. The caller keeps the blob to
  /// pair with the peer's response in [verifyAndAdmit].
  Uint8List? makeChallenge() {
    final h = _handle;
    return h == null ? null : _api.makeChallenge(h);
  }

  /// Sign an incoming challenge blob, returning a `BleResponse` blob to relay
  /// back to the challenger. `null` if the engine is unavailable.
  Uint8List? signChallenge(Uint8List challenge) {
    final h = _handle;
    return h == null ? null : _api.signChallenge(h, challenge);
  }

  /// Pure signature check (no admission), e.g. for UI feedback. `false` if the
  /// engine is unavailable.
  bool verifyPeer(Uint8List challenge, Uint8List response) {
    final h = _handle;
    return h == null ? false : _api.verifyPeer(h, challenge, response);
  }

  /// Verify + admit a peer's response (the Rust trust boundary). Returns
  /// [BleAdmit.rejected] if the engine is unavailable or any check fails.
  BleAdmit verifyAndAdmit(Uint8List challenge, Uint8List response) {
    final h = _handle;
    return h == null
        ? BleAdmit.rejected
        : _api.verifyAndAdmit(h, challenge, response);
  }

  /// Push data received from a local-mesh peer into the engine. No-op if the
  /// engine is unavailable.
  void pushDataReceived(String peer, String topic, Uint8List data) {
    final h = _handle;
    if (h != null) _api.pushDataReceived(h, peer, topic, data);
  }

  /// Notify the engine a local-mesh peer went out of range. No-op if the engine
  /// is unavailable.
  void pushPeerDisconnected(String peer) {
    final h = _handle;
    if (h != null) _api.pushPeerDisconnected(h, peer);
  }

  /// Poll for an outbound packet the engine wants transmitted, or `null`.
  /// (Inert until the engine routes outbound to the adapter.)
  OutboundPacket? pollOutbound() {
    final h = _handle;
    return h == null ? null : _api.pollOutbound(h);
  }

  /// Gate engine consumption of inbound local-mesh events. The plugin sets this
  /// `true` only when the radio is up AND the app is foregrounded, `false`
  /// otherwise — so this is wired to the plugin's radio-ready signal together
  /// with `didChangeAppLifecycleState`, not to raw app lifecycle alone. Required
  /// for inbound events / admissions to be processed by the engine. No-op if the
  /// engine is unavailable.
  void setAvailable(bool available) {
    final h = _handle;
    if (h != null) _api.setAvailable(h, available);
  }
}
