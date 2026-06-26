// FFI bindings for the local-mesh / BLE seam.
//
// Self-contained sibling of [PhalanxBridge] (like `CommunityBridge`): it loads
// its own library handle and binds its own free/error helpers. Every method
// takes the engine handle as its first argument — the caller (LocalMeshService)
// supplies `PhalanxBridge.nativeHandle`.
//
// The handshake blobs (`BleChallenge` / `BleResponse`) are OPAQUE postcard
// bytes the platform plugin only relays; Rust owns the crypto and never lets
// the plugin assemble or parse them. Byte buffers returned through out-params
// are leaked by Rust (`leak_bytes_to_c`) and freed here via `phalanx_free_bytes`;
// returned peer strings via `phalanx_free_string`.

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'library_loader.dart';
import 'phalanx_bridge.dart' show PhalanxError, PhalanxException;

/// Result of `phalanx_ble_verify_and_admit`. Admission is a normal binary
/// outcome — `rejected` (signature/freshness/rate-cap/nonce) is expected, not
/// an error. Transport-level failures (null handle, malformed blob) still throw
/// [PhalanxException].
enum BleAdmit { admitted, rejected }

/// An outbound local-mesh packet the engine wants the radio to transmit to
/// [peer]. (Returned by [LocalMeshApi.pollOutbound].)
class OutboundPacket {
  final String peer;
  final Uint8List data;
  const OutboundPacket(this.peer, this.data);
}

/// The seam API the local-mesh service depends on. [LocalMeshBridge] implements
/// it over FFI; tests substitute a fake (no `.so` needed). Every method takes
/// the engine handle (`PhalanxBridge.nativeHandle`) as its first argument.
abstract class LocalMeshApi {
  /// Build a fresh `BleChallenge` blob bound to the engine's active recording.
  /// Throws [PhalanxException] (`invalidState`) if no recording is active.
  Uint8List makeChallenge(Pointer<Void> handle);

  /// Sign an incoming `BleChallenge` blob, returning a `BleResponse` blob.
  Uint8List signChallenge(Pointer<Void> handle, Uint8List challenge);

  /// Pure signature check of a `BleResponse` against its `BleChallenge`
  /// (no freshness/admission). `true` if the signature verifies.
  bool verifyPeer(Pointer<Void> handle, Uint8List challenge, Uint8List response);

  /// The Rust-side admission trust boundary: verify + freshness + rate-cap +
  /// single-use nonce. On `admitted`, a `PeerDiscovered{LocalMesh}` (and, while
  /// recording, a `ProximityWitness`) is emitted for the verified DID.
  BleAdmit verifyAndAdmit(
    Pointer<Void> handle,
    Uint8List challenge,
    Uint8List response,
  );

  /// Push data received from a local-mesh peer into the engine.
  void pushDataReceived(
    Pointer<Void> handle,
    String peer,
    String topic,
    Uint8List data,
  );

  /// Notify the engine that a local-mesh peer went out of range.
  void pushPeerDisconnected(Pointer<Void> handle, String peer);

  /// Poll for an outbound packet the engine wants transmitted. `null` when the
  /// queue is empty. (Inert until the engine routes outbound to the adapter.)
  OutboundPacket? pollOutbound(Pointer<Void> handle);

  /// Gate engine consumption of inbound local-mesh events. Must be `true` for
  /// pushed events / admissions to be processed.
  void setAvailable(Pointer<Void> handle, bool available);
}

// ── C-ABI typedefs ─────────────────────────────────────────────────────

typedef _MakeChallengeC = Int32 Function(
  Pointer<Void>, Pointer<Pointer<Uint8>>, Pointer<Uint32>,
);
typedef _MakeChallengeDart = int Function(
  Pointer<Void>, Pointer<Pointer<Uint8>>, Pointer<Uint32>,
);

typedef _SignChallengeC = Int32 Function(
  Pointer<Void>, Pointer<Uint8>, IntPtr, Pointer<Pointer<Uint8>>, Pointer<Uint32>,
);
typedef _SignChallengeDart = int Function(
  Pointer<Void>, Pointer<Uint8>, int, Pointer<Pointer<Uint8>>, Pointer<Uint32>,
);

// verify_ble_peer and verify_and_admit share a shape.
typedef _VerifyC = Int32 Function(
  Pointer<Void>, Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr,
);
typedef _VerifyDart = int Function(
  Pointer<Void>, Pointer<Uint8>, int, Pointer<Uint8>, int,
);

typedef _PushDataC = Int32 Function(
  Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Uint8>, Uint32,
);
typedef _PushDataDart = int Function(
  Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Uint8>, int,
);

typedef _PushDisconnectedC = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef _PushDisconnectedDart = int Function(Pointer<Void>, Pointer<Utf8>);

typedef _PollOutboundC = Int32 Function(
  Pointer<Void>, Pointer<Pointer<Utf8>>, Pointer<Pointer<Uint8>>, Pointer<Uint32>,
);
typedef _PollOutboundDart = int Function(
  Pointer<Void>, Pointer<Pointer<Utf8>>, Pointer<Pointer<Uint8>>, Pointer<Uint32>,
);

typedef _SetAvailableC = Int32 Function(Pointer<Void>, Bool);
typedef _SetAvailableDart = int Function(Pointer<Void>, bool);

typedef _FreeStringC = Void Function(Pointer<Utf8>);
typedef _FreeStringDart = void Function(Pointer<Utf8>);
typedef _FreeBytesC = Void Function(Pointer<Uint8>, Uint32);
typedef _FreeBytesDart = void Function(Pointer<Uint8>, int);

// ── Bridge ─────────────────────────────────────────────────────────────

class LocalMeshBridge implements LocalMeshApi {
  late final DynamicLibrary _lib;
  late final _MakeChallengeDart _make;
  late final _SignChallengeDart _sign;
  late final _VerifyDart _verifyPeer;
  late final _VerifyDart _verifyAndAdmit;
  late final _PushDataDart _pushData;
  late final _PushDisconnectedDart _pushDisconnected;
  late final _PollOutboundDart _pollOutbound;
  late final _SetAvailableDart _setAvailable;
  late final _FreeStringDart _freeString;
  late final _FreeBytesDart _freeBytes;

  LocalMeshBridge() {
    _lib = loadPhalanxLibrary();
    _make = _lib.lookupFunction<_MakeChallengeC, _MakeChallengeDart>(
      'phalanx_make_ble_challenge',
    );
    _sign = _lib.lookupFunction<_SignChallengeC, _SignChallengeDart>(
      'phalanx_sign_ble_challenge',
    );
    _verifyPeer = _lib.lookupFunction<_VerifyC, _VerifyDart>(
      'phalanx_verify_ble_peer',
    );
    _verifyAndAdmit = _lib.lookupFunction<_VerifyC, _VerifyDart>(
      'phalanx_ble_verify_and_admit',
    );
    _pushData = _lib.lookupFunction<_PushDataC, _PushDataDart>(
      'phalanx_local_mesh_push_data_received',
    );
    _pushDisconnected = _lib
        .lookupFunction<_PushDisconnectedC, _PushDisconnectedDart>(
          'phalanx_local_mesh_push_peer_disconnected',
        );
    _pollOutbound = _lib.lookupFunction<_PollOutboundC, _PollOutboundDart>(
      'phalanx_local_mesh_poll_outbound',
    );
    _setAvailable = _lib.lookupFunction<_SetAvailableC, _SetAvailableDart>(
      'phalanx_local_mesh_set_available',
    );
    _freeString = _lib.lookupFunction<_FreeStringC, _FreeStringDart>(
      'phalanx_free_string',
    );
    _freeBytes = _lib.lookupFunction<_FreeBytesC, _FreeBytesDart>(
      'phalanx_free_bytes',
    );
  }

  @override
  Uint8List makeChallenge(Pointer<Void> handle) {
    final outData = calloc<Pointer<Uint8>>();
    final outLen = calloc<Uint32>();
    try {
      _check(_make(handle, outData, outLen), 'phalanx_make_ble_challenge');
      return _takeBytes(outData, outLen);
    } finally {
      calloc.free(outData);
      calloc.free(outLen);
    }
  }

  @override
  Uint8List signChallenge(Pointer<Void> handle, Uint8List challenge) {
    final chNative = calloc<Uint8>(challenge.length);
    final outData = calloc<Pointer<Uint8>>();
    final outLen = calloc<Uint32>();
    try {
      chNative.asTypedList(challenge.length).setAll(0, challenge);
      _check(
        _sign(handle, chNative, challenge.length, outData, outLen),
        'phalanx_sign_ble_challenge',
      );
      return _takeBytes(outData, outLen);
    } finally {
      calloc.free(chNative);
      calloc.free(outData);
      calloc.free(outLen);
    }
  }

  @override
  bool verifyPeer(
    Pointer<Void> handle,
    Uint8List challenge,
    Uint8List response,
  ) {
    final code = _withBlobs(
      challenge,
      response,
      (ch, chLen, resp, respLen) =>
          _verifyPeer(handle, ch, chLen, resp, respLen),
    );
    if (code == PhalanxError.ok) return true;
    if (code == PhalanxError.invalidState) return false;
    throw PhalanxException(code, 'phalanx_verify_ble_peer');
  }

  @override
  BleAdmit verifyAndAdmit(
    Pointer<Void> handle,
    Uint8List challenge,
    Uint8List response,
  ) {
    final code = _withBlobs(
      challenge,
      response,
      (ch, chLen, resp, respLen) =>
          _verifyAndAdmit(handle, ch, chLen, resp, respLen),
    );
    if (code == PhalanxError.ok) return BleAdmit.admitted;
    if (code == PhalanxError.invalidState) return BleAdmit.rejected;
    throw PhalanxException(code, 'phalanx_ble_verify_and_admit');
  }

  @override
  void pushDataReceived(
    Pointer<Void> handle,
    String peer,
    String topic,
    Uint8List data,
  ) {
    final peerNative = peer.toNativeUtf8();
    final topicNative = topic.toNativeUtf8();
    final dataNative = calloc<Uint8>(data.length);
    try {
      dataNative.asTypedList(data.length).setAll(0, data);
      _check(
        _pushData(handle, peerNative, topicNative, dataNative, data.length),
        'phalanx_local_mesh_push_data_received',
      );
    } finally {
      calloc.free(peerNative);
      calloc.free(topicNative);
      calloc.free(dataNative);
    }
  }

  @override
  void pushPeerDisconnected(Pointer<Void> handle, String peer) {
    final peerNative = peer.toNativeUtf8();
    try {
      _check(
        _pushDisconnected(handle, peerNative),
        'phalanx_local_mesh_push_peer_disconnected',
      );
    } finally {
      calloc.free(peerNative);
    }
  }

  @override
  OutboundPacket? pollOutbound(Pointer<Void> handle) {
    final outPeer = calloc<Pointer<Utf8>>();
    final outData = calloc<Pointer<Uint8>>();
    final outLen = calloc<Uint32>();
    try {
      final code = _pollOutbound(handle, outPeer, outData, outLen);
      if (code < 0) return null;
      if (outPeer.value == nullptr || outData.value == nullptr) return null;
      final peer = outPeer.value.toDartString();
      _freeString(outPeer.value);
      final len = outLen.value;
      final data = Uint8List.fromList(outData.value.asTypedList(len));
      _freeBytes(outData.value, len);
      return OutboundPacket(peer, data);
    } finally {
      calloc.free(outPeer);
      calloc.free(outData);
      calloc.free(outLen);
    }
  }

  @override
  void setAvailable(Pointer<Void> handle, bool available) {
    _check(
      _setAvailable(handle, available),
      'phalanx_local_mesh_set_available',
    );
  }

  // ── Private ────────────────────────────────────────────────────────

  void _check(int code, String fn) {
    if (code != PhalanxError.ok) throw PhalanxException(code, fn);
  }

  /// Copy a Rust-leaked byte buffer out of `(outData, outLen)` and free the
  /// native allocation. Call only after an `ok` status, which guarantees a
  /// non-null buffer.
  Uint8List _takeBytes(Pointer<Pointer<Uint8>> outData, Pointer<Uint32> outLen) {
    final len = outLen.value;
    final bytes = Uint8List.fromList(outData.value.asTypedList(len));
    _freeBytes(outData.value, len);
    return bytes;
  }

  int _withBlobs(
    Uint8List challenge,
    Uint8List response,
    int Function(Pointer<Uint8>, int, Pointer<Uint8>, int) call,
  ) {
    final ch = calloc<Uint8>(challenge.length);
    final resp = calloc<Uint8>(response.length);
    try {
      ch.asTypedList(challenge.length).setAll(0, challenge);
      resp.asTypedList(response.length).setAll(0, response);
      return call(ch, challenge.length, resp, response.length);
    } finally {
      calloc.free(ch);
      calloc.free(resp);
    }
  }
}
