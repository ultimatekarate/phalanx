// FFI bindings for the Trusted Community surface.
//
// All five functions follow the two-call buffer protocol defined in
// `phalanx-ffi/src/error.rs`:
//
//   1. First call: pass `outBuf = nullptr, outLen = &0`. FFI writes the
//      required size into `*outLen` and returns `bufferTooSmall` (-15).
//   2. Second call: pass an adequately-sized buffer. FFI writes the
//      payload and returns `ok` (0). `*outLen` is updated to the bytes
//      actually written.
//
// The bridge hides this dance — each method exposes a Future<...> that
// allocates, dispatches, and decodes once both calls succeed. Domain
// errors ride inside the postcard payload (ImportOutcome, DissolveOutcome,
// PreviewOutcome); transport failures throw [PhalanxException] so the UI
// can distinguish "token rejected by crypto" from "FFI bridge broken".

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'community_models.dart';
import 'library_loader.dart';
import 'phalanx_bridge.dart' show PhalanxException;

/// Transport-layer status codes. Must stay in lock-step with
/// `phalanx-ffi/src/error.rs`. Domain errors never use these codes —
/// they arrive as postcard payload.
class PhalanxFfiStatus {
  static const ok = 0;
  static const nullPointer = -1;
  static const invalidUtf8 = -3;
  static const bufferTooSmall = -15;
  static const serializationFailure = -16;
}

// ── C-ABI typedefs ─────────────────────────────────────────────────────

// import / dissolve / list / get — all take the handle.
typedef _ImportCommunityC = Int32 Function(
  Pointer<Void>, Pointer<Uint8>, IntPtr, Pointer<Uint8>, Pointer<IntPtr>,
);
typedef _ImportCommunityDart = int Function(
  Pointer<Void>, Pointer<Uint8>, int, Pointer<Uint8>, Pointer<IntPtr>,
);

typedef _DissolveCommunityC = Int32 Function(
  Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>, Pointer<IntPtr>,
);
typedef _DissolveCommunityDart = int Function(
  Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>, Pointer<IntPtr>,
);

typedef _ListCommunitiesC = Int32 Function(
  Pointer<Void>, Pointer<Uint8>, Pointer<IntPtr>,
);
typedef _ListCommunitiesDart = int Function(
  Pointer<Void>, Pointer<Uint8>, Pointer<IntPtr>,
);

typedef _GetCommunityC = Int32 Function(
  Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>, Pointer<IntPtr>,
);
typedef _GetCommunityDart = int Function(
  Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>, Pointer<IntPtr>,
);

// preview takes no handle — pure verb.
typedef _PreviewCommunityC = Int32 Function(
  Pointer<Uint8>, IntPtr, Uint64, Pointer<Uint8>, Pointer<IntPtr>,
);
typedef _PreviewCommunityDart = int Function(
  Pointer<Uint8>, int, int, Pointer<Uint8>, Pointer<IntPtr>,
);

// Ceremony — preview + sign. Both take the handle (the preview verb
// checks `request.voucher_did == handle.did`; sign uses the handle's
// keypair directly, no actor round-trip).
typedef _PreviewVouchRequestC = Int32 Function(
  Pointer<Void>, Pointer<Uint8>, IntPtr, Pointer<Uint8>, Pointer<IntPtr>,
);
typedef _PreviewVouchRequestDart = int Function(
  Pointer<Void>, Pointer<Uint8>, int, Pointer<Uint8>, Pointer<IntPtr>,
);

typedef _SignVouchRequestC = Int32 Function(
  Pointer<Void>, Pointer<Uint8>, IntPtr, Pointer<Uint8>, Pointer<IntPtr>,
);
typedef _SignVouchRequestDart = int Function(
  Pointer<Void>, Pointer<Uint8>, int, Pointer<Uint8>, Pointer<IntPtr>,
);

// ── Bridge ─────────────────────────────────────────────────────────────

/// Sibling of [PhalanxBridge] for the community surface. Constructed once
/// per app lifetime and shares the same native handle (the Pointer<Void>
/// you pass into each call).
class CommunityBridge {
  late final DynamicLibrary _lib;
  late final _ImportCommunityDart _import;
  late final _DissolveCommunityDart _dissolve;
  late final _ListCommunitiesDart _list;
  late final _GetCommunityDart _get;
  late final _PreviewCommunityDart _preview;
  late final _PreviewVouchRequestDart _previewVouch;
  late final _SignVouchRequestDart _signVouch;

  CommunityBridge() {
    _lib = loadPhalanxLibrary();
    _import = _lib.lookupFunction<_ImportCommunityC, _ImportCommunityDart>(
      'phalanx_import_community',
    );
    _dissolve = _lib
        .lookupFunction<_DissolveCommunityC, _DissolveCommunityDart>(
          'phalanx_dissolve_community',
        );
    _list = _lib.lookupFunction<_ListCommunitiesC, _ListCommunitiesDart>(
      'phalanx_list_communities',
    );
    _get = _lib.lookupFunction<_GetCommunityC, _GetCommunityDart>(
      'phalanx_get_community',
    );
    _preview = _lib.lookupFunction<_PreviewCommunityC, _PreviewCommunityDart>(
      'phalanx_preview_community',
    );
    _previewVouch = _lib
        .lookupFunction<_PreviewVouchRequestC, _PreviewVouchRequestDart>(
          'phalanx_preview_vouch_request',
        );
    _signVouch = _lib
        .lookupFunction<_SignVouchRequestC, _SignVouchRequestDart>(
          'phalanx_sign_vouch_request',
        );
  }

  /// Import a verified community token. Returns [ImportOutcome] so the
  /// caller can distinguish `Ok(id)` from specific verify errors.
  ImportOutcome importCommunity(Pointer<Void> handle, Uint8List tokenBytes) {
    final bytes = _twoCallBuffer((outBuf, outLen) {
      final tokenNative = calloc<Uint8>(tokenBytes.length);
      try {
        tokenNative.asTypedList(tokenBytes.length).setAll(0, tokenBytes);
        return _import(handle, tokenNative, tokenBytes.length, outBuf, outLen);
      } finally {
        calloc.free(tokenNative);
      }
    }, 'phalanx_import_community');
    return ImportOutcome.decode(bytes);
  }

  /// Dissolve a community by its fingerprint. The community is removed
  /// from the live routing table; on-disk persistence (if any) is the
  /// caller's responsibility.
  DissolveOutcome dissolveCommunity(Pointer<Void> handle, CommunityId id) {
    final bytes = _twoCallBuffer((outBuf, outLen) {
      final idNative = calloc<Uint8>(32);
      try {
        idNative.asTypedList(32).setAll(0, id.bytes);
        return _dissolve(handle, idNative, outBuf, outLen);
      } finally {
        calloc.free(idNative);
      }
    }, 'phalanx_dissolve_community');
    return DissolveOutcome.decode(bytes);
  }

  /// List all communities currently registered with this node.
  List<CommunitySummary> listCommunities(Pointer<Void> handle) {
    final bytes = _twoCallBuffer(
      (outBuf, outLen) => _list(handle, outBuf, outLen),
      'phalanx_list_communities',
    );
    return decodeSummaryList(bytes);
  }

  /// Fetch the full roster for a single community. Returns `null` if
  /// the fingerprint is unknown to the actor (e.g. dissolved).
  CommunityRoster? getCommunity(Pointer<Void> handle, CommunityId id) {
    final bytes = _twoCallBuffer((outBuf, outLen) {
      final idNative = calloc<Uint8>(32);
      try {
        idNative.asTypedList(32).setAll(0, id.bytes);
        return _get(handle, idNative, outBuf, outLen);
      } finally {
        calloc.free(idNative);
      }
    }, 'phalanx_get_community');
    return decodeOptionalRoster(bytes);
  }

  /// Preview a community token without touching the registry. Pure
  /// verification + projection — safe to run on a freshly-scanned QR
  /// before the user has accepted. See R1 (phishing mitigation).
  ///
  /// `nowMillis` is the caller's trusted wall-clock reading in epoch
  /// milliseconds — Temporal Agreement (§III) requires the Dart side
  /// to source its own time.
  PreviewOutcome previewCommunity(Uint8List tokenBytes, int nowMillis) {
    final bytes = _twoCallBuffer((outBuf, outLen) {
      final tokenNative = calloc<Uint8>(tokenBytes.length);
      try {
        tokenNative.asTypedList(tokenBytes.length).setAll(0, tokenBytes);
        return _preview(
          tokenNative, tokenBytes.length, nowMillis, outBuf, outLen,
        );
      } finally {
        calloc.free(tokenNative);
      }
    }, 'phalanx_preview_community');
    return PreviewOutcome.decode(bytes);
  }

  /// Preview a scanned `VouchRequest` — strips the envelope, verifies
  /// the request targets this device's DID, and projects to the
  /// review-safe [VouchRequestPreview] shape. Pure — no side effects
  /// and no signature produced.
  ///
  /// Errors that prevent preview (bad version, voucher mismatch) ride
  /// inside the [PreviewVouchOutcome] payload rather than throwing;
  /// transport failures still throw [PhalanxException].
  PreviewVouchOutcome previewVouchRequest(
    Pointer<Void> handle,
    Uint8List requestBytes,
  ) {
    final bytes = _twoCallBuffer((outBuf, outLen) {
      final reqNative = calloc<Uint8>(requestBytes.length);
      try {
        reqNative.asTypedList(requestBytes.length).setAll(0, requestBytes);
        return _previewVouch(
          handle,
          reqNative,
          requestBytes.length,
          outBuf,
          outLen,
        );
      } finally {
        calloc.free(reqNative);
      }
    }, 'phalanx_preview_vouch_request');
    return PreviewVouchOutcome.decode(bytes);
  }

  /// Sign a scanned `VouchRequest`. On `Ok`, the returned bytes are a
  /// wrapped `[VOUCH_RESPONSE_VERSION] || postcard(VouchResponse)`
  /// envelope — hand straight to a QR encoder or file writer.
  ///
  /// Signing uses `SystemClock.now()` on the Rust side (same time
  /// source as `phalanx_sign_vouch`), so the caller does not supply
  /// a timestamp.
  SignVouchOutcome signVouchRequest(
    Pointer<Void> handle,
    Uint8List requestBytes,
  ) {
    final bytes = _twoCallBuffer((outBuf, outLen) {
      final reqNative = calloc<Uint8>(requestBytes.length);
      try {
        reqNative.asTypedList(requestBytes.length).setAll(0, requestBytes);
        return _signVouch(
          handle,
          reqNative,
          requestBytes.length,
          outBuf,
          outLen,
        );
      } finally {
        calloc.free(reqNative);
      }
    }, 'phalanx_sign_vouch_request');
    return SignVouchOutcome.decode(bytes);
  }

  // ── Private ────────────────────────────────────────────────────────

  /// Executes the two-call buffer protocol. [call] takes
  /// `(outBuf, outLen) -> statusCode` and is invoked twice — once with
  /// a null pointer to discover the required size, then again with an
  /// allocated buffer. Returns the payload bytes on success; throws
  /// [PhalanxException] otherwise.
  Uint8List _twoCallBuffer(
    int Function(Pointer<Uint8>, Pointer<IntPtr>) call,
    String fn,
  ) {
    final outLen = calloc<IntPtr>();
    try {
      outLen.value = 0;
      final probe = call(nullptr, outLen);
      if (probe != PhalanxFfiStatus.bufferTooSmall) {
        // Either an early-exit error (null ptr, invalid state) or a
        // zero-byte response. The Rust side guarantees bufferTooSmall
        // on success-with-payload, so anything else here is terminal.
        throw PhalanxException(probe, fn);
      }

      final size = outLen.value;
      if (size <= 0) {
        throw PhalanxException(PhalanxFfiStatus.serializationFailure, fn);
      }

      final buf = calloc<Uint8>(size);
      try {
        outLen.value = size;
        final status = call(buf, outLen);
        if (status != PhalanxFfiStatus.ok) {
          throw PhalanxException(status, fn);
        }
        return Uint8List.fromList(buf.asTypedList(outLen.value));
      } finally {
        calloc.free(buf);
      }
    } finally {
      calloc.free(outLen);
    }
  }
}
