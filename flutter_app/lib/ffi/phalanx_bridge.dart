import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'library_loader.dart';
import 'models.dart';

/// FFI error codes matching PhalanxError in Rust.
class PhalanxError {
  static const ok = 0;
  static const nullPointer = -1;
  static const invalidState = -2;
  static const invalidUtf8 = -3;
  static const bootFailed = -4;
  static const alreadyRunning = -5;
  static const notRunning = -6;
  static const channelClosed = -7;
  static const trustError = -8;
  static const playbackError = -9;
  static const configError = -10;
  static const alreadyRecording = -11;
  static const notRecording = -12;
}

/// Exception thrown when an FFI call fails.
class PhalanxException implements Exception {
  final int code;
  final String function;
  PhalanxException(this.code, this.function);

  @override
  String toString() => 'PhalanxException($function): error code $code';
}

// =====================================================================
// NATIVE FUNCTION TYPEDEFS
// =====================================================================

// Lifecycle
typedef _PhalanxCreateC = Pointer<Void> Function(
  Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>,
);
typedef _PhalanxCreateDart = Pointer<Void> Function(
  Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>,
);

typedef _PhalanxI32HandleC = Int32 Function(Pointer<Void>);
typedef _PhalanxI32HandleDart = int Function(Pointer<Void>);

typedef _PhalanxDestroyC = Void Function(Pointer<Void>);
typedef _PhalanxDestroyDart = void Function(Pointer<Void>);

// Status
typedef _PhalanxGetDidC = Int32 Function(
  Pointer<Void>, Pointer<Pointer<Utf8>>,
);
typedef _PhalanxGetDidDart = int Function(
  Pointer<Void>, Pointer<Pointer<Utf8>>,
);

// Probe updates
typedef _PhalanxUpdateBatteryC = Int32 Function(
  Pointer<Void>, Uint8, Bool,
);
typedef _PhalanxUpdateBatteryDart = int Function(
  Pointer<Void>, int, bool,
);

typedef _PhalanxUpdateThermalC = Int32 Function(Pointer<Void>, Int32);
typedef _PhalanxUpdateThermalDart = int Function(Pointer<Void>, int);

typedef _PhalanxUpdateLifecycleC = Int32 Function(Pointer<Void>, Bool);
typedef _PhalanxUpdateLifecycleDart = int Function(Pointer<Void>, bool);

// Recording
typedef _PhalanxStartRecordingC = Int32 Function(
  Pointer<Void>, Pointer<Pointer<Utf8>>,
);
typedef _PhalanxStartRecordingDart = int Function(
  Pointer<Void>, Pointer<Pointer<Utf8>>,
);

typedef _PhalanxPushFrameC = Int32 Function(
  Pointer<Void>,
  Pointer<Uint8>, Uint32,       // y_plane, y_len
  Pointer<Uint8>, Uint32,       // uv_plane, uv_len
  Uint32, Uint32,               // width, height
  Int32,                        // pixel_format (0=NV21, 1=NV12)
  Pointer<Utf8>,                // recording_id
  Uint64,                       // timestamp_ms
);
typedef _PhalanxPushFrameDart = int Function(
  Pointer<Void>,
  Pointer<Uint8>, int,          // y_plane, y_len
  Pointer<Uint8>, int,          // uv_plane, uv_len
  int, int,                     // width, height
  int,                          // pixel_format
  Pointer<Utf8>,                // recording_id
  int,                          // timestamp_ms
);

// Audio capture
typedef _PhalanxPushAudioC = Int32 Function(
  Pointer<Void>,
  Pointer<Uint8>, Uint32,       // pcm_data, pcm_len
  Uint32,                       // sample_rate
  Uint8,                        // channels
  Pointer<Utf8>,                // recording_id
);
typedef _PhalanxPushAudioDart = int Function(
  Pointer<Void>,
  Pointer<Uint8>, int,          // pcm_data, pcm_len
  int,                          // sample_rate
  int,                          // channels
  Pointer<Utf8>,                // recording_id
);

// Trust
typedef _PhalanxGetPeersC = Int32 Function(
  Pointer<Void>, Pointer<Pointer<Utf8>>,
);
typedef _PhalanxGetPeersDart = int Function(
  Pointer<Void>, Pointer<Pointer<Utf8>>,
);

typedef _PhalanxTrustOpC = Int32 Function(
  Pointer<Void>, Pointer<Utf8>, Int32,
);
typedef _PhalanxTrustOpDart = int Function(
  Pointer<Void>, Pointer<Utf8>, int,
);

typedef _PhalanxPetNameC = Int32 Function(
  Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>,
);
typedef _PhalanxPetNameDart = int Function(
  Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>,
);

typedef _PhalanxRemovePeerC = Int32 Function(
  Pointer<Void>, Pointer<Utf8>,
);
typedef _PhalanxRemovePeerDart = int Function(
  Pointer<Void>, Pointer<Utf8>,
);

// Playback — session-based (PlaybackSession* returned from start)
typedef _PhalanxStartPlaybackC = Pointer<Void> Function(
  Pointer<Void>, Pointer<Utf8>,
);
typedef _PhalanxStartPlaybackDart = Pointer<Void> Function(
  Pointer<Void>, Pointer<Utf8>,
);

typedef _PhalanxPollFrameC = Int32 Function(
  Pointer<Void>, Pointer<Pointer<Uint8>>, Pointer<Uint32>,
);
typedef _PhalanxPollFrameDart = int Function(
  Pointer<Void>, Pointer<Pointer<Uint8>>, Pointer<Uint32>,
);

typedef _PhalanxStopPlaybackC = Void Function(Pointer<Void>);
typedef _PhalanxStopPlaybackDart = void Function(Pointer<Void>);

// Deep links
typedef _PhalanxShareLinkC = Int32 Function(
  Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Pointer<Utf8>>,
);
typedef _PhalanxShareLinkDart = int Function(
  Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Pointer<Utf8>>,
);

typedef _PhalanxOpenLinkC = Int32 Function(
  Pointer<Void>, Pointer<Utf8>,
);
typedef _PhalanxOpenLinkDart = int Function(
  Pointer<Void>, Pointer<Utf8>,
);

// C2PA export
typedef _PhalanxExportC2paC = Int32 Function(
  Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>,
);
typedef _PhalanxExportC2paDart = int Function(
  Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>,
);

// Memory
typedef _PhalanxFreeStringC = Void Function(Pointer<Utf8>);
typedef _PhalanxFreeStringDart = void Function(Pointer<Utf8>);

typedef _PhalanxFreeBytesC = Void Function(Pointer<Uint8>, Uint32);
typedef _PhalanxFreeBytesDart = void Function(Pointer<Uint8>, int);

// =====================================================================
// PHALANX BRIDGE
// =====================================================================

/// Ergonomic Dart wrapper around the phalanx-ffi C-ABI.
///
/// All Rust complexity is behind this class. The UI never touches FFI directly.
class PhalanxBridge {
  late final DynamicLibrary _lib;
  Pointer<Void> _handle = nullptr;
  bool _destroyed = false;

  // Cached function lookups
  late final _PhalanxCreateDart _create;
  late final _PhalanxI32HandleDart _start;
  late final _PhalanxI32HandleDart _stop;
  late final _PhalanxDestroyDart _destroy;
  late final _PhalanxI32HandleDart _getPowerState;
  late final _PhalanxI32HandleDart _isRecording;
  late final _PhalanxI32HandleDart _getTargetFps;
  late final _PhalanxGetDidDart _getNodeDid;
  late final _PhalanxUpdateBatteryDart _updateBattery;
  late final _PhalanxUpdateThermalDart _updateThermal;
  late final _PhalanxUpdateLifecycleDart _updateLifecycle;
  late final _PhalanxStartRecordingDart _startRecording;
  late final _PhalanxI32HandleDart _stopRecording;
  late final _PhalanxPushFrameDart _pushFrame;
  late final _PhalanxPushAudioDart _pushAudio;
  late final _PhalanxGetPeersDart _getPeers;
  late final _PhalanxTrustOpDart _setTrustLevel;
  late final _PhalanxPetNameDart _assignPetName;
  late final _PhalanxRemovePeerDart _removePeer;
  late final _PhalanxStartPlaybackDart _startPlayback;
  late final _PhalanxPollFrameDart _pollVideoFrame;
  late final _PhalanxPollFrameDart _pollAudioFrame;
  late final _PhalanxStopPlaybackDart _stopPlayback;
  late final _PhalanxShareLinkDart _getShareLink;
  late final _PhalanxOpenLinkDart _openLink;
  late final _PhalanxExportC2paDart _exportC2pa;
  late final _PhalanxFreeStringDart _freeString;
  late final _PhalanxFreeBytesDart _freeBytes;

  PhalanxBridge() {
    _lib = loadPhalanxLibrary();
    _bindFunctions();
  }

  void _bindFunctions() {
    _create = _lib.lookupFunction<_PhalanxCreateC, _PhalanxCreateDart>(
      'phalanx_create',
    );
    _start = _lib.lookupFunction<_PhalanxI32HandleC, _PhalanxI32HandleDart>(
      'phalanx_start',
    );
    _stop = _lib.lookupFunction<_PhalanxI32HandleC, _PhalanxI32HandleDart>(
      'phalanx_stop',
    );
    _destroy = _lib.lookupFunction<_PhalanxDestroyC, _PhalanxDestroyDart>(
      'phalanx_destroy',
    );
    _getPowerState =
        _lib.lookupFunction<_PhalanxI32HandleC, _PhalanxI32HandleDart>(
          'phalanx_get_power_state',
        );
    _isRecording =
        _lib.lookupFunction<_PhalanxI32HandleC, _PhalanxI32HandleDart>(
          'phalanx_is_recording',
        );
    _getTargetFps =
        _lib.lookupFunction<_PhalanxI32HandleC, _PhalanxI32HandleDart>(
          'phalanx_get_target_fps',
        );
    _getNodeDid = _lib.lookupFunction<_PhalanxGetDidC, _PhalanxGetDidDart>(
      'phalanx_get_node_did',
    );
    _updateBattery =
        _lib.lookupFunction<_PhalanxUpdateBatteryC, _PhalanxUpdateBatteryDart>(
          'phalanx_update_battery',
        );
    _updateThermal =
        _lib.lookupFunction<_PhalanxUpdateThermalC, _PhalanxUpdateThermalDart>(
          'phalanx_update_thermal',
        );
    _updateLifecycle = _lib.lookupFunction<
      _PhalanxUpdateLifecycleC,
      _PhalanxUpdateLifecycleDart
    >('phalanx_update_lifecycle');
    _startRecording = _lib.lookupFunction<
      _PhalanxStartRecordingC,
      _PhalanxStartRecordingDart
    >('phalanx_start_recording');
    _stopRecording =
        _lib.lookupFunction<_PhalanxI32HandleC, _PhalanxI32HandleDart>(
          'phalanx_stop_recording',
        );
    _pushFrame = _lib.lookupFunction<_PhalanxPushFrameC, _PhalanxPushFrameDart>(
      'phalanx_push_video_frame',
    );
    _pushAudio =
        _lib.lookupFunction<_PhalanxPushAudioC, _PhalanxPushAudioDart>(
          'phalanx_push_audio_frame',
        );
    _getPeers = _lib.lookupFunction<_PhalanxGetPeersC, _PhalanxGetPeersDart>(
      'phalanx_get_peers',
    );
    _setTrustLevel =
        _lib.lookupFunction<_PhalanxTrustOpC, _PhalanxTrustOpDart>(
          'phalanx_set_trust_level',
        );
    _assignPetName =
        _lib.lookupFunction<_PhalanxPetNameC, _PhalanxPetNameDart>(
          'phalanx_assign_pet_name',
        );
    _removePeer =
        _lib.lookupFunction<_PhalanxRemovePeerC, _PhalanxRemovePeerDart>(
          'phalanx_remove_peer',
        );
    _startPlayback = _lib.lookupFunction<
      _PhalanxStartPlaybackC,
      _PhalanxStartPlaybackDart
    >('phalanx_start_playback');
    _pollVideoFrame =
        _lib.lookupFunction<_PhalanxPollFrameC, _PhalanxPollFrameDart>(
          'phalanx_poll_video_frame',
        );
    _pollAudioFrame =
        _lib.lookupFunction<_PhalanxPollFrameC, _PhalanxPollFrameDart>(
          'phalanx_poll_audio_frame',
        );
    _stopPlayback =
        _lib.lookupFunction<_PhalanxStopPlaybackC, _PhalanxStopPlaybackDart>(
          'phalanx_stop_playback',
        );
    _getShareLink =
        _lib.lookupFunction<_PhalanxShareLinkC, _PhalanxShareLinkDart>(
          'phalanx_get_share_link',
        );
    _openLink = _lib.lookupFunction<_PhalanxOpenLinkC, _PhalanxOpenLinkDart>(
      'phalanx_open_link',
    );
    _exportC2pa =
        _lib.lookupFunction<_PhalanxExportC2paC, _PhalanxExportC2paDart>(
          'phalanx_export_c2pa',
        );
    _freeString =
        _lib.lookupFunction<_PhalanxFreeStringC, _PhalanxFreeStringDart>(
          'phalanx_free_string',
        );
    _freeBytes =
        _lib.lookupFunction<_PhalanxFreeBytesC, _PhalanxFreeBytesDart>(
          'phalanx_free_bytes',
        );
  }

  void _check(int code, String fn) {
    if (code < 0) throw PhalanxException(code, fn);
  }

  bool get isAlive => _handle != nullptr && !_destroyed;

  // =====================================================================
  // LIFECYCLE
  // =====================================================================

  /// Initialize the Phalanx engine with storage path and passphrase.
  void create(String storagePath, String passphrase, {String? configPath}) {
    final storageNative = storagePath.toNativeUtf8();
    final passphraseNative = passphrase.toNativeUtf8();
    final configNative = configPath?.toNativeUtf8() ?? nullptr;

    try {
      _handle = _create(
        configNative.cast(),
        storageNative.cast(),
        passphraseNative.cast(),
      );
      if (_handle == nullptr) {
        throw PhalanxException(PhalanxError.bootFailed, 'phalanx_create');
      }
    } finally {
      calloc.free(storageNative);
      calloc.free(passphraseNative);
      if (configNative != nullptr) calloc.free(configNative);
    }
  }

  /// Start the engine's run loop.
  void start() {
    _check(_start(_handle), 'phalanx_start');
  }

  /// Stop the engine gracefully.
  void stop() {
    _check(_stop(_handle), 'phalanx_stop');
  }

  /// Destroy the handle and free all resources.
  void destroy() {
    if (!_destroyed && _handle != nullptr) {
      _destroy(_handle);
      _handle = nullptr;
      _destroyed = true;
    }
  }

  // =====================================================================
  // STATUS
  // =====================================================================

  /// Current power state.
  PowerState get powerState => PowerState.fromInt(_getPowerState(_handle));

  /// Whether a recording is active.
  bool get isRecording => _isRecording(_handle) == 1;

  /// Target FPS based on current power state.
  int get targetFps => _getTargetFps(_handle);

  /// This node's DID.
  String get nodeDid {
    final out = calloc<Pointer<Utf8>>();
    try {
      _check(_getNodeDid(_handle, out), 'phalanx_get_node_did');
      final result = out.value.toDartString();
      _freeString(out.value);
      return result;
    } finally {
      calloc.free(out);
    }
  }

  // =====================================================================
  // PROBE UPDATES
  // =====================================================================

  /// Update battery level (0-100) and charging state.
  void updateBattery(int level, bool charging) {
    _check(
      _updateBattery(_handle, level, charging),
      'phalanx_update_battery',
    );
  }

  /// Update thermal reading in Celsius.
  void updateThermal(int celsius) {
    _check(_updateThermal(_handle, celsius), 'phalanx_update_thermal');
  }

  /// Update foreground/background lifecycle state.
  void updateLifecycle(bool isForeground) {
    _check(
      _updateLifecycle(_handle, isForeground),
      'phalanx_update_lifecycle',
    );
  }

  // =====================================================================
  // RECORDING
  // =====================================================================

  /// Start recording. Returns the recording ID.
  String startRecording() {
    final out = calloc<Pointer<Utf8>>();
    try {
      _check(_startRecording(_handle, out), 'phalanx_start_recording');
      final result = out.value.toDartString();
      _freeString(out.value);
      return result;
    } finally {
      calloc.free(out);
    }
  }

  /// Stop the current recording.
  void stopRecording() {
    _check(_stopRecording(_handle), 'phalanx_stop_recording');
  }

  /// Push a raw YUV video frame through the forensic pipeline.
  ///
  /// [yPlane] — luminance data (width × height bytes).
  /// [uvPlane] — interleaved chroma data (width × height / 2 bytes).
  /// [pixelFormat] — 0 = NV21 (Android), 1 = NV12 (iOS).
  /// [recordingId] — the ID returned from [startRecording].
  void pushVideoFrame(
    Uint8List yPlane,
    Uint8List uvPlane,
    int width,
    int height,
    int pixelFormat,
    String recordingId,
    int timestampMs,
  ) {
    final yNative = calloc<Uint8>(yPlane.length);
    final uvNative = calloc<Uint8>(uvPlane.length);
    final recNative = recordingId.toNativeUtf8();
    try {
      yNative.asTypedList(yPlane.length).setAll(0, yPlane);
      uvNative.asTypedList(uvPlane.length).setAll(0, uvPlane);
      _check(
        _pushFrame(
          _handle,
          yNative, yPlane.length,
          uvNative, uvPlane.length,
          width, height,
          pixelFormat,
          recNative.cast(),
          timestampMs,
        ),
        'phalanx_push_video_frame',
      );
    } finally {
      calloc.free(yNative);
      calloc.free(uvNative);
      calloc.free(recNative);
    }
  }

  /// Push a raw PCM audio frame through the forensic pipeline.
  ///
  /// [pcmData] — 16-bit LE PCM audio bytes.
  /// [sampleRate] — sample rate in Hz (e.g. 44100).
  /// [channels] — channel count (1 = mono, 2 = stereo).
  /// [recordingId] — the ID returned from [startRecording].
  void pushAudioFrame(
    Uint8List pcmData,
    int sampleRate,
    int channels,
    String recordingId,
  ) {
    final native = calloc<Uint8>(pcmData.length);
    final recNative = recordingId.toNativeUtf8();
    try {
      native.asTypedList(pcmData.length).setAll(0, pcmData);
      _check(
        _pushAudio(
          _handle,
          native, pcmData.length,
          sampleRate,
          channels,
          recNative.cast(),
        ),
        'phalanx_push_audio_frame',
      );
    } finally {
      calloc.free(native);
      calloc.free(recNative);
    }
  }

  // =====================================================================
  // TRUST / PEERS
  // =====================================================================

  /// Get list of all peers from the trust registry.
  List<PeerInfo> getPeers() {
    final out = calloc<Pointer<Utf8>>();
    try {
      _check(_getPeers(_handle, out), 'phalanx_get_peers');
      final json = out.value.toDartString();
      _freeString(out.value);
      final list = jsonDecode(json) as List;
      return list
          .map((e) => PeerInfo.fromJson(e as Map<String, dynamic>))
          .toList();
    } finally {
      calloc.free(out);
    }
  }

  /// Set trust level for a peer.
  void setTrustLevel(String did, TrustLevel level) {
    final didNative = did.toNativeUtf8();
    try {
      _check(
        _setTrustLevel(_handle, didNative.cast(), level.toInt()),
        'phalanx_set_trust_level',
      );
    } finally {
      calloc.free(didNative);
    }
  }

  /// Assign a pet name to a peer.
  void assignPetName(String did, String name) {
    final didNative = did.toNativeUtf8();
    final nameNative = name.toNativeUtf8();
    try {
      _check(
        _assignPetName(_handle, didNative.cast(), nameNative.cast()),
        'phalanx_assign_pet_name',
      );
    } finally {
      calloc.free(didNative);
      calloc.free(nameNative);
    }
  }

  /// Remove a peer from the trust registry.
  void removePeer(String did) {
    final didNative = did.toNativeUtf8();
    try {
      _check(
        _removePeer(_handle, didNative.cast()),
        'phalanx_remove_peer',
      );
    } finally {
      calloc.free(didNative);
    }
  }

  // =====================================================================
  // PLAYBACK
  // =====================================================================

  /// Start playback of a recording. Returns an opaque session pointer.
  ///
  /// Pass the returned pointer to [pollVideoFrame], [pollAudioFrame],
  /// and [stopPlayback]. The session owns the receiver channels.
  Pointer<Void> startPlayback(String recordingId) {
    final idNative = recordingId.toNativeUtf8();
    try {
      final session = _startPlayback(_handle, idNative.cast());
      if (session == nullptr) {
        throw PhalanxException(PhalanxError.playbackError, 'phalanx_start_playback');
      }
      return session;
    } finally {
      calloc.free(idNative);
    }
  }

  /// Poll for the next decoded video frame. Returns null if none available.
  Uint8List? pollVideoFrame(Pointer<Void> session) {
    return _pollChannel(session, _pollVideoFrame);
  }

  /// Poll for the next decoded audio frame. Returns null if none available.
  Uint8List? pollAudioFrame(Pointer<Void> session) {
    return _pollChannel(session, _pollAudioFrame);
  }

  /// Stop active playback and free the session.
  void stopPlayback(Pointer<Void> session) {
    _stopPlayback(session);
  }

  Uint8List? _pollChannel(
    Pointer<Void> session,
    int Function(Pointer<Void>, Pointer<Pointer<Uint8>>, Pointer<Uint32>) pollFn,
  ) {
    final outData = calloc<Pointer<Uint8>>();
    final outLen = calloc<Uint32>();
    try {
      final code = pollFn(session, outData, outLen);
      if (code < 0) return null;
      if (outData.value == nullptr) return null;

      final len = outLen.value;
      final bytes = Uint8List.fromList(outData.value.asTypedList(len));
      _freeBytes(outData.value, len);
      return bytes;
    } finally {
      calloc.free(outData);
      calloc.free(outLen);
    }
  }

  // =====================================================================
  // DEEP LINKS
  // =====================================================================

  /// Generate a phx:// share link for a recording.
  String getShareLink(String recordingId, String recipientDid) {
    final recNative = recordingId.toNativeUtf8();
    final didNative = recipientDid.toNativeUtf8();
    final out = calloc<Pointer<Utf8>>();
    try {
      _check(
        _getShareLink(_handle, recNative.cast(), didNative.cast(), out),
        'phalanx_get_share_link',
      );
      final result = out.value.toDartString();
      _freeString(out.value);
      return result;
    } finally {
      calloc.free(recNative);
      calloc.free(didNative);
      calloc.free(out);
    }
  }

  /// Export a recording frame as a C2PA-compliant JPEG with forensic metadata.
  void exportC2pa(String recordingId, String outPath) {
    final recNative = recordingId.toNativeUtf8();
    final pathNative = outPath.toNativeUtf8();
    try {
      _check(
        _exportC2pa(_handle, recNative.cast(), pathNative.cast()),
        'phalanx_export_c2pa',
      );
    } finally {
      calloc.free(recNative);
      calloc.free(pathNative);
    }
  }

  /// Open a received phx:// deep link — initiates retrieval from the mesh.
  void openLink(String phxLink) {
    final linkNative = phxLink.toNativeUtf8();
    try {
      _check(_openLink(_handle, linkNative.cast()), 'phalanx_open_link');
    } finally {
      calloc.free(linkNative);
    }
  }
}
