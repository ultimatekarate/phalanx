/// Audio playback controller wrapping flutter_pcm_sound.
///
/// Bridges the gap between Phalanx's push-based audio delivery (poll → feed)
/// and flutter_pcm_sound's pull-based callback model (native requests samples).
/// A ring buffer absorbs delivery jitter — Rust pushes PCM into the buffer,
/// and the native callback drains it.

import 'dart:collection';
import 'dart:typed_data';

import 'package:flutter_pcm_sound/flutter_pcm_sound.dart';

class AudioPlaybackController {
  bool _initialized = false;
  bool _initFailed = false;

  /// Buffered PCM samples waiting to be drained by the native callback.
  /// Each entry is a chunk of 16-bit LE PCM from a single audio shard.
  final Queue<Int16List> _buffer = Queue<Int16List>();

  /// Total number of samples (not bytes) currently buffered.
  int _bufferedSamples = 0;

  bool get isInitialized => _initialized;

  /// Try to initialize the audio output. No-op if already initialized.
  /// If init fails (missing permission, unsupported format), sets a flag
  /// and silently discards all future frames — no infinite retry loop.
  void tryInit(int sampleRate, int channels) {
    if (_initialized || _initFailed) return;
    try {
      FlutterPcmSound.setup(sampleRate: sampleRate, channelCount: channels);
      // Fire callback when buffer drops below ~0.25s of audio.
      // At 44100 Hz mono, that's ~11025 samples.
      final threshold = sampleRate ~/ 4;
      FlutterPcmSound.setFeedThreshold(threshold);
      FlutterPcmSound.setFeedCallback(_onFeedRequested);
      _initialized = true;
    } catch (_) {
      _initFailed = true;
    }
  }

  /// Push a chunk of raw 16-bit LE PCM into the ring buffer.
  /// Called from _drainAudio on each polled audio frame.
  void feed(Uint8List pcmBytes) {
    if (!_initialized || pcmBytes.isEmpty) return;

    // Convert raw bytes to Int16List (16-bit LE samples).
    // Uint8List from Rust is already LE on all supported platforms.
    final samples = pcmBytes.buffer.asInt16List(
      pcmBytes.offsetInBytes,
      pcmBytes.lengthInBytes ~/ 2,
    );
    _buffer.addLast(samples);
    _bufferedSamples += samples.length;
  }

  /// Native callback — flutter_pcm_sound requests more samples.
  void _onFeedRequested(int remainingFrames) {
    if (_buffer.isEmpty) return;

    // Drain up to the full buffer into a single feed call.
    // Merging avoids per-chunk overhead on the native bridge.
    final merged = Int16List(_bufferedSamples);
    var offset = 0;
    while (_buffer.isNotEmpty) {
      final chunk = _buffer.removeFirst();
      merged.setRange(offset, offset + chunk.length, chunk);
      offset += chunk.length;
    }
    _bufferedSamples = 0;

    FlutterPcmSound.feed(PcmArrayInt16(bytes: merged.buffer.asByteData()));
  }

  /// Release audio resources. Idempotent — safe to call multiple times.
  void dispose() {
    if (!_initialized) return;
    _buffer.clear();
    _bufferedSamples = 0;
    FlutterPcmSound.setFeedCallback(null);
    _initialized = false;
  }
}
