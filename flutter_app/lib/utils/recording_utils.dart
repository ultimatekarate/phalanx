/// Utility functions for recording ID formatting and playback frame parsing.
///
/// Extracted from widget code to enable unit testing. These functions embody
/// the conventions of the Phalanx recording protocol:
///   - Recording IDs: "rec-{did_prefix}-{epoch_ms}"
///   - Video frames: 8-byte LE timestamp prefix + JPEG payload
///   - Audio frames: 6-byte metadata header (sample_rate, channels) + PCM payload

import 'dart:typed_data';

/// Extract a human-readable timestamp from a recording ID.
///
/// Recording IDs follow the format "rec-{did_prefix}-{epoch_ms}".
/// Returns a formatted date/time string, or the raw ID if parsing fails.
///
/// Example:
///   "rec-did:key:-1774832454134" → "3/30 14:20:54"
String formatRecordingId(String id) {
  final parts = id.split('-');
  if (parts.length >= 3) {
    final ms = int.tryParse(parts.last);
    if (ms != null) {
      final dt = DateTime.fromMillisecondsSinceEpoch(ms.abs());
      return '${dt.month}/${dt.day} '
          '${dt.hour.toString().padLeft(2, '0')}:'
          '${dt.minute.toString().padLeft(2, '0')}:'
          '${dt.second.toString().padLeft(2, '0')}';
    }
  }
  return id;
}

/// Result of parsing a timestamped video frame from the playback coordinator.
class TimestampedFrame {
  /// Epoch milliseconds from the coordinator's timestamp prefix.
  final int timestampMs;

  /// Raw JPEG bytes (after stripping the 8-byte timestamp prefix).
  final Uint8List jpeg;

  const TimestampedFrame({required this.timestampMs, required this.jpeg});
}

/// Parse a raw video frame from the coordinator into timestamp + JPEG payload.
///
/// The coordinator prepends an 8-byte little-endian u64 timestamp to each
/// JPEG frame. Returns null if the data is too short to contain a valid frame
/// (minimum 9 bytes: 8 timestamp + at least 1 byte payload).
TimestampedFrame? parseVideoFrame(Uint8List data) {
  if (data.length < 9) return null;

  final tsMs = ByteData.sublistView(data, 0, 8).getUint64(0, Endian.little);
  final jpeg = Uint8List.sublistView(data, 8);

  return TimestampedFrame(timestampMs: tsMs, jpeg: jpeg);
}

/// Result of parsing a 6-byte audio metadata header from the playback coordinator.
class AudioFrameHeader {
  /// Sample rate in Hz (e.g. 44100). Range: [1, 192000].
  final int sampleRate;

  /// Channel count (1 = mono, 2 = stereo). Range: [1, 8].
  final int channels;

  /// Raw PCM bytes (16-bit LE, after stripping the 6-byte header).
  final Uint8List pcm;

  const AudioFrameHeader({
    required this.sampleRate,
    required this.channels,
    required this.pcm,
  });
}

/// Parse a raw audio frame from the coordinator into metadata + PCM payload.
///
/// The coordinator prepends a 6-byte header:
///   bytes 0..4: sample_rate (u32 LE)
///   byte 4:    channels (u8)
///   byte 5:    reserved (0u8)
///   bytes 6..: raw 16-bit LE PCM
///
/// Returns null on malformed data — never throws.
AudioFrameHeader? parseAudioFrame(Uint8List data) {
  if (data.length < 7) return null; // 6 header + 1 byte PCM min

  final byteData = ByteData.sublistView(data, 0, 5);
  final sampleRate = byteData.getUint32(0, Endian.little);
  final channels = byteData.getUint8(4);

  // Validate ranges — match Rust-side SampleRate/ChannelCount constraints.
  if (sampleRate < 1 || sampleRate > 192000) return null;
  if (channels < 1 || channels > 8) return null;

  final pcm = Uint8List.sublistView(data, 6);
  // 16-bit LE PCM requires even byte count. Odd = corrupted decompression.
  if (pcm.length.isOdd) return null;

  return AudioFrameHeader(
    sampleRate: sampleRate,
    channels: channels,
    pcm: pcm,
  );
}

/// Compute the inter-frame delay for playback pacing.
///
/// Returns the number of milliseconds to wait before displaying this frame,
/// based on the delta between the current and previous timestamps.
///
/// Returns 0 for the first frame (no previous timestamp) or if the delta
/// is non-positive or exceeds 1 second (likely a recording gap).
int computeFrameDelay(int currentTimestampMs, int lastTimestampMs) {
  if (lastTimestampMs <= 0) return 0;

  final delta = currentTimestampMs - lastTimestampMs;
  if (delta > 0 && delta < 1000) return delta;

  return 0;
}
