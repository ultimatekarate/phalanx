import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phalanx/utils/recording_utils.dart';

void main() {
  group('formatRecordingId', () {
    test('formats standard recording ID with epoch timestamp', () {
      // 1774832454134 ms = some future date
      final result = formatRecordingId('rec-did:key:-1774832454134');
      // Should parse the last segment as epoch ms
      expect(result, isNot('rec-did:key:-1774832454134'));
      expect(result, matches(RegExp(r'\d+/\d+ \d{2}:\d{2}:\d{2}')));
    });

    test('handles negative epoch (abs applied)', () {
      // The abs() in the implementation handles negative timestamps
      final result1 = formatRecordingId('rec-prefix-1000000000000');
      final result2 = formatRecordingId('rec-prefix--1000000000000');
      // Both should parse to the same absolute timestamp
      expect(result1, matches(RegExp(r'\d+/\d+ \d{2}:\d{2}:\d{2}')));
      expect(result2, matches(RegExp(r'\d+/\d+ \d{2}:\d{2}:\d{2}')));
    });

    test('returns raw ID when fewer than 3 parts', () {
      expect(formatRecordingId('simple'), 'simple');
      expect(formatRecordingId('two-parts'), 'two-parts');
    });

    test('returns raw ID when last part is not numeric', () {
      expect(formatRecordingId('rec-did-notanumber'), 'rec-did-notanumber');
    });

    test('handles recording ID with many dashes in DID', () {
      // did:key: contains colons, not dashes — but the DID prefix might
      final result = formatRecordingId('rec-did:key:-1709312400000');
      expect(result, matches(RegExp(r'\d+/\d+ \d{2}:\d{2}:\d{2}')));
    });

    test('formats known epoch correctly', () {
      // 2024-03-01 12:00:00 UTC = 1709294400000 ms
      final result = formatRecordingId('rec-prefix-1709294400000');
      // We can't check exact local time (timezone dependent), but format is correct
      expect(result, matches(RegExp(r'\d{1,2}/\d{1,2} \d{2}:\d{2}:\d{2}')));
    });

    test('handles zero epoch', () {
      final result = formatRecordingId('rec-prefix-0');
      // Epoch 0 = Jan 1, 1970 — should still format
      expect(result, matches(RegExp(r'\d+/\d+ \d{2}:\d{2}:\d{2}')));
    });
  });

  group('parseVideoFrame', () {
    test('returns null for data shorter than 9 bytes', () {
      expect(parseVideoFrame(Uint8List(0)), isNull);
      expect(parseVideoFrame(Uint8List(8)), isNull);
    });

    test('returns null for exactly 8 bytes (no payload)', () {
      expect(parseVideoFrame(Uint8List(8)), isNull);
    });

    test('parses valid frame with timestamp and payload', () {
      // Build a frame: 8-byte LE timestamp + JPEG data
      final tsMs = 1709294400000; // 2024-03-01 12:00:00 UTC
      final jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00]; // JPEG header bytes

      final data = ByteData(8 + jpeg.length);
      data.setUint64(0, tsMs, Endian.little);
      final bytes = Uint8List.view(data.buffer);
      for (var i = 0; i < jpeg.length; i++) {
        bytes[8 + i] = jpeg[i];
      }

      final result = parseVideoFrame(bytes);

      expect(result, isNotNull);
      expect(result!.timestampMs, tsMs);
      expect(result.jpeg.length, jpeg.length);
      expect(result.jpeg[0], 0xFF); // JPEG SOI marker
      expect(result.jpeg[1], 0xD8);
    });

    test('handles minimum valid frame (9 bytes: 8 timestamp + 1 payload)', () {
      final data = Uint8List(9);
      data[8] = 0x42; // single payload byte

      final result = parseVideoFrame(data);

      expect(result, isNotNull);
      expect(result!.timestampMs, 0); // all-zero timestamp
      expect(result.jpeg.length, 1);
      expect(result.jpeg[0], 0x42);
    });

    test('preserves exact timestamp from LE encoding', () {
      final data = ByteData(9);
      // Set a specific timestamp: 0x0000_0001_0000_0000 = 4294967296
      data.setUint64(0, 4294967296, Endian.little);
      data.setUint8(8, 0xFF);

      final result = parseVideoFrame(Uint8List.view(data.buffer));
      expect(result!.timestampMs, 4294967296);
    });

    test('large JPEG payload preserved exactly', () {
      // Simulate a 120KB JPEG frame
      const jpegSize = 120000;
      final data = Uint8List(8 + jpegSize);
      // Fill JPEG region with a pattern
      for (var i = 0; i < jpegSize; i++) {
        data[8 + i] = i & 0xFF;
      }

      final result = parseVideoFrame(data);

      expect(result, isNotNull);
      expect(result!.jpeg.length, jpegSize);
      // Verify pattern preserved
      for (var i = 0; i < jpegSize; i++) {
        expect(result.jpeg[i], i & 0xFF);
      }
    });
  });

  group('computeFrameDelay', () {
    test('returns 0 for first frame (lastTimestamp is 0)', () {
      expect(computeFrameDelay(1000, 0), 0);
    });

    test('returns 0 for negative lastTimestamp', () {
      expect(computeFrameDelay(1000, -1), 0);
    });

    test('returns delta for normal frame spacing', () {
      // 30fps: ~33ms between frames
      expect(computeFrameDelay(1033, 1000), 33);
    });

    test('returns delta for 10fps pacing', () {
      expect(computeFrameDelay(1100, 1000), 100);
    });

    test('returns delta for adaptive FPS transition', () {
      // Battery dropped: FPS went from 30 to 6 mid-recording
      expect(computeFrameDelay(1166, 1000), 166);
    });

    test('returns 0 for delta >= 1000ms (recording gap)', () {
      // 1-second gap — likely a recording pause or missing shard
      expect(computeFrameDelay(2000, 1000), 0);
      expect(computeFrameDelay(5000, 1000), 0);
    });

    test('returns 0 for exactly 1000ms delta', () {
      // Boundary: >= 1000 is treated as a gap
      expect(computeFrameDelay(2000, 1000), 0);
    });

    test('returns 999 for 999ms delta', () {
      // Just under the gap threshold
      expect(computeFrameDelay(1999, 1000), 999);
    });

    test('returns 0 for zero delta (duplicate timestamp)', () {
      expect(computeFrameDelay(1000, 1000), 0);
    });

    test('returns 0 for negative delta (timestamp went backwards)', () {
      // Should not happen in practice, but guard against it
      expect(computeFrameDelay(900, 1000), 0);
    });

    test('handles large timestamps correctly', () {
      // Real epoch timestamps: ~1.7 trillion ms
      const t1 = 1709294400000;
      const t2 = 1709294400066; // 66ms later (~15fps)
      expect(computeFrameDelay(t2, t1), 66);
    });
  });

  group('parseAudioFrame', () {
    /// Build a well-formed 6-byte audio header + PCM payload.
    Uint8List makeAudioFrame(int sampleRate, int channels, List<int> pcmBytes) {
      final buf = ByteData(6 + pcmBytes.length);
      buf.setUint32(0, sampleRate, Endian.little);
      buf.setUint8(4, channels);
      buf.setUint8(5, 0); // reserved
      final bytes = Uint8List.view(buf.buffer);
      for (var i = 0; i < pcmBytes.length; i++) {
        bytes[6 + i] = pcmBytes[i];
      }
      return bytes;
    }

    test('parses valid mono 44100Hz frame', () {
      final data = makeAudioFrame(44100, 1, [0x80, 0x00, 0x7F, 0xFF]);
      final result = parseAudioFrame(data);
      expect(result, isNotNull);
      expect(result!.sampleRate, 44100);
      expect(result.channels, 1);
      expect(result.pcm.length, 4);
      expect(result.pcm[0], 0x80);
    });

    test('parses valid stereo 48000Hz frame', () {
      final data = makeAudioFrame(48000, 2, [0x01, 0x02, 0x03, 0x04]);
      final result = parseAudioFrame(data);
      expect(result, isNotNull);
      expect(result!.sampleRate, 48000);
      expect(result.channels, 2);
    });

    test('returns null for data shorter than 7 bytes', () {
      expect(parseAudioFrame(Uint8List(0)), isNull);
      expect(parseAudioFrame(Uint8List(6)), isNull);
    });

    test('returns null for sample_rate = 0', () {
      final data = makeAudioFrame(0, 1, [0x00, 0x00]);
      expect(parseAudioFrame(data), isNull);
    });

    test('returns null for sample_rate > 192000', () {
      final data = makeAudioFrame(192001, 1, [0x00, 0x00]);
      expect(parseAudioFrame(data), isNull);
    });

    test('returns null for channels = 0', () {
      final data = makeAudioFrame(44100, 0, [0x00, 0x00]);
      expect(parseAudioFrame(data), isNull);
    });

    test('returns null for channels > 8', () {
      final data = makeAudioFrame(44100, 9, [0x00, 0x00]);
      expect(parseAudioFrame(data), isNull);
    });

    test('returns null for odd-length PCM (corrupted)', () {
      // 3 bytes of PCM = odd, invalid for 16-bit LE
      final data = makeAudioFrame(44100, 1, [0x00, 0x00, 0x01]);
      expect(parseAudioFrame(data), isNull);
    });

    test('accepts boundary sample_rate = 1', () {
      final data = makeAudioFrame(1, 1, [0x00, 0x00]);
      final result = parseAudioFrame(data);
      expect(result, isNotNull);
      expect(result!.sampleRate, 1);
    });

    test('accepts boundary sample_rate = 192000', () {
      final data = makeAudioFrame(192000, 1, [0x00, 0x00]);
      final result = parseAudioFrame(data);
      expect(result, isNotNull);
      expect(result!.sampleRate, 192000);
    });

    test('accepts boundary channels = 8', () {
      final data = makeAudioFrame(44100, 8, [0x00, 0x00]);
      final result = parseAudioFrame(data);
      expect(result, isNotNull);
      expect(result!.channels, 8);
    });
  });
}
