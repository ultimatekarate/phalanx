import 'package:flutter_test/flutter_test.dart';
import 'package:phalanx/ffi/phalanx_bridge.dart';

void main() {
  group('PhalanxError codes', () {
    test('ok is zero', () {
      expect(PhalanxError.ok, 0);
    });

    test('all error codes are negative', () {
      expect(PhalanxError.nullPointer, isNegative);
      expect(PhalanxError.invalidState, isNegative);
      expect(PhalanxError.invalidUtf8, isNegative);
      expect(PhalanxError.bootFailed, isNegative);
      expect(PhalanxError.alreadyRunning, isNegative);
      expect(PhalanxError.notRunning, isNegative);
      expect(PhalanxError.channelClosed, isNegative);
      expect(PhalanxError.trustError, isNegative);
      expect(PhalanxError.playbackError, isNegative);
      expect(PhalanxError.configError, isNegative);
      expect(PhalanxError.alreadyRecording, isNegative);
      expect(PhalanxError.notRecording, isNegative);
      expect(PhalanxError.revocationFailed, isNegative);
    });

    test('all error codes are unique', () {
      final codes = [
        PhalanxError.nullPointer,
        PhalanxError.invalidState,
        PhalanxError.invalidUtf8,
        PhalanxError.bootFailed,
        PhalanxError.alreadyRunning,
        PhalanxError.notRunning,
        PhalanxError.channelClosed,
        PhalanxError.trustError,
        PhalanxError.playbackError,
        PhalanxError.configError,
        PhalanxError.alreadyRecording,
        PhalanxError.notRecording,
        PhalanxError.revocationFailed,
      ];
      expect(codes.toSet().length, codes.length, reason: 'Error codes must be unique');
    });
  });

  group('PhalanxException', () {
    test('stores code and function name', () {
      final e = PhalanxException(-1, 'phalanx_start');
      expect(e.code, -1);
      expect(e.function, 'phalanx_start');
    });

    test('toString includes function name and code', () {
      final e = PhalanxException(-4, 'phalanx_create');
      expect(e.toString(), contains('phalanx_create'));
      expect(e.toString(), contains('-4'));
    });

    test('implements Exception', () {
      expect(PhalanxException(0, 'test'), isA<Exception>());
    });
  });
}
