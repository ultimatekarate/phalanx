import 'package:flutter_test/flutter_test.dart';
import 'package:phalanx/providers/capture_provider.dart';

void main() {
  group('RecordingState', () {
    test('default state is not recording', () {
      const state = RecordingState();
      expect(state.isRecording, false);
      expect(state.recordingId, isNull);
      expect(state.targetFps, 30);
    });

    test('copyWith preserves unchanged fields', () {
      const original = RecordingState(
        isRecording: true,
        recordingId: 'rec-test-123',
        targetFps: 15,
      );

      final updated = original.copyWith(targetFps: 6);

      expect(updated.isRecording, true);
      expect(updated.recordingId, 'rec-test-123');
      expect(updated.targetFps, 6);
    });

    test('copyWith updates recording state', () {
      const original = RecordingState();

      final recording = original.copyWith(
        isRecording: true,
        recordingId: 'rec-did:key:-1709312400000',
      );

      expect(recording.isRecording, true);
      expect(recording.recordingId, 'rec-did:key:-1709312400000');
      expect(recording.targetFps, 30); // default unchanged
    });

    test('copyWith can stop recording', () {
      const recording = RecordingState(
        isRecording: true,
        recordingId: 'rec-test-123',
        targetFps: 15,
      );

      final stopped = recording.copyWith(isRecording: false);

      expect(stopped.isRecording, false);
      // recordingId preserved — last recording ID still accessible
      expect(stopped.recordingId, 'rec-test-123');
    });

    test('copyWith with no arguments returns equivalent state', () {
      const original = RecordingState(
        isRecording: true,
        recordingId: 'rec-test',
        targetFps: 10,
      );

      final copy = original.copyWith();

      expect(copy.isRecording, original.isRecording);
      expect(copy.recordingId, original.recordingId);
      expect(copy.targetFps, original.targetFps);
    });
  });
}
