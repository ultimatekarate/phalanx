import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'phalanx_provider.dart';

/// Recording state managed by the capture screen.
class RecordingState {
  final bool isRecording;
  final String? recordingId;
  final int targetFps;

  const RecordingState({
    this.isRecording = false,
    this.recordingId,
    this.targetFps = 30,
  });

  RecordingState copyWith({
    bool? isRecording,
    String? recordingId,
    int? targetFps,
  }) {
    return RecordingState(
      isRecording: isRecording ?? this.isRecording,
      recordingId: recordingId ?? this.recordingId,
      targetFps: targetFps ?? this.targetFps,
    );
  }
}

class RecordingNotifier extends StateNotifier<RecordingState> {
  final Ref _ref;

  RecordingNotifier(this._ref) : super(const RecordingState());

  void startRecording() {
    final bridge = _ref.read(phalanxProvider);
    final id = bridge.startRecording();
    state = state.copyWith(
      isRecording: true,
      recordingId: id,
      targetFps: bridge.targetFps,
    );
  }

  void stopRecording() {
    final bridge = _ref.read(phalanxProvider);
    bridge.stopRecording();
    state = state.copyWith(isRecording: false);
  }

  void refreshTargetFps() {
    final bridge = _ref.read(phalanxProvider);
    state = state.copyWith(targetFps: bridge.targetFps);
  }
}

final recordingProvider =
    StateNotifierProvider<RecordingNotifier, RecordingState>(
      (ref) => RecordingNotifier(ref),
    );
