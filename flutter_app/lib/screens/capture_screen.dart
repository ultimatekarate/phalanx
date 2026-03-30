import 'dart:async';
import 'dart:io' show Platform;
import 'dart:typed_data';

import 'package:camera/camera.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:record/record.dart';

import '../providers/capture_provider.dart';
import '../providers/phalanx_provider.dart';

/// The primary screen — full-bleed camera with a single record button.
///
/// Design principle: Nothing between the user and recording.
/// This is an emergency tool for people in adversarial situations.
/// Tap to record. Tap to stop. That's it.
class CaptureScreen extends ConsumerStatefulWidget {
  final bool emergencyMode;
  const CaptureScreen({super.key, this.emergencyMode = false});

  @override
  ConsumerState<CaptureScreen> createState() => _CaptureScreenState();
}

class _CaptureScreenState extends ConsumerState<CaptureScreen> {
  CameraController? _controller;
  bool _cameraReady = false;
  Timer? _fpsTimer;
  AudioRecorder? _audioRecorder;
  StreamSubscription<Uint8List>? _audioSub;
  int _lastFrameMs = 0;

  @override
  void initState() {
    super.initState();
    _initCamera();
  }

  Future<void> _initCamera() async {
    final cameras = await availableCameras();
    if (cameras.isEmpty) return;

    // Prefer back camera for evidence capture
    final camera = cameras.firstWhere(
      (c) => c.lensDirection == CameraLensDirection.back,
      orElse: () => cameras.first,
    );

    _controller = CameraController(
      camera,
      ResolutionPreset.high,
      enableAudio: false, // Audio handled separately
      imageFormatGroup: ImageFormatGroup.yuv420,
    );

    await _controller!.initialize();
    if (!mounted) return;

    setState(() => _cameraReady = true);

    // Emergency mode: start recording immediately
    if (widget.emergencyMode) {
      _toggleRecording();
    }
  }

  void _toggleRecording() {
    final notifier = ref.read(recordingProvider.notifier);
    final state = ref.read(recordingProvider);

    if (state.isRecording) {
      // Stop
      debugPrint('PHALANX: stopping recording');
      _controller?.stopImageStream();
      _fpsTimer?.cancel();
      _stopAudioCapture();
      notifier.stopRecording();
    } else {
      // Start
      debugPrint('PHALANX: startRecording...');
      try {
        notifier.startRecording();
      } catch (e) {
        debugPrint('PHALANX: startRecording FAILED: $e');
        return;
      }
      final recId = ref.read(recordingProvider).recordingId;
      debugPrint('PHALANX: recording started, id=$recId');
      _startFrameStream();
      debugPrint('PHALANX: frame stream started');
      _startAudioCapture();
      debugPrint('PHALANX: audio capture started');
    }
  }

  void _startFrameStream() {
    final bridge = ref.read(phalanxProvider);
    final recordingId = ref.read(recordingProvider).recordingId;
    if (recordingId == null) return;

    // CameraX (camera_android_camerax) delivers YUV_420_888 where plane[1] is U (Cb).
    // With pixelStride=2, bytes are U,V,U,V... = NV12 order on both Android and iOS.
    const pixelFormat = 1; // NV12

    _controller?.startImageStream((CameraImage image) {
      // Plane 0: Y (luminance) — width × height bytes
      // Plane 1: UV/VU (interleaved chroma) — width × height/2 bytes
      if (image.planes.length < 2) return;

      // Throttle to ~30 fps on the Dart side. The FFI call itself is non-blocking
      // (just a memcpy — compression runs on tokio's thread pool).
      // Actual capture rate is governed by Rust's target_fps() based on power state.
      final nowMs = DateTime.now().millisecondsSinceEpoch;
      if ((nowMs - _lastFrameMs) < 33) return;
      _lastFrameMs = nowMs;

      final yPlane = image.planes[0].bytes;
      final uvPlane = image.planes[1].bytes;
      final width = image.width;
      final height = image.height;

      try {
        bridge.pushVideoFrame(
          yPlane, uvPlane, width, height, pixelFormat, recordingId!, nowMs,
        );
      } catch (_) {
        // Frame dropped — the homeostatic integrals will adapt
      }
    });

    // Periodically refresh target FPS so the UI can display it
    _fpsTimer = Timer.periodic(const Duration(seconds: 5), (_) {
      ref.read(recordingProvider.notifier).refreshTargetFps();
    });
  }

  Future<void> _startAudioCapture() async {
    final bridge = ref.read(phalanxProvider);
    final recordingId = ref.read(recordingProvider).recordingId;
    if (recordingId == null) return;

    _audioRecorder = AudioRecorder();

    // Check permission
    if (!await _audioRecorder!.hasPermission()) return;

    // Start PCM stream: 16-bit LE, 44100 Hz, mono
    final stream = await _audioRecorder!.startStream(const RecordConfig(
      encoder: AudioEncoder.pcm16bits,
      sampleRate: 44100,
      numChannels: 1,
    ));

    _audioSub = stream.listen((Uint8List pcmBytes) {
      try {
        bridge.pushAudioFrame(pcmBytes, 44100, 1, recordingId);
      } catch (_) {
        // Audio chunk dropped — backpressure handled by Rust
      }
    });
  }

  void _stopAudioCapture() {
    _audioSub?.cancel();
    _audioSub = null;
    _audioRecorder?.stop();
    _audioRecorder?.dispose();
    _audioRecorder = null;
  }

  @override
  void dispose() {
    _fpsTimer?.cancel();
    _stopAudioCapture();
    _controller?.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final recording = ref.watch(recordingProvider);

    return Scaffold(
      backgroundColor: Colors.black,
      body: Stack(
        fit: StackFit.expand,
        children: [
          // Camera preview — full bleed, no chrome
          if (_cameraReady && _controller != null)
            CameraPreview(_controller!)
          else
            const Center(
              child: CircularProgressIndicator(color: Colors.white),
            ),

          // Recording indicator — subtle dot in top-right
          if (recording.isRecording)
            Positioned(
              top: MediaQuery.of(context).padding.top + 16,
              right: 16,
              child: _RecordingIndicator(),
            ),

          // Record button — bottom center
          Positioned(
            bottom: 48,
            left: 0,
            right: 0,
            child: Center(
              child: _RecordButton(
                isRecording: recording.isRecording,
                onTap: _cameraReady ? _toggleRecording : null,
              ),
            ),
          ),

          // Navigation — small menu icon in top-left
          Positioned(
            top: MediaQuery.of(context).padding.top + 8,
            left: 8,
            child: IconButton(
              icon: const Icon(Icons.menu, color: Colors.white70, size: 28),
              onPressed: () => _showNavigationSheet(context),
            ),
          ),
        ],
      ),
    );
  }

  void _showNavigationSheet(BuildContext context) {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.grey[900],
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.play_arrow, color: Colors.white),
              title: const Text(
                'Recordings',
                style: TextStyle(color: Colors.white),
              ),
              onTap: () {
                Navigator.pop(context);
                Navigator.pushNamed(context, '/playback');
              },
            ),
            ListTile(
              leading: const Icon(Icons.people, color: Colors.white),
              title: const Text(
                'Peers',
                style: TextStyle(color: Colors.white),
              ),
              onTap: () {
                Navigator.pop(context);
                Navigator.pushNamed(context, '/peers');
              },
            ),
            ListTile(
              leading: const Icon(Icons.settings, color: Colors.white),
              title: const Text(
                'Settings',
                style: TextStyle(color: Colors.white),
              ),
              onTap: () {
                Navigator.pop(context);
                Navigator.pushNamed(context, '/settings');
              },
            ),
          ],
        ),
      ),
    );
  }
}

/// The record button — large, unmistakable, emergency-grade.
class _RecordButton extends StatelessWidget {
  final bool isRecording;
  final VoidCallback? onTap;

  const _RecordButton({required this.isRecording, this.onTap});

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        width: 80,
        height: 80,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          border: Border.all(color: Colors.white, width: 4),
        ),
        child: Center(
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 200),
            width: isRecording ? 32 : 64,
            height: isRecording ? 32 : 64,
            decoration: BoxDecoration(
              color: Colors.red,
              borderRadius: BorderRadius.circular(isRecording ? 6 : 32),
            ),
          ),
        ),
      ),
    );
  }
}

/// Recording indicator — pulsing red dot.
class _RecordingIndicator extends StatefulWidget {
  @override
  State<_RecordingIndicator> createState() => _RecordingIndicatorState();
}

class _RecordingIndicatorState extends State<_RecordingIndicator>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1000),
    )..repeat(reverse: true);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return FadeTransition(
      opacity: _controller,
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 12,
            height: 12,
            decoration: const BoxDecoration(
              color: Colors.red,
              shape: BoxShape.circle,
            ),
          ),
          const SizedBox(width: 6),
          const Text(
            'REC',
            style: TextStyle(
              color: Colors.red,
              fontWeight: FontWeight.bold,
              fontSize: 14,
            ),
          ),
        ],
      ),
    );
  }
}
