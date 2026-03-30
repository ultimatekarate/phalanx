import 'dart:async';
import 'dart:ffi';

import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:share_plus/share_plus.dart';

import '../providers/phalanx_provider.dart';
import '../utils/audio_playback.dart';
import '../utils/recording_utils.dart';
import '../widgets/forget_dialog.dart';

/// Playback screen — list of recordings with tap-to-play and share.
class PlaybackScreen extends ConsumerStatefulWidget {
  const PlaybackScreen({super.key});

  @override
  ConsumerState<PlaybackScreen> createState() => _PlaybackScreenState();
}

class _PlaybackScreenState extends ConsumerState<PlaybackScreen> {
  String? _activeRecordingId;
  ui.Image? _currentImage;
  Timer? _pollTimer;
  bool _decoding = false;
  bool _drainingAudio = false;
  int _lastTimestampMs = 0;

  /// Opaque session pointer returned from Rust. Owns video + audio receivers.
  Pointer<Void>? _session;

  /// Audio output — lazily initialized from first audio frame's metadata.
  final AudioPlaybackController _audioController = AudioPlaybackController();

  void _startPlayback(String recordingId) {
    final bridge = ref.read(phalanxProvider);
    try {
      final session = bridge.startPlayback(recordingId);
      setState(() {
        _activeRecordingId = recordingId;
        _session = session;
      });

      // Poll at 16ms (60Hz check rate). Actual frame rate is governed by
      // timestamps embedded in each frame — adapts to capture FPS automatically.
      _pollTimer = Timer.periodic(const Duration(milliseconds: 16), (_) async {
        if (_session == null) return;

        // Audio: drain all available frames OUTSIDE the _decoding guard.
        // This ensures audio feeds continuously even during video pacing delays.
        _drainAudio(bridge);

        if (_decoding) return;

        // Acquire immediately — prevents re-entrant callbacks from polling
        // additional frames while we await the delay or decode below.
        _decoding = true;
        try {

          final data = bridge.pollVideoFrame(_session!);
          if (data == null) {
            _decoding = false;
            return;
          }

          final parsed = parseVideoFrame(data);
          if (parsed == null) {
            _decoding = false;
            return;
          }

          // Pace: sleep for the inter-frame delta before displaying
          final delayMs = computeFrameDelay(parsed.timestampMs, _lastTimestampMs);
          if (delayMs > 0) {
            await Future.delayed(Duration(milliseconds: delayMs));
          }
          _lastTimestampMs = parsed.timestampMs;

          // Async JPEG decode — runs on Flutter engine worker thread
          final codec = await ui.instantiateImageCodec(parsed.jpeg);
          final frame = await codec.getNextFrame();
          if (mounted) {
            _currentImage?.dispose();
            setState(() => _currentImage = frame.image);
          } else {
            frame.image.dispose();
          }
        } finally {
          _decoding = false;
        }
      });
    } catch (e) {
      _showError('Playback failed: $e');
    }
  }

  void _stopPlayback() {
    _pollTimer?.cancel();
    _pollTimer = null;
    _audioController.dispose();

    if (_session != null) {
      final bridge = ref.read(phalanxProvider);
      bridge.stopPlayback(_session!);
      _session = null;
    }

    _currentImage?.dispose();
    setState(() {
      _activeRecordingId = null;
      _currentImage = null;
      _lastTimestampMs = 0;
    });
  }

  /// Drain all buffered audio frames from Rust and feed to the audio controller.
  /// Runs outside the _decoding guard so audio is not starved by video pacing.
  void _drainAudio(dynamic bridge) {
    final s = _session;
    if (s == null || _drainingAudio) return;
    _drainingAudio = true;
    try {
      // Channel bounded at 8 frames — loop terminates in ≤8 iterations.
      while (true) {
        final audioData = bridge.pollAudioFrame(s);
        if (audioData == null) break;
        final frame = parseAudioFrame(audioData);
        if (frame == null) continue;
        _audioController.tryInit(frame.sampleRate, frame.channels);
        _audioController.feed(frame.pcm);
      }
    } finally {
      _drainingAudio = false;
    }
  }

  void _shareRecording(String recordingId) {
    final bridge = ref.read(phalanxProvider);
    // For now, share with a generic recipient — in production this would
    // be selected from the peer list.
    try {
      final link = bridge.getShareLink(recordingId, 'did:key:recipient');
      Share.share(link, subject: 'Phalanx Recording');
    } catch (e) {
      _showError('Share failed: $e');
    }
  }

  void _exportC2pa(String recordingId) {
    final bridge = ref.read(phalanxProvider);
    // Export to app's documents directory — will be MP4 after Part D
    final outPath = '/storage/emulated/0/Download/${recordingId}_c2pa.mp4';
    try {
      bridge.exportC2pa(recordingId, outPath);
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('C2PA export saved: $outPath')),
      );
    } catch (e) {
      _showError('C2PA export failed: $e');
    }
  }

  Future<void> _forgetRecording(String recordingId) async {
    // Stop playback first if this recording is active
    if (_activeRecordingId == recordingId) {
      _stopPlayback();
    }

    try {
      final bridge = ref.read(phalanxProvider);
      final forgotten = await showForgetRecordingDialog(
        context: context,
        bridge: bridge,
        recordingId: recordingId,
      );

      if (forgotten && mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Recording permanently forgotten'),
            duration: Duration(seconds: 3),
          ),
        );
        // TODO: Refresh recording list after successful revocation
      }
    } catch (e) {
      _showError('Forget failed: $e');
    }
  }

  void _debugDeleteRecording(String recordingId) {
    if (_activeRecordingId == recordingId) {
      _stopPlayback();
    }
    try {
      final bridge = ref.read(phalanxProvider);
      bridge.debugDeleteRecording(recordingId);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Recording deleted (debug)')),
        );
      }
    } catch (e) {
      _showError('Delete failed: $e');
    }
  }

  void _showError(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(message)));
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    _audioController.dispose();
    _currentImage?.dispose();
    if (_session != null) {
      final bridge = ref.read(phalanxProvider);
      bridge.stopPlayback(_session!);
      _session = null;
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: const Text('Recordings'),
        backgroundColor: Colors.grey[900],
      ),
      body: Column(
        children: [
          // Playback viewport
          if (_activeRecordingId != null)
            Expanded(
              flex: 2,
              child: Container(
                color: Colors.black,
                child: Center(
                  child: _currentImage != null
                      ? RawImage(
                          image: _currentImage,
                          fit: BoxFit.contain,
                        )
                      : const CircularProgressIndicator(color: Colors.white),
                ),
              ),
            ),

          // Playback controls
          if (_activeRecordingId != null)
            Container(
              color: Colors.grey[900],
              padding: const EdgeInsets.all(8),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  IconButton(
                    icon: const Icon(Icons.stop, color: Colors.red, size: 32),
                    onPressed: _stopPlayback,
                  ),
                  const SizedBox(width: 16),
                  IconButton(
                    icon: const Icon(
                      Icons.share,
                      color: Colors.white,
                      size: 28,
                    ),
                    onPressed: () => _shareRecording(_activeRecordingId!),
                  ),
                  const SizedBox(width: 16),
                  IconButton(
                    icon: const Icon(
                      Icons.verified_user,
                      color: Colors.blue,
                      size: 28,
                    ),
                    tooltip: 'Export as C2PA',
                    onPressed: () => _exportC2pa(_activeRecordingId!),
                  ),
                  const SizedBox(width: 16),
                  IconButton(
                    icon: const Icon(
                      Icons.delete_forever,
                      color: Colors.red,
                      size: 28,
                    ),
                    tooltip: 'Forget Recording',
                    onPressed: () => _forgetRecording(_activeRecordingId!),
                  ),
                ],
              ),
            ),

          // Recording list
          Expanded(
            flex: _activeRecordingId != null ? 1 : 3,
            child: _RecordingList(
              onPlay: _startPlayback,
              onShare: _shareRecording,
              onForget: _forgetRecording,
              onDebugDelete: _debugDeleteRecording,
              activeId: _activeRecordingId,
            ),
          ),
        ],
      ),
    );
  }
}

/// Recording list — queries the storage actor for available recordings.
class _RecordingList extends ConsumerStatefulWidget {
  final void Function(String) onPlay;
  final void Function(String) onShare;
  final void Function(String) onForget;
  final void Function(String) onDebugDelete;
  final String? activeId;

  const _RecordingList({
    required this.onPlay,
    required this.onShare,
    required this.onForget,
    required this.onDebugDelete,
    this.activeId,
  });

  @override
  ConsumerState<_RecordingList> createState() => _RecordingListState();
}

class _RecordingListState extends ConsumerState<_RecordingList> {
  List<String> _recordings = [];
  Timer? _refreshTimer;

  @override
  void initState() {
    super.initState();
    _refresh();
    // Poll every 3 seconds for new recordings
    _refreshTimer = Timer.periodic(const Duration(seconds: 3), (_) => _refresh());
  }

  void _refresh() {
    try {
      final bridge = ref.read(phalanxProvider);
      final ids = bridge.listRecordings();
      if (mounted) {
        setState(() => _recordings = ids.reversed.toList()); // newest first
      }
    } catch (_) {}
  }

  @override
  void dispose() {
    _refreshTimer?.cancel();
    super.dispose();
  }

  String _debugInfo(String id) {
    try {
      final bridge = ref.read(phalanxProvider);
      return bridge.debugRecordingInfo(id);
    } catch (_) {
      return id;
    }
  }

  String _formatId(String id) => formatRecordingId(id);

  @override
  Widget build(BuildContext context) {
    if (_recordings.isEmpty) {
      return const Center(
        child: Text(
          'No recordings yet.\nPress the red button to start.',
          textAlign: TextAlign.center,
          style: TextStyle(color: Colors.white54, fontSize: 16),
        ),
      );
    }

    return ListView.builder(
      itemCount: _recordings.length,
      itemBuilder: (context, index) {
        final id = _recordings[index];
        final isActive = id == widget.activeId;

        return ListTile(
          leading: Icon(
            isActive ? Icons.play_circle_filled : Icons.videocam,
            color: isActive ? Colors.red : Colors.white54,
          ),
          title: Text(
            _formatId(id),
            style: const TextStyle(color: Colors.white),
          ),
          subtitle: Text(
            _debugInfo(id),
            style: const TextStyle(color: Colors.white38, fontSize: 11),
            overflow: TextOverflow.ellipsis,
          ),
          trailing: PopupMenuButton<String>(
            icon: const Icon(Icons.more_vert, color: Colors.white54),
            color: Colors.grey[850],
            onSelected: (action) {
              switch (action) {
                case 'play':
                  widget.onPlay(id);
                case 'share':
                  widget.onShare(id);
                case 'delete':
                  widget.onDebugDelete(id);
                case 'forget':
                  widget.onForget(id);
              }
            },
            itemBuilder: (_) => [
              const PopupMenuItem(
                value: 'play',
                child: Text('Play', style: TextStyle(color: Colors.white)),
              ),
              const PopupMenuItem(
                value: 'share',
                child: Text('Share', style: TextStyle(color: Colors.white)),
              ),
              const PopupMenuItem(
                value: 'delete',
                child: Text('Delete (debug)', style: TextStyle(color: Colors.orange)),
              ),
              const PopupMenuItem(
                value: 'forget',
                child: Text('Forget Forever', style: TextStyle(color: Colors.red)),
              ),
            ],
          ),
          onTap: () => widget.onPlay(id),
        );
      },
    );
  }
}
