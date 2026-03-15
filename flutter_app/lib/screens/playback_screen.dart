import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:share_plus/share_plus.dart';

import '../providers/phalanx_provider.dart';

/// Playback screen — list of recordings with tap-to-play and share.
class PlaybackScreen extends ConsumerStatefulWidget {
  const PlaybackScreen({super.key});

  @override
  ConsumerState<PlaybackScreen> createState() => _PlaybackScreenState();
}

class _PlaybackScreenState extends ConsumerState<PlaybackScreen> {
  String? _activeRecordingId;
  Uint8List? _currentFrame;
  Timer? _pollTimer;

  void _startPlayback(String recordingId) {
    final bridge = ref.read(phalanxProvider);
    try {
      bridge.startPlayback(recordingId);
      setState(() => _activeRecordingId = recordingId);

      // Poll for frames at ~30fps
      _pollTimer = Timer.periodic(const Duration(milliseconds: 33), (_) {
        final frame = bridge.pollPlaybackFrame();
        if (frame != null) {
          setState(() => _currentFrame = frame);
        }
      });
    } catch (e) {
      _showError('Playback failed: $e');
    }
  }

  void _stopPlayback() {
    _pollTimer?.cancel();
    _pollTimer = null;
    final bridge = ref.read(phalanxProvider);
    bridge.stopPlayback();
    setState(() {
      _activeRecordingId = null;
      _currentFrame = null;
    });
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

  void _showError(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(message)));
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
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
                  child: _currentFrame != null
                      ? Image.memory(
                          _currentFrame!,
                          fit: BoxFit.contain,
                          gaplessPlayback: true,
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
                ],
              ),
            ),

          // Recording list
          Expanded(
            flex: _activeRecordingId != null ? 1 : 3,
            child: _RecordingList(
              onPlay: _startPlayback,
              onShare: _shareRecording,
              activeId: _activeRecordingId,
            ),
          ),
        ],
      ),
    );
  }
}

/// Placeholder recording list.
/// In production, this queries the storage actor for available recordings.
class _RecordingList extends StatelessWidget {
  final void Function(String) onPlay;
  final void Function(String) onShare;
  final String? activeId;

  const _RecordingList({
    required this.onPlay,
    required this.onShare,
    this.activeId,
  });

  @override
  Widget build(BuildContext context) {
    // TODO: Replace with actual recording list from storage
    return const Center(
      child: Text(
        'Recordings will appear here after capture.',
        style: TextStyle(color: Colors.white54, fontSize: 16),
      ),
    );
  }
}
