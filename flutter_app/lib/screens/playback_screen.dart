import 'dart:async';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:share_plus/share_plus.dart';

import '../providers/phalanx_provider.dart';
import '../widgets/forget_dialog.dart';

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

  /// Opaque session pointer returned from Rust. Owns video + audio receivers.
  Pointer<Void>? _session;

  void _startPlayback(String recordingId) {
    final bridge = ref.read(phalanxProvider);
    try {
      final session = bridge.startPlayback(recordingId);
      setState(() {
        _activeRecordingId = recordingId;
        _session = session;
      });

      // Poll for video + audio at ~30fps
      _pollTimer = Timer.periodic(const Duration(milliseconds: 33), (_) {
        if (_session == null) return;

        final frame = bridge.pollVideoFrame(_session!);
        if (frame != null) {
          setState(() => _currentFrame = frame);
        }

        // Poll audio — for now, discard (audio playback output TBD)
        final audio = bridge.pollAudioFrame(_session!);
        if (audio != null) {
          // TODO: feed PCM to audio output sink
        }
      });
    } catch (e) {
      _showError('Playback failed: $e');
    }
  }

  void _stopPlayback() {
    _pollTimer?.cancel();
    _pollTimer = null;

    if (_session != null) {
      final bridge = ref.read(phalanxProvider);
      bridge.stopPlayback(_session!);
      _session = null;
    }

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

  void _showError(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(message)));
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
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
  final void Function(String) onForget;
  final String? activeId;

  const _RecordingList({
    required this.onPlay,
    required this.onShare,
    required this.onForget,
    this.activeId,
  });

  @override
  Widget build(BuildContext context) {
    // TODO: Replace with actual recording list from storage.
    // Each recording tile should look like:
    //
    //   ListTile(
    //     title: Text(recording.id),
    //     subtitle: Text(recording.timestamp),
    //     trailing: PopupMenuButton<String>(
    //       onSelected: (action) {
    //         switch (action) {
    //           case 'play':   onPlay(recording.id);
    //           case 'share':  onShare(recording.id);
    //           case 'forget': onForget(recording.id);
    //         }
    //       },
    //       itemBuilder: (_) => [
    //         const PopupMenuItem(value: 'play',   child: Text('Play')),
    //         const PopupMenuItem(value: 'share',  child: Text('Share')),
    //         const PopupMenuItem(
    //           value: 'forget',
    //           child: Text('Forget Forever', style: TextStyle(color: Colors.red)),
    //         ),
    //       ],
    //     ),
    //   )
    //
    return const Center(
      child: Text(
        'Recordings will appear here after capture.',
        style: TextStyle(color: Colors.white54, fontSize: 16),
      ),
    );
  }
}
