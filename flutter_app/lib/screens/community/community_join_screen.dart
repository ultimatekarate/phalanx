// Community Join screen. Hosts the camera viewfinder and feeds scanned
// text through `community_link_service.decodeJoinPayload` — on success
// it navigates to the Confirm screen, which is the *only* path to
// `phalanx_import_community`.

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../../services/community_link_service.dart';

class CommunityJoinScreen extends ConsumerStatefulWidget {
  const CommunityJoinScreen({super.key});

  @override
  ConsumerState<CommunityJoinScreen> createState() =>
      _CommunityJoinScreenState();
}

class _CommunityJoinScreenState extends ConsumerState<CommunityJoinScreen> {
  final MobileScannerController _controller = MobileScannerController(
    detectionSpeed: DetectionSpeed.noDuplicates,
    facing: CameraFacing.back,
  );
  bool _handled = false;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _onDetect(BarcodeCapture capture) {
    if (_handled) return;
    final barcodes = capture.barcodes;
    for (final bc in barcodes) {
      final raw = bc.rawValue;
      if (raw == null || raw.isEmpty) continue;
      try {
        final bytes = decodeJoinPayload(raw);
        _handled = true;
        _controller.stop();
        // The Confirm screen is the gatekeeper — it runs
        // `phalanx_preview_community` and requires the user to tap
        // "Join" before any import actually happens.
        Navigator.of(context)
            .pushReplacementNamed('/community/confirm', arguments: bytes);
        return;
      } on LinkDecodeError catch (e) {
        _handled = true;
        _controller.stop();
        showDialog<void>(
          context: context,
          builder: (_) => AlertDialog(
            title: const Text('Unrecognized QR'),
            content: Text(e.message),
            actions: [
              TextButton(
                onPressed: () {
                  Navigator.of(context).pop();
                  _handled = false;
                  _controller.start();
                },
                child: const Text('Try again'),
              ),
              TextButton(
                onPressed: () {
                  Navigator.of(context).pop();
                  Navigator.of(context).pop();
                },
                child: const Text('Cancel'),
              ),
            ],
          ),
        );
        return;
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Scan Community QR'),
      ),
      body: Stack(
        children: [
          MobileScanner(
            controller: _controller,
            onDetect: _onDetect,
          ),
          Positioned(
            bottom: 24,
            left: 24,
            right: 24,
            child: Card(
              color: Colors.black.withValues(alpha: 0.6),
              child: const Padding(
                padding: EdgeInsets.all(12),
                child: Text(
                  'Position the QR code in the frame. You will be asked to '
                  'confirm the community details before joining.',
                  style: TextStyle(color: Colors.white),
                  textAlign: TextAlign.center,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
