import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../ffi/phalanx_bridge.dart';
import '../services/pairing_link_service.dart';

/// Collect the Stronghold pairing (a dialable multiaddr + DID) for the
/// Community profile, by scanning the Stronghold's `stronghold pairing` QR or
/// pasting it. Mirrors `community_join_screen.dart` (the camera viewfinder
/// feeding a decode service), with a manual-paste fallback.
///
/// The decoded pairing is cross-checked with `phalanx_validate_pairing` before
/// it is returned, so a typo'd paste is caught here rather than surfacing as a
/// blank boot failure later. [onSkip] proceeds unpaired — an un-paired
/// Community still boots (passive gossip); the operator can pair later.
class StrongholdPairingScreen extends StatefulWidget {
  final PhalanxBridge bridge;
  final void Function(String addr, String did) onPaired;
  final VoidCallback onSkip;

  const StrongholdPairingScreen({
    super.key,
    required this.bridge,
    required this.onPaired,
    required this.onSkip,
  });

  @override
  State<StrongholdPairingScreen> createState() =>
      _StrongholdPairingScreenState();
}

class _StrongholdPairingScreenState extends State<StrongholdPairingScreen> {
  final MobileScannerController _controller = MobileScannerController(
    detectionSpeed: DetectionSpeed.noDuplicates,
    facing: CameraFacing.back,
  );
  final TextEditingController _paste = TextEditingController();
  bool _handled = false;
  String? _error;

  @override
  void dispose() {
    _controller.dispose();
    _paste.dispose();
    super.dispose();
  }

  void _accept(String raw) {
    final PairingInfo info;
    try {
      info = decodePairingPayload(raw);
    } on PairingDecodeError catch (e) {
      setState(() => _error = e.message);
      return;
    }
    // Cross-check dialability with the engine's own validator.
    final code = widget.bridge.validatePairing(
      info.addr,
      strongholdDid: info.did,
    );
    if (code != PhalanxError.ok) {
      setState(() => _error =
          'That pairing looks malformed (code $code). Ask the Stronghold '
          'operator to re-share it.');
      return;
    }
    _handled = true;
    _controller.stop();
    widget.onPaired(info.addr, info.did);
  }

  void _onDetect(BarcodeCapture capture) {
    if (_handled) return;
    for (final bc in capture.barcodes) {
      final raw = bc.rawValue;
      if (raw == null || raw.isEmpty) continue;
      _accept(raw);
      return;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Pair a Stronghold'),
        actions: [
          TextButton(
            onPressed: widget.onSkip,
            child: const Text('Skip for now'),
          ),
        ],
      ),
      body: SingleChildScrollView(
        child: Column(
          children: [
            SizedBox(
              height: 260,
              child: MobileScanner(controller: _controller, onDetect: _onDetect),
            ),
            Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Text(
                    "Scan the Stronghold's pairing QR, or paste it below. The "
                    'operator gets it by running `stronghold pairing`.',
                    style: TextStyle(color: Colors.grey, fontSize: 13),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _paste,
                    style: const TextStyle(color: Colors.white),
                    decoration: const InputDecoration(
                      labelText: 'phalanx://pair#data=…',
                      border: OutlineInputBorder(),
                    ),
                  ),
                  if (_error != null) ...[
                    const SizedBox(height: 8),
                    Text(
                      _error!,
                      style: const TextStyle(color: Colors.redAccent),
                    ),
                  ],
                  const SizedBox(height: 12),
                  ElevatedButton(
                    onPressed: () => _accept(_paste.text),
                    child: const Padding(
                      padding: EdgeInsets.symmetric(vertical: 12),
                      child: Text('Use pasted pairing'),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
