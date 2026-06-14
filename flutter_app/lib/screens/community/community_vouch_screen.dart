// Community Vouch screen. Scan a VouchRequest QR, review it, sign it,
// and hand the response back to the organizer by QR / file / share.
//
// Structural pivot from earlier phases: signing happens on the voucher's
// phone, not on a second Stronghold. The wrapped request bytes round-trip
// through `phalanx_preview_vouch_request` for the review projection, then
// through `phalanx_sign_vouch_request` to produce a wrapped `VouchResponse`
// envelope. The Dart side never decodes the `VouchRequest` or
// `VouchResponse` itself — the raw bytes are opaque to Dart, which keeps
// the postcard surface here small.
//
// Import: this screen does NOT call `phalanx_import_community`. Signing
// for community X does not install X on this phone. The phone receives
// X later via the normal Join/Confirm path after the coordinator has
// finished assembly. Today's active community is untouched during
// vouching.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:share_plus/share_plus.dart';

import '../../ffi/community_models.dart';
import '../../providers/communities_provider.dart';

/// The three linear stages the voucher walks through: scan the
/// request, review its fields, display / save / share the signed
/// response.
enum _VouchStage { scan, review, signed }

class CommunityVouchScreen extends ConsumerStatefulWidget {
  const CommunityVouchScreen({super.key});

  @override
  ConsumerState<CommunityVouchScreen> createState() =>
      _CommunityVouchScreenState();
}

class _CommunityVouchScreenState extends ConsumerState<CommunityVouchScreen> {
  _VouchStage _stage = _VouchStage.scan;

  MobileScannerController? _scanner;
  bool _scannerHandled = false;

  /// Raw wrapped-envelope bytes as scanned or imported. Kept until the
  /// review stage offers "Sign", at which point the same bytes are
  /// handed to `phalanx_sign_vouch_request` — the Rust side strips the
  /// envelope again to recover the `VouchRequest`.
  Uint8List? _requestBytes;

  /// Review-safe projection produced by `phalanx_preview_vouch_request`.
  VouchRequestPreview? _preview;

  /// Wrapped `VouchResponse` envelope bytes produced by
  /// `phalanx_sign_vouch_request`. Rendered as a QR, written to a file,
  /// or attached to a share sheet.
  Uint8List? _responseBytes;

  /// Most recent user-facing error, if any. Surfaced in the current
  /// stage (overlay on scan, inline card on review).
  String? _errorMessage;

  /// Drives the freshness countdown on the Review stage. Cancelled
  /// when the stage advances or the screen pops.
  Timer? _freshnessTicker;

  @override
  void initState() {
    super.initState();
    _startScanner();
  }

  void _startScanner() {
    _scanner = MobileScannerController(
      detectionSpeed: DetectionSpeed.noDuplicates,
      facing: CameraFacing.back,
    );
    _scannerHandled = false;
  }

  @override
  void dispose() {
    _scanner?.dispose();
    _freshnessTicker?.cancel();
    super.dispose();
  }

  // ── Scan / import ───────────────────────────────────────────────────

  void _onDetect(BarcodeCapture capture) {
    if (_scannerHandled) return;
    for (final bc in capture.barcodes) {
      final raw = bc.rawValue;
      if (raw == null || raw.isEmpty) continue;
      _scannerHandled = true;
      _scanner?.stop();
      _ingestScannedText(raw);
      return;
    }
  }

  void _ingestScannedText(String text) {
    // Stronghold-side QR format: base64url (URL_SAFE_NO_PAD) of the
    // wrapped request envelope (see `render_qr_modal` in the ceremony
    // panel). Strip whitespace — some scanners wrap lines.
    final normalized = text.trim();
    Uint8List bytes;
    try {
      bytes = base64Url.decode(base64.normalize(normalized));
    } catch (_) {
      _showScanError('The scanned QR is not a Phalanx vouch request.');
      return;
    }
    _ingestBytes(bytes);
  }

  Future<void> _ingestFromFile() async {
    final result = await FilePicker.platform.pickFiles(
      dialogTitle: 'Import vouch request',
      type: FileType.custom,
      allowedExtensions: const ['bin', 'request'],
      withData: true,
    );
    if (result == null || result.files.isEmpty) return;
    final file = result.files.single;
    var bytes = file.bytes;
    if (bytes == null) {
      // Some Android SAF pickers return only a path. Fall back to a
      // plain file read before giving up.
      final path = file.path;
      if (path == null) {
        _showScanError('Could not read the selected file.');
        return;
      }
      try {
        bytes = await File(path).readAsBytes();
      } catch (e) {
        _showScanError('File read failed: $e');
        return;
      }
    }
    _ingestBytes(bytes);
  }

  void _ingestBytes(Uint8List bytes) {
    final notifier = ref.read(communitiesProvider.notifier);
    PreviewVouchOutcome outcome;
    try {
      outcome = notifier.previewVouchRequest(bytes);
    } on StateError catch (e) {
      _showScanError(e.message);
      return;
    } on FormatException catch (e) {
      _showScanError('Malformed vouch request: ${e.message}');
      return;
    }
    if (outcome is PreviewVouchOutcomeErr) {
      _showScanError(outcome.error.userMessage);
      return;
    }
    final preview = (outcome as PreviewVouchOutcomeOk).preview;
    setState(() {
      _requestBytes = bytes;
      _preview = preview;
      _errorMessage = null;
      _stage = _VouchStage.review;
    });
    _startFreshnessTicker();
    _disposeScanner();
  }

  void _showScanError(String message) {
    setState(() {
      _errorMessage = message;
      _stage = _VouchStage.scan;
    });
    _restartScanner();
  }

  void _restartScanner() {
    _scannerHandled = false;
    // If we disposed the scanner during a successful ingest, rebuild it.
    if (_scanner == null) {
      _startScanner();
      return;
    }
    unawaited(_scanner!.start());
  }

  void _disposeScanner() {
    _scanner?.dispose();
    _scanner = null;
  }

  // ── Review / sign ───────────────────────────────────────────────────

  void _startFreshnessTicker() {
    _freshnessTicker?.cancel();
    _freshnessTicker = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) setState(() {});
    });
  }

  void _cancel() {
    Navigator.of(context).pop();
  }

  void _sign() {
    final requestBytes = _requestBytes;
    if (requestBytes == null) return;
    final notifier = ref.read(communitiesProvider.notifier);
    SignVouchOutcome outcome;
    try {
      outcome = notifier.signVouchRequest(requestBytes);
    } on StateError catch (e) {
      setState(() => _errorMessage = e.message);
      return;
    } on FormatException catch (e) {
      setState(() => _errorMessage = 'Sign failed: ${e.message}');
      return;
    }
    if (outcome is SignVouchOutcomeErr) {
      final message = outcome.error.userMessage;
      setState(() => _errorMessage = message);
      return;
    }
    final responseBytes = (outcome as SignVouchOutcomeOk).wrappedResponse;
    setState(() {
      _responseBytes = responseBytes;
      _stage = _VouchStage.signed;
      _errorMessage = null;
    });
    _freshnessTicker?.cancel();
  }

  // ── Save / share ────────────────────────────────────────────────────

  String _responseFilename() {
    final preview = _preview;
    if (preview == null) return 'vouch-response.bin';
    return 'vouch-${preview.requestIdShortHex()}.response.bin';
  }

  Future<void> _save() async {
    final bytes = _responseBytes;
    if (bytes == null) return;
    try {
      final path = await FilePicker.platform.saveFile(
        dialogTitle: 'Save vouch response',
        fileName: _responseFilename(),
        bytes: bytes,
        type: FileType.custom,
        allowedExtensions: const ['bin'],
      );
      if (!mounted) return;
      if (path == null) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Saved.')),
      );
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Save failed: $e')),
      );
    }
  }

  Future<void> _share() async {
    final bytes = _responseBytes;
    if (bytes == null) return;
    try {
      await Share.shareXFiles(
        [
          XFile.fromData(
            bytes,
            name: _responseFilename(),
            mimeType: 'application/octet-stream',
          ),
        ],
        subject: 'Phalanx vouch response',
      );
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Share failed: $e')),
      );
    }
  }

  // ── Build ───────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(_titleFor(_stage))),
      body: switch (_stage) {
        _VouchStage.scan => _scanBody(),
        _VouchStage.review => _reviewBody(),
        _VouchStage.signed => _signedBody(),
      },
    );
  }

  String _titleFor(_VouchStage stage) => switch (stage) {
        _VouchStage.scan => 'Scan request QR',
        _VouchStage.review => 'Review vouch request',
        _VouchStage.signed => 'Vouch signed',
      };

  Widget _scanBody() {
    final scanner = _scanner;
    if (scanner == null) {
      // Re-entry after an ingest that was subsequently cancelled —
      // rebuild the controller.
      WidgetsBinding.instance.addPostFrameCallback(
        (_) => setState(_startScanner),
      );
      return const Center(child: CircularProgressIndicator());
    }
    return Stack(
      children: [
        MobileScanner(controller: scanner, onDetect: _onDetect),
        Positioned(
          top: 24,
          left: 24,
          right: 24,
          child: Card(
            color: Colors.black.withValues(alpha: 0.6),
            child: const Padding(
              padding: EdgeInsets.all(12),
              child: Text(
                'Scan the vouch request QR on the organizer\'s laptop. '
                'Phalanx will check the request is addressed to this '
                'phone before asking you to sign.',
                style: TextStyle(color: Colors.white),
                textAlign: TextAlign.center,
              ),
            ),
          ),
        ),
        if (_errorMessage != null)
          Positioned(
            top: 120,
            left: 24,
            right: 24,
            child: Card(
              color: Colors.red.shade900.withValues(alpha: 0.85),
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Text(
                  _errorMessage!,
                  style: const TextStyle(color: Colors.white),
                  textAlign: TextAlign.center,
                ),
              ),
            ),
          ),
        Positioned(
          bottom: 24,
          left: 24,
          right: 24,
          child: FilledButton.tonalIcon(
            onPressed: _ingestFromFile,
            icon: const Icon(Icons.folder_open),
            label: const Text('Import from file'),
          ),
        ),
      ],
    );
  }

  Widget _reviewBody() {
    final preview = _preview!;
    final now = DateTime.now().millisecondsSinceEpoch;
    // CEREMONY_RESPONSE_FRESHNESS_SECS = 3600 on the Rust side. The
    // countdown is a UX hint tied to `issued_at`; the hard freshness
    // gate that rejects stale responses uses the *signed*
    // `member_joined_at` on the coordinator side, not this value.
    const windowMs = 3600 * 1000;
    final expiryMs = preview.issuedAtMillis + windowMs;
    final remainingMs = (expiryMs - now).clamp(0, windowMs);
    final remaining = Duration(milliseconds: remainingMs);
    final isExpired = remainingMs <= 0;

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        _CommunityHeaderCard(preview: preview),
        const SizedBox(height: 12),
        _VouchTargetCard(memberDid: preview.memberDid),
        const SizedBox(height: 12),
        _RosterCard(members: preview.members),
        const SizedBox(height: 12),
        _FreshnessBar(isExpired: isExpired, remaining: remaining),
        if (_errorMessage != null) ...[
          const SizedBox(height: 12),
          Card(
            color: Colors.red.shade100,
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Text(
                _errorMessage!,
                style: const TextStyle(color: Colors.black),
              ),
            ),
          ),
        ],
        const SizedBox(height: 24),
        Row(
          children: [
            Expanded(
              child: OutlinedButton(
                onPressed: _cancel,
                child: const Text('Cancel'),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: FilledButton.icon(
                onPressed: isExpired ? null : _sign,
                icon: const Icon(Icons.verified_user),
                label: const Text('Sign vouch'),
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _signedBody() {
    final bytes = _responseBytes!;
    // Response QR format: base64url(URL_SAFE_NO_PAD) of the wrapped
    // envelope. Symmetric to the request QR rendered by the Stronghold
    // ceremony panel, so any future Stronghold-side camera / file
    // pipeline can decode response QRs the same way it decoded its
    // own request output.
    final payloadB64 =
        base64UrlEncode(bytes).replaceAll('=', '');
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              children: [
                const Text(
                  'Signed. Send this response back to the organizer.',
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 16),
                Center(
                  child: QrImageView(
                    data: payloadB64,
                    version: QrVersions.auto,
                    size: 260,
                    backgroundColor: Colors.white,
                  ),
                ),
                const SizedBox(height: 12),
                SelectableText(
                  payloadB64,
                  maxLines: 3,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 10,
                  ),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 16),
        Row(
          children: [
            Expanded(
              child: FilledButton.tonalIcon(
                onPressed: _save,
                icon: const Icon(Icons.save_alt),
                label: const Text('Save to file'),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: FilledButton.tonalIcon(
                onPressed: _share,
                icon: const Icon(Icons.share),
                label: const Text('Share'),
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        FilledButton(
          onPressed: _cancel,
          child: const Text('Done'),
        ),
      ],
    );
  }
}

// ── Review-stage sub-widgets ───────────────────────────────────────────
//
// Extracted for readability. They're stateless and unit-testable in
// isolation with `WidgetTester.pumpWidget`.

class _CommunityHeaderCard extends StatelessWidget {
  final VouchRequestPreview preview;
  const _CommunityHeaderCard({required this.preview});

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              preview.name,
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            const SizedBox(height: 4),
            Text(
              'Quorum ${preview.quorum} \u2022 '
              '${preview.members.length} members',
            ),
            const SizedBox(height: 8),
            SelectableText(
              'Fingerprint: ${preview.tentativeFingerprint.toShortHex()}',
              style: const TextStyle(fontFamily: 'monospace'),
            ),
          ],
        ),
      ),
    );
  }
}

class _VouchTargetCard extends StatelessWidget {
  final String memberDid;
  const _VouchTargetCard({required this.memberDid});

  @override
  Widget build(BuildContext context) {
    return Card(
      color: Theme.of(context).colorScheme.primaryContainer,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'You are vouching for',
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 6),
            SelectableText(
              memberDid,
              style: const TextStyle(fontFamily: 'monospace'),
            ),
          ],
        ),
      ),
    );
  }
}

class _RosterCard extends StatelessWidget {
  final List<String> members;
  const _RosterCard({required this.members});

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Full roster',
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 6),
            for (final did in members)
              Padding(
                padding: const EdgeInsets.only(bottom: 4),
                child: SelectableText(
                  did,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12,
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }
}

class _FreshnessBar extends StatelessWidget {
  final bool isExpired;
  final Duration remaining;
  const _FreshnessBar({required this.isExpired, required this.remaining});

  @override
  Widget build(BuildContext context) {
    final color = isExpired
        ? Colors.red
        : remaining.inMinutes < 5
            ? Colors.amber
            : Colors.green;
    final label = isExpired
        ? 'Request expired \u2014 ask the organizer for a fresh one.'
        : 'Request expires in ${_fmt(remaining)}';
    return Card(
      color: color.withValues(alpha: 0.15),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Row(
          children: [
            Icon(isExpired ? Icons.timer_off : Icons.timer, color: color),
            const SizedBox(width: 8),
            Expanded(
              child: Text(label, style: TextStyle(color: color)),
            ),
          ],
        ),
      ),
    );
  }

  String _fmt(Duration d) {
    if (d.inSeconds < 60) return '${d.inSeconds}s';
    final m = d.inMinutes;
    final s = d.inSeconds - m * 60;
    return '${m}m ${s}s';
  }
}
