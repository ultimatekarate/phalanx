import 'dart:typed_data';

import 'package:flutter/material.dart';

import '../ffi/phalanx_bridge.dart';
import 'mnemonic_input_grid.dart';

/// Two-step dialog for Cryptographic Forgetting.
///
/// Step 1: Confirmation — warns the user this is irreversible.
/// Step 2: Mnemonic input — user types their 12-word recovery phrase
///         via the shared [MnemonicInputGrid] (obscured cells, per-cell
///         wordlist validation, single FFI checksum call before submit).
///
/// Returns `true` if the recording was successfully forgotten, `false`
/// otherwise.
Future<bool> showForgetRecordingDialog({
  required BuildContext context,
  required PhalanxBridge bridge,
  required String recordingId,
}) async {
  // Step 1: Confirmation
  final confirmed = await showDialog<bool>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: const Row(
        children: [
          Icon(Icons.warning_amber_rounded, color: Colors.red),
          SizedBox(width: 8),
          Text('Forget Recording'),
        ],
      ),
      content: const Text(
        'This will permanently destroy all evidence for this recording '
        'across the entire mesh. This action cannot be undone.\n\n'
        'You will need your 12-word recovery phrase to proceed.',
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(ctx).pop(false),
          child: const Text('Cancel'),
        ),
        ElevatedButton(
          onPressed: () => Navigator.of(ctx).pop(true),
          style: ElevatedButton.styleFrom(
            backgroundColor: Colors.red,
            foregroundColor: Colors.white,
          ),
          child: const Text('Continue'),
        ),
      ],
    ),
  );

  if (confirmed != true) return false;
  if (!context.mounted) return false;

  // Step 2: Mnemonic input
  final result = await showDialog<bool>(
    context: context,
    barrierDismissible: false,
    builder: (ctx) => _MnemonicInputDialog(
      bridge: bridge,
      recordingId: recordingId,
    ),
  );
  return result ?? false;
}

class _MnemonicInputDialog extends StatelessWidget {
  final PhalanxBridge bridge;
  final String recordingId;

  const _MnemonicInputDialog({
    required this.bridge,
    required this.recordingId,
  });

  String? _onSubmit(BuildContext ctx, Uint8List phrase) {
    try {
      bridge.forgetRecording(recordingId, phrase);
      Navigator.of(ctx).pop(true);
      return null;
    } on PhalanxException catch (e) {
      switch (e.code) {
        case PhalanxError.mnemonicParseError:
          return "That phrase isn't a valid 12-word BIP-39 recovery phrase.";
        case PhalanxError.revocationKeyMismatch:
          return "This phrase doesn't match this recording. "
              "Check that you're using the phrase from the device that captured it.";
        case PhalanxError.recordingNotFound:
          return 'Recording not found on this device or the mesh.';
        case PhalanxError.revocationFailed:
          return 'Revocation failed. Try again, or check connectivity.';
        default:
          return 'Operation failed (error ${e.code})';
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Enter Recovery Phrase'),
      content: SingleChildScrollView(
        child: MnemonicInputGrid(
          headerText:
              'Enter your 12-word recovery phrase to authorize the destruction '
              'of this recording.',
          submitLabel: 'Forget Forever',
          submitColor: Colors.red,
          onChecksumValidate: bridge.validateMnemonic,
          onSubmit: (phrase) => _onSubmit(context, phrase),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
      ],
    );
  }
}
