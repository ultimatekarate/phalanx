import 'package:flutter/material.dart';

import '../ffi/phalanx_bridge.dart';

/// Two-step dialog for Cryptographic Forgetting.
///
/// Step 1: Confirmation — warns the user this is irreversible.
/// Step 2: Mnemonic input — user types their 12-word recovery phrase.
///
/// Returns `true` if the recording was successfully forgotten, `false` otherwise.
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
  final controller = TextEditingController();
  try {
    final result = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => _MnemonicInputDialog(
        controller: controller,
        bridge: bridge,
        recordingId: recordingId,
      ),
    );
    return result ?? false;
  } finally {
    controller.dispose();
  }
}

class _MnemonicInputDialog extends StatefulWidget {
  final TextEditingController controller;
  final PhalanxBridge bridge;
  final String recordingId;

  const _MnemonicInputDialog({
    required this.controller,
    required this.bridge,
    required this.recordingId,
  });

  @override
  State<_MnemonicInputDialog> createState() => _MnemonicInputDialogState();
}

class _MnemonicInputDialogState extends State<_MnemonicInputDialog> {
  String? _error;
  bool _processing = false;

  void _submit() {
    final phrase = widget.controller.text.trim();
    if (phrase.isEmpty) {
      setState(() => _error = 'Please enter your recovery phrase');
      return;
    }

    setState(() {
      _error = null;
      _processing = true;
    });

    try {
      widget.bridge.forgetRecording(widget.recordingId, phrase);
      if (mounted) Navigator.of(context).pop(true);
    } on PhalanxException catch (e) {
      setState(() {
        _processing = false;
        if (e.code == PhalanxError.revocationFailed) {
          _error = 'Invalid recovery phrase or recording not found';
        } else {
          _error = 'Operation failed (error ${e.code})';
        }
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Enter Recovery Phrase'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const Text(
            'Enter your 12-word recovery phrase to authorize '
            'the destruction of this recording.',
            style: TextStyle(fontSize: 13, color: Colors.grey),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: widget.controller,
            decoration: InputDecoration(
              hintText: 'word1 word2 word3 ...',
              border: const OutlineInputBorder(),
              errorText: _error,
            ),
            maxLines: 2,
            autocorrect: false,
            enableSuggestions: false,
            enabled: !_processing,
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: _processing ? null : () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        ElevatedButton(
          onPressed: _processing ? null : _submit,
          style: ElevatedButton.styleFrom(
            backgroundColor: Colors.red,
            foregroundColor: Colors.white,
          ),
          child: _processing
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Text('Forget Forever'),
        ),
      ],
    );
  }
}
