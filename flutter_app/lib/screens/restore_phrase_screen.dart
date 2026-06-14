import 'dart:typed_data';

import 'package:flutter/material.dart';

import '../ffi/phalanx_bridge.dart';
import '../widgets/mnemonic_input_grid.dart';

/// Onboarding screen for restoring an existing identity from a 12-word
/// BIP-39 recovery phrase.
///
/// Wraps the shared [MnemonicInputGrid] with restore-specific copy and a
/// "Restore Identity" submit label. On successful submit, calls
/// [onRestored] with no arguments — the caller (typically `main.dart`)
/// transitions out of onboarding into the normal app shell.
///
/// The screen does NOT start the engine after restore — that's the caller's
/// responsibility (so the caller can wire up the post-restore manifest-walk
/// progress UI). The grid's `onSubmit` invokes `bridge.restoreFromPhrase`
/// and returns null on success or an error message on failure (the grid
/// displays the error inline so the user can retry without leaving the
/// screen).
class RestorePhraseScreen extends StatelessWidget {
  final PhalanxBridge bridge;
  final String storagePath;
  final String passphrase;

  /// The chosen deployment profile + optional Stronghold pairing. When
  /// [profileName] is non-null the restore goes through `restoreWithProfile`
  /// so the restored node adopts the selected topology; otherwise it falls back
  /// to the bare `restoreFromPhrase` (compiled defaults).
  final String? profileName;
  final String? strongholdAddr;
  final String? strongholdDid;
  final VoidCallback onRestored;

  const RestorePhraseScreen({
    super.key,
    required this.bridge,
    required this.storagePath,
    required this.passphrase,
    this.profileName,
    this.strongholdAddr,
    this.strongholdDid,
    required this.onRestored,
  });

  String? _onSubmit(BuildContext context, Uint8List phrase) {
    try {
      if (profileName != null) {
        bridge.restoreWithProfile(
          profileName!,
          storagePath,
          passphrase,
          phrase,
          strongholdAddr: strongholdAddr,
          strongholdDid: strongholdDid,
        );
      } else {
        bridge.restoreFromPhrase(storagePath, passphrase, phrase);
      }
      onRestored();
      return null;
    } on PhalanxException catch (e) {
      // phalanx_restore returns nullptr on any failure cause: the FFI
      // surface doesn't currently propagate the specific PhalanxError
      // code back. Since the grid calls `bridge.validateMnemonic` (which
      // distinguishes parse failures) before reaching this point, a
      // failure here is most likely either:
      //   - an identity.bin already on disk (UX should have caught this
      //     before navigation; treat as a stale-state bug),
      //   - a transport / vault / boot failure.
      return 'Restore failed (error ${e.code}). Make sure you have network '
          'connectivity and try again.';
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Restore Identity')),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Icon(Icons.restore, size: 48, color: Colors.amber),
                const SizedBox(height: 16),
                const Text(
                  'Restore your identity',
                  style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 12),
                const Text(
                  'Enter your 12-word recovery phrase to restore your identity '
                  'on this device. After restore, the app will reach out to the '
                  'mesh and pull any recordings you previously captured.',
                  style: TextStyle(fontSize: 14, color: Colors.grey),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 24),
                MnemonicInputGrid(
                  submitLabel: 'Restore Identity',
                  submitColor: Colors.amber.shade700,
                  onChecksumValidate: bridge.validateMnemonic,
                  onSubmit: (phrase) => _onSubmit(context, phrase),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
