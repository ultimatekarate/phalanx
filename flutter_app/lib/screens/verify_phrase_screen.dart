import 'dart:math';

import 'package:flutter/material.dart';

import '../services/screen_security.dart';

/// Verification step after the genesis phrase is shown. Picks two
/// pseudo-random positions from the 12-word phrase and asks the user to
/// type the words at those positions. Catches the "click-through without
/// saving" failure mode — for a forensic evidence tool, lost-phrase ==
/// lost-evidence, so we trade a small bit of friction for a real
/// recoverability guarantee.
///
/// The positions are chosen once at screen-creation time and remain stable
/// across rebuilds so the user isn't moving targets. If they're wrong, we
/// show an inline error and let them retry without bouncing back to the
/// genesis screen — that screen is also reachable via the back button so
/// they can re-review their saved copy.
class VerifyPhraseScreen extends StatefulWidget {
  /// The 12-word genesis phrase the user just saw. Used only to validate
  /// the typed words; never persisted, never logged, never re-shown.
  final String phrase;
  final VoidCallback onVerified;

  const VerifyPhraseScreen({
    super.key,
    required this.phrase,
    required this.onVerified,
  });

  @override
  State<VerifyPhraseScreen> createState() => _VerifyPhraseScreenState();
}

class _VerifyPhraseScreenState extends State<VerifyPhraseScreen> {
  late final List<String> _words;
  late final int _posA;
  late final int _posB;
  final _controllerA = TextEditingController();
  final _controllerB = TextEditingController();
  String? _error;

  @override
  void initState() {
    super.initState();
    _words = widget.phrase.split(' ');
    // Pick two distinct positions in [0, 11]. Deterministic seed = none;
    // we use the default secure-ish Random — good enough for an
    // anti-click-through challenge that the user themselves is solving.
    final rng = Random();
    _posA = rng.nextInt(_words.length);
    int b;
    do {
      b = rng.nextInt(_words.length);
    } while (b == _posA);
    _posB = b;
    ScreenSecurity.enableSecure();
  }

  @override
  void dispose() {
    ScreenSecurity.disableSecure();
    _controllerA.clear();
    _controllerA.dispose();
    _controllerB.clear();
    _controllerB.dispose();
    super.dispose();
  }

  void _onVerify() {
    final a = _controllerA.text.trim().toLowerCase();
    final b = _controllerB.text.trim().toLowerCase();
    if (a == _words[_posA] && b == _words[_posB]) {
      _controllerA.clear();
      _controllerB.clear();
      widget.onVerified();
      return;
    }
    setState(() {
      _error =
          "Those don't match the saved phrase. Go back, re-check the words, and try again.";
    });
  }

  Widget _buildCell(int position, TextEditingController controller) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: TextField(
        controller: controller,
        obscureText: true,
        autocorrect: false,
        enableSuggestions: false,
        style: const TextStyle(fontFamily: 'monospace'),
        decoration: InputDecoration(
          labelText: 'Word ${position + 1}',
          border: const OutlineInputBorder(),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Verify Recovery Phrase')),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const SizedBox(height: 12),
              const Text(
                'Confirm you saved your phrase',
                style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 8),
              const Text(
                'Type the two words at the positions below. Use the back '
                'button if you need to re-check your saved copy.',
                style: TextStyle(fontSize: 14, color: Colors.grey),
              ),
              const SizedBox(height: 24),
              _buildCell(_posA, _controllerA),
              _buildCell(_posB, _controllerB),
              if (_error != null) ...[
                const SizedBox(height: 12),
                Text(
                  _error!,
                  style: const TextStyle(color: Colors.redAccent, fontSize: 13),
                ),
              ],
              const SizedBox(height: 24),
              ElevatedButton(
                onPressed: _onVerify,
                style: ElevatedButton.styleFrom(
                  padding: const EdgeInsets.symmetric(vertical: 14),
                ),
                child: const Text('Verify and continue'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
