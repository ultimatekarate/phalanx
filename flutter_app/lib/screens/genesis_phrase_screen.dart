import 'package:flutter/material.dart';

import '../services/screen_security.dart';

/// Displays the BIP39 recovery phrase during first-time identity creation.
///
/// This screen is shown exactly once — when a new identity is generated.
/// The user must acknowledge they have saved their 12 words before proceeding.
/// These words are the ONLY way to exercise Cryptographic Forgetting.
class GenesisPhraseScreen extends StatefulWidget {
  final String phrase;
  final VoidCallback onAcknowledged;

  const GenesisPhraseScreen({
    super.key,
    required this.phrase,
    required this.onAcknowledged,
  });

  @override
  State<GenesisPhraseScreen> createState() => _GenesisPhraseScreenState();
}

class _GenesisPhraseScreenState extends State<GenesisPhraseScreen> {
  bool _acknowledged = false;

  List<String> get _words => widget.phrase.split(' ');

  @override
  void initState() {
    super.initState();
    // Block Android screenshots / iOS recents snapshot for the lifetime
    // of this screen. iOS is a stub until the AppDelegate scaffold lands;
    // ScreenSecurity degrades silently on platforms without a handler.
    ScreenSecurity.enableSecure();
  }

  @override
  void dispose() {
    ScreenSecurity.disableSecure();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Recovery Phrase'),
        automaticallyImplyLeading: false, // No back button — must acknowledge
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Icon(Icons.key, size: 48, color: Colors.amber),
              const SizedBox(height: 16),
              const Text(
                'Save Your Recovery Phrase',
                style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 12),
              const Text(
                'These 12 words are the only way to exercise '
                'Cryptographic Forgetting — the ability to permanently '
                'destroy a recording from the entire mesh. '
                'Write them down and keep them safe.',
                style: TextStyle(fontSize: 14, color: Colors.grey),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 8),
              const Text(
                'Never share your recovery phrase with anyone, ever — '
                'it grants both recovery and destruction of your evidence.',
                style: TextStyle(
                  fontSize: 13,
                  color: Colors.redAccent,
                  fontWeight: FontWeight.w500,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 24),
              // Word grid
              Expanded(
                child: GridView.count(
                  crossAxisCount: 3,
                  childAspectRatio: 2.5,
                  crossAxisSpacing: 8,
                  mainAxisSpacing: 8,
                  children: List.generate(_words.length, (index) {
                    return Container(
                      decoration: BoxDecoration(
                        color: Colors.grey.shade900,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: Colors.grey.shade700),
                      ),
                      alignment: Alignment.center,
                      child: Text(
                        '${index + 1}. ${_words[index]}',
                        style: const TextStyle(
                          fontSize: 14,
                          fontWeight: FontWeight.w500,
                          fontFamily: 'monospace',
                        ),
                      ),
                    );
                  }),
                ),
              ),
              const SizedBox(height: 16),
              // Acknowledgment checkbox
              CheckboxListTile(
                value: _acknowledged,
                onChanged: (v) => setState(() => _acknowledged = v ?? false),
                title: const Text(
                  'I have saved my recovery phrase',
                  style: TextStyle(fontSize: 14),
                ),
                controlAffinity: ListTileControlAffinity.leading,
                contentPadding: EdgeInsets.zero,
              ),
              const SizedBox(height: 8),
              // Continue button
              ElevatedButton(
                onPressed: _acknowledged ? widget.onAcknowledged : null,
                style: ElevatedButton.styleFrom(
                  padding: const EdgeInsets.symmetric(vertical: 16),
                ),
                child: const Text('Continue'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
