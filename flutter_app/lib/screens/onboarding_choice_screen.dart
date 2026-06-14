import 'package:flutter/material.dart';

/// First-launch onboarding choice: generate a new identity (the normal
/// path for someone using Phalanx for the first time) or restore an
/// existing identity from a BIP-39 recovery phrase (someone who lost
/// their device or reinstalled).
///
/// Shown when no `identity.bin` is found at the configured storage path.
/// The caller (`main.dart`) supplies callbacks that drive the respective
/// downstream flows.
class OnboardingChoiceScreen extends StatelessWidget {
  final VoidCallback onCreateNew;
  final VoidCallback onRestoreExisting;

  const OnboardingChoiceScreen({
    super.key,
    required this.onCreateNew,
    required this.onRestoreExisting,
  });

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Spacer(),
              const Icon(Icons.security, size: 64, color: Colors.amber),
              const SizedBox(height: 24),
              const Text(
                'Welcome to Phalanx',
                style: TextStyle(fontSize: 28, fontWeight: FontWeight.bold),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 12),
              const Text(
                'Choose how to set up this device.',
                style: TextStyle(fontSize: 14, color: Colors.grey),
                textAlign: TextAlign.center,
              ),
              const Spacer(),
              ElevatedButton.icon(
                onPressed: onCreateNew,
                icon: const Icon(Icons.add),
                label: const Padding(
                  padding: EdgeInsets.symmetric(vertical: 14),
                  child: Text('Create a new identity'),
                ),
              ),
              const SizedBox(height: 12),
              OutlinedButton.icon(
                onPressed: onRestoreExisting,
                icon: const Icon(Icons.restore),
                label: const Padding(
                  padding: EdgeInsets.symmetric(vertical: 14),
                  child: Text('I have a recovery phrase'),
                ),
              ),
              const SizedBox(height: 24),
              const Text(
                'Choose "Restore" if you previously captured evidence with '
                'Phalanx and have your 12-word recovery phrase. Otherwise '
                'choose "Create" to start fresh.',
                style: TextStyle(fontSize: 12, color: Colors.grey),
                textAlign: TextAlign.center,
              ),
              const Spacer(),
            ],
          ),
        ),
      ),
    );
  }
}
