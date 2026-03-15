import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../providers/phalanx_provider.dart';

/// Emergency mode toggle provider (persisted in shared preferences in production).
final emergencyModeProvider = StateProvider<bool>((ref) => false);

/// Settings screen — minimal. The system manages itself.
class SettingsScreen extends ConsumerWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final emergencyMode = ref.watch(emergencyModeProvider);
    String? nodeDid;
    try {
      nodeDid = ref.read(phalanxProvider).nodeDid;
    } catch (_) {
      nodeDid = 'Engine not running';
    }

    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: const Text('Settings'),
        backgroundColor: Colors.grey[900],
      ),
      body: ListView(
        children: [
          // Node DID
          ListTile(
            title: const Text(
              'Node DID',
              style: TextStyle(color: Colors.white),
            ),
            subtitle: Text(
              nodeDid ?? 'Unknown',
              style: const TextStyle(color: Colors.white54, fontSize: 12),
            ),
            trailing: IconButton(
              icon: const Icon(Icons.copy, color: Colors.white54),
              onPressed: () {
                if (nodeDid != null) {
                  Clipboard.setData(ClipboardData(text: nodeDid));
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('DID copied to clipboard')),
                  );
                }
              },
            ),
          ),
          const Divider(color: Colors.white12),

          // Emergency mode toggle
          SwitchListTile(
            title: const Text(
              'Emergency Mode',
              style: TextStyle(color: Colors.white),
            ),
            subtitle: const Text(
              'Start recording immediately when the app opens.',
              style: TextStyle(color: Colors.white54, fontSize: 13),
            ),
            value: emergencyMode,
            activeColor: Colors.red,
            onChanged: (val) {
              ref.read(emergencyModeProvider.notifier).state = val;
            },
          ),
          const Divider(color: Colors.white12),

          // Version info
          const ListTile(
            title: Text('Phalanx', style: TextStyle(color: Colors.white)),
            subtitle: Text(
              'v0.1.0 — Forensic-grade capture with mesh distribution.',
              style: TextStyle(color: Colors.white54, fontSize: 13),
            ),
          ),
        ],
      ),
    );
  }
}
