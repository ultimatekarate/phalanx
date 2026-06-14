import 'package:flutter/material.dart';

import '../ffi/phalanx_bridge.dart';

/// First-launch deployment-topology picker, shown before the create/restore
/// onboarding choice. It sets how this device joins the network and where
/// evidence is kept.
///
/// Selectability is driven by the engine's `phalanx_profile_flags` (Rust truth),
/// not a hardcoded list: a profile whose `requires_psk` bit is set is disabled
/// until on-device swarm-key provisioning lands. The display names/copy live
/// here (UI text); the behaviour comes from the flags.
class ProfileChoiceScreen extends StatelessWidget {
  final PhalanxBridge bridge;
  final void Function(String profileName) onProfileChosen;

  const ProfileChoiceScreen({
    super.key,
    required this.bridge,
    required this.onProfileChosen,
  });

  static const _profiles = <_ProfileOption>[
    _ProfileOption(
      'solo_device',
      'Solo device',
      'Just this phone. Recordings replicate to nearby peers; no custody node.',
      Icons.smartphone,
    ),
    _ProfileOption(
      'community_with_stronghold',
      'Community + Stronghold',
      'Your group plus a wall-powered custody node (e.g. an NGO office) that '
          'holds and exports evidence. You will pair the Stronghold next.',
      Icons.shield,
    ),
    _ProfileOption(
      'affinity_group_lan',
      'Affinity group (LAN)',
      'A closed group on a local network. Needs a shared swarm key.',
      Icons.group,
    ),
    _ProfileOption(
      'high_risk_cross_border',
      'High-risk / cross-border',
      'Hardened posture for state-level adversaries. Needs a shared swarm key.',
      Icons.security,
    ),
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: ListView(
            children: [
              const SizedBox(height: 16),
              const Icon(Icons.tune, size: 56, color: Colors.amber),
              const SizedBox(height: 16),
              const Text(
                'Choose your setup',
                style: TextStyle(fontSize: 26, fontWeight: FontWeight.bold),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 8),
              const Text(
                'This sets how your device joins the network and where your '
                'evidence is kept. You can change it later in Settings.',
                style: TextStyle(fontSize: 13, color: Colors.grey),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 24),
              for (final p in _profiles) _tile(p),
            ],
          ),
        ),
      ),
    );
  }

  Widget _tile(_ProfileOption p) {
    final flags = bridge.profileFlags(p.name);
    final known = flags > 0;
    final requiresPsk = known && (flags & 4) != 0;
    final enabled = known && !requiresPsk;

    return Card(
      color: enabled ? Colors.grey[900] : Colors.grey[850],
      child: ListTile(
        leading: Icon(p.icon, color: enabled ? Colors.amber : Colors.grey),
        title: Text(
          p.label,
          style: TextStyle(color: enabled ? Colors.white : Colors.grey),
        ),
        subtitle: Text(
          requiresPsk
              ? '${p.subtitle}\nNot yet available on mobile.'
              : p.subtitle,
          style: const TextStyle(color: Colors.grey, fontSize: 12),
        ),
        isThreeLine: true,
        enabled: enabled,
        onTap: enabled ? () => onProfileChosen(p.name) : null,
      ),
    );
  }
}

class _ProfileOption {
  final String name;
  final String label;
  final String subtitle;
  final IconData icon;
  const _ProfileOption(this.name, this.label, this.subtitle, this.icon);
}
