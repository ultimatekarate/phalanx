import 'package:flutter/material.dart';
import '../ffi/models.dart';

/// Single peer row in the peers list.
class PeerTile extends StatelessWidget {
  final PeerInfo peer;
  final VoidCallback onTap;

  const PeerTile({super.key, required this.peer, required this.onTap});

  Color get _trustColor {
    return switch (peer.level) {
      TrustLevel.blocked => Colors.red,
      TrustLevel.ignored => Colors.grey,
      TrustLevel.verified => Colors.blue,
      TrustLevel.ally => Colors.green,
    };
  }

  String get _trustLabel {
    return peer.level.name[0].toUpperCase() + peer.level.name.substring(1);
  }

  @override
  Widget build(BuildContext context) {
    return ListTile(
      onTap: onTap,
      leading: CircleAvatar(
        backgroundColor: _trustColor.withValues(alpha: 0.2),
        child: Icon(
          peer.isBlacklisted ? Icons.block : Icons.person,
          color: _trustColor,
        ),
      ),
      title: Text(
        peer.displayName,
        style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w500),
      ),
      subtitle: Text(
        peer.did.length > 24 ? '${peer.did.substring(0, 24)}...' : peer.did,
        style: const TextStyle(color: Colors.white38, fontSize: 12),
      ),
      trailing: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
        decoration: BoxDecoration(
          color: _trustColor.withValues(alpha: 0.15),
          borderRadius: BorderRadius.circular(12),
        ),
        child: Text(
          _trustLabel,
          style: TextStyle(color: _trustColor, fontSize: 12),
        ),
      ),
    );
  }
}
