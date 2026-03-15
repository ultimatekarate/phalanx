import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../ffi/models.dart';
import '../providers/peers_provider.dart';
import '../widgets/peer_tile.dart';

/// Peer management screen — list of peers with pet names and trust levels.
class PeersScreen extends ConsumerStatefulWidget {
  const PeersScreen({super.key});

  @override
  ConsumerState<PeersScreen> createState() => _PeersScreenState();
}

class _PeersScreenState extends ConsumerState<PeersScreen> {
  @override
  void initState() {
    super.initState();
    // Refresh peer list on screen open
    Future.microtask(() => ref.read(peersProvider.notifier).refresh());
  }

  void _showPeerActions(BuildContext context, PeerInfo peer) {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.grey[900],
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Padding(
              padding: const EdgeInsets.all(16),
              child: Text(
                peer.displayName,
                style: const TextStyle(
                  color: Colors.white,
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
            ListTile(
              leading: const Icon(Icons.edit, color: Colors.white),
              title: const Text(
                'Rename',
                style: TextStyle(color: Colors.white),
              ),
              onTap: () {
                Navigator.pop(context);
                _showRenameDialog(peer);
              },
            ),
            ListTile(
              leading: const Icon(Icons.shield, color: Colors.white),
              title: const Text(
                'Change Trust Level',
                style: TextStyle(color: Colors.white),
              ),
              onTap: () {
                Navigator.pop(context);
                _showTrustDialog(peer);
              },
            ),
            ListTile(
              leading: const Icon(Icons.delete, color: Colors.red),
              title: const Text(
                'Remove Peer',
                style: TextStyle(color: Colors.red),
              ),
              onTap: () {
                Navigator.pop(context);
                _confirmRemove(peer);
              },
            ),
          ],
        ),
      ),
    );
  }

  void _showRenameDialog(PeerInfo peer) {
    final controller = TextEditingController(text: peer.petName ?? '');
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Colors.grey[850],
        title: const Text('Pet Name', style: TextStyle(color: Colors.white)),
        content: TextField(
          controller: controller,
          autofocus: true,
          style: const TextStyle(color: Colors.white),
          decoration: const InputDecoration(
            hintText: 'Enter a name for this peer',
            hintStyle: TextStyle(color: Colors.white38),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () {
              final name = controller.text.trim();
              if (name.isNotEmpty) {
                ref.read(peersProvider.notifier).assignPetName(peer.did, name);
              }
              Navigator.pop(context);
            },
            child: const Text('Save'),
          ),
        ],
      ),
    );
  }

  void _showTrustDialog(PeerInfo peer) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Colors.grey[850],
        title: const Text(
          'Trust Level',
          style: TextStyle(color: Colors.white),
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: TrustLevel.values.map((level) {
            return RadioListTile<TrustLevel>(
              title: Text(
                level.name[0].toUpperCase() + level.name.substring(1),
                style: TextStyle(
                  color: _trustColor(level),
                ),
              ),
              value: level,
              groupValue: peer.level,
              onChanged: (val) {
                if (val != null) {
                  ref
                      .read(peersProvider.notifier)
                      .setTrustLevel(peer.did, val);
                  Navigator.pop(context);
                }
              },
            );
          }).toList(),
        ),
      ),
    );
  }

  void _confirmRemove(PeerInfo peer) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Colors.grey[850],
        title: const Text(
          'Remove Peer?',
          style: TextStyle(color: Colors.white),
        ),
        content: Text(
          'Remove ${peer.displayName} from your trust registry?',
          style: const TextStyle(color: Colors.white70),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () {
              ref.read(peersProvider.notifier).removePeer(peer.did);
              Navigator.pop(context);
            },
            child: const Text('Remove', style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );
  }

  Color _trustColor(TrustLevel level) {
    return switch (level) {
      TrustLevel.blocked => Colors.red,
      TrustLevel.ignored => Colors.grey,
      TrustLevel.verified => Colors.blue,
      TrustLevel.ally => Colors.green,
    };
  }

  @override
  Widget build(BuildContext context) {
    final peers = ref.watch(peersProvider);

    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: const Text('Peers'),
        backgroundColor: Colors.grey[900],
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: () => ref.read(peersProvider.notifier).refresh(),
          ),
        ],
      ),
      body: peers.isEmpty
          ? const Center(
              child: Text(
                'No peers discovered yet.\nPeers appear when your node\nconnects to the mesh.',
                textAlign: TextAlign.center,
                style: TextStyle(color: Colors.white54, fontSize: 16),
              ),
            )
          : ListView.builder(
              itemCount: peers.length,
              itemBuilder: (context, index) {
                final peer = peers[index];
                return PeerTile(
                  peer: peer,
                  onTap: () => _showPeerActions(context, peer),
                );
              },
            ),
    );
  }
}
