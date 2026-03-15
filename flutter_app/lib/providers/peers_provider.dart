import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/models.dart';
import 'phalanx_provider.dart';

class PeersNotifier extends StateNotifier<List<PeerInfo>> {
  final Ref _ref;

  PeersNotifier(this._ref) : super([]);

  void refresh() {
    try {
      final bridge = _ref.read(phalanxProvider);
      state = bridge.getPeers();
    } catch (_) {
      // Engine not running yet — keep empty list
    }
  }

  void setTrustLevel(String did, TrustLevel level) {
    final bridge = _ref.read(phalanxProvider);
    bridge.setTrustLevel(did, level);
    refresh();
  }

  void assignPetName(String did, String name) {
    final bridge = _ref.read(phalanxProvider);
    bridge.assignPetName(did, name);
    refresh();
  }

  void removePeer(String did) {
    final bridge = _ref.read(phalanxProvider);
    bridge.removePeer(did);
    refresh();
  }
}

final peersProvider = StateNotifierProvider<PeersNotifier, List<PeerInfo>>(
  (ref) => PeersNotifier(ref),
);
