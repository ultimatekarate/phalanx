import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/phalanx_bridge.dart';

/// Singleton provider for the PhalanxBridge.
///
/// The bridge is created once and lives for the entire app lifecycle.
/// It is NOT disposed on widget rebuild — the engine outlives the UI.
final phalanxProvider = Provider<PhalanxBridge>((ref) {
  final bridge = PhalanxBridge();
  ref.onDispose(() => bridge.destroy());
  return bridge;
});
