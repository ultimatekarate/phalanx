// Riverpod provider surface for the community feature.
//
// Three pieces of state:
//   1. [communityBridgeProvider]   singleton FFI wrapper.
//   2. [communitiesProvider]       StateNotifier<AsyncValue<List<...>>>
//                                  for the roster list screen.
//   3. [activeCommunityProvider]   currently-selected community shown in
//                                  the capture-screen status chip.
//
// Imports, dissolves, and refreshes all pass through
// [CommunitiesNotifier] so the list is always coherent with the
// underlying actor.

import 'dart:ffi';
import 'dart:typed_data';

import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../ffi/community_bridge.dart';
import '../ffi/community_models.dart';
import '../ffi/library_loader.dart' show loadPhalanxLibrary;
import 'phalanx_provider.dart';

// ── Bridge singleton ───────────────────────────────────────────────────

final communityBridgeProvider = Provider<CommunityBridge>((ref) {
  // Shares the loaded dynamic library with PhalanxBridge via the
  // loader's internal cache. Constructing twice is safe; subsequent
  // loads return the same handle.
  loadPhalanxLibrary();
  return CommunityBridge();
});

// ── Native handle accessor ─────────────────────────────────────────────

/// Extracts the raw `Pointer<Void>` from the [PhalanxBridge] for FFI
/// calls that still need the native handle. The bridge exposes this
/// through a private field, so we expose a focused getter through a
/// provider rather than adding public surface to PhalanxBridge.
///
/// Returns [nullptr] if the engine has not yet been created. Callers
/// should guard with `phalanxReady` before dispatching.
final phalanxHandleProvider = Provider<Pointer<Void>>((ref) {
  final bridge = ref.watch(phalanxProvider);
  return bridge.nativeHandle;
});

// ── Communities list ───────────────────────────────────────────────────

/// Snapshot of the community list. AsyncValue semantics mirror the
/// standard Riverpod pattern:
///   - [AsyncLoading] while the FFI call is in flight.
///   - [AsyncData] with a cached list after a successful fetch.
///   - [AsyncError] with a message on transport failure.
class CommunitiesNotifier extends StateNotifier<AsyncValue<List<CommunitySummary>>> {
  final Ref _ref;

  CommunitiesNotifier(this._ref) : super(const AsyncValue.loading());

  /// Fetches the current list from the actor. Call on first build and
  /// after any mutation (import/dissolve) to stay coherent.
  Future<void> refresh() async {
    state = const AsyncValue.loading();
    try {
      final bridge = _ref.read(communityBridgeProvider);
      final handle = _ref.read(phalanxHandleProvider);
      if (handle == nullptr) {
        state = AsyncValue.error('Phalanx engine not yet ready.', StackTrace.current);
        return;
      }
      final list = bridge.listCommunities(handle);
      state = AsyncValue.data(list);
    } catch (e, st) {
      state = AsyncValue.error(e, st);
    }
  }

  /// Import a verified token. The confirmation screen calls this after
  /// the user accepts. On `Ok`, the list is refreshed; on `Err`, the
  /// [CommunityVerifyError] is returned to the caller so it can show a
  /// specific snackbar.
  Future<ImportOutcome> importToken(Uint8List payloadBytes) async {
    final bridge = _ref.read(communityBridgeProvider);
    final handle = _ref.read(phalanxHandleProvider);
    if (handle == nullptr) {
      throw StateError('Phalanx engine not yet ready.');
    }
    final outcome = bridge.importCommunity(handle, payloadBytes);
    if (outcome is ImportOutcomeOk) {
      await refresh();
    }
    return outcome;
  }

  /// Dissolve a community. On `Ok`, refreshes the list and clears the
  /// active-community chip if it was pointing at this id.
  Future<DissolveOutcome> dissolve(CommunityId id) async {
    final bridge = _ref.read(communityBridgeProvider);
    final handle = _ref.read(phalanxHandleProvider);
    if (handle == nullptr) {
      throw StateError('Phalanx engine not yet ready.');
    }
    final outcome = bridge.dissolveCommunity(handle, id);
    if (outcome is DissolveOutcomeOk) {
      await refresh();
      final active = _ref.read(activeCommunityProvider);
      if (active != null && active.id == id) {
        _ref.read(activeCommunityProvider.notifier).state = null;
      }
    }
    return outcome;
  }

  /// Fetch a full roster for the detail screen. Returns `null` if the
  /// actor no longer knows about the community (e.g. dissolved in
  /// another tab between list refresh and detail open).
  CommunityRoster? getRoster(CommunityId id) {
    final bridge = _ref.read(communityBridgeProvider);
    final handle = _ref.read(phalanxHandleProvider);
    if (handle == nullptr) return null;
    return bridge.getCommunity(handle, id);
  }

  /// Preview a token without side effects. Used by the confirmation
  /// screen (R1). Any `CommunityVerifyError` returned here means the
  /// user is looking at a malformed or tampered token.
  PreviewOutcome preview(Uint8List payloadBytes) {
    final bridge = _ref.read(communityBridgeProvider);
    final now = DateTime.now().millisecondsSinceEpoch;
    return bridge.previewCommunity(payloadBytes, now);
  }

  /// Preview a scanned `VouchRequest`. The Vouch screen calls this on
  /// every scan to get the review-safe projection before offering
  /// "Sign". A [CeremonyErrorVoucherMismatch] means the QR is
  /// addressed to a different phone.
  PreviewVouchOutcome previewVouchRequest(Uint8List requestBytes) {
    final bridge = _ref.read(communityBridgeProvider);
    final handle = _ref.read(phalanxHandleProvider);
    if (handle == nullptr) {
      throw StateError('Phalanx engine not yet ready.');
    }
    return bridge.previewVouchRequest(handle, requestBytes);
  }

  /// Sign a scanned `VouchRequest`. On `Ok`, the returned bytes are
  /// the already-wrapped `VouchResponse` envelope — the Vouch screen
  /// hands them straight to its QR encoder and file-saver.
  SignVouchOutcome signVouchRequest(Uint8List requestBytes) {
    final bridge = _ref.read(communityBridgeProvider);
    final handle = _ref.read(phalanxHandleProvider);
    if (handle == nullptr) {
      throw StateError('Phalanx engine not yet ready.');
    }
    return bridge.signVouchRequest(handle, requestBytes);
  }
}

final communitiesProvider =
    StateNotifierProvider<CommunitiesNotifier, AsyncValue<List<CommunitySummary>>>(
  (ref) => CommunitiesNotifier(ref),
);

// ── Active community (capture-screen chip) ─────────────────────────────

/// The community currently scoped for recording. `null` means no
/// community is pinned — the capture screen falls back to "lone wolf"
/// mode with no community tag applied to the evidence envelope.
final activeCommunityProvider = StateProvider<CommunitySummary?>((_) => null);

// ── Pending join-link queue ────────────────────────────────────────────

/// FIFO buffer of decoded Join payloads received from deep-link taps.
/// Drained by the router once `ProviderScope` is ready (see R9 fix in
/// main.dart). Each entry carries the raw postcard bytes and is passed
/// directly to the confirmation screen.
final pendingJoinQueueProvider =
    StateNotifierProvider<PendingJoinQueue, List<Uint8List>>(
  (_) => PendingJoinQueue(),
);

class PendingJoinQueue extends StateNotifier<List<Uint8List>> {
  PendingJoinQueue() : super(const []);

  void enqueue(Uint8List bytes) {
    state = [...state, bytes];
  }

  Uint8List? dequeue() {
    if (state.isEmpty) return null;
    final head = state.first;
    state = state.sublist(1);
    return head;
  }

  bool get isEmpty => state.isEmpty;
}
