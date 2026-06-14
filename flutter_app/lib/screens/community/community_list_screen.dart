// Community list screen. Shows all communities imported on this device
// with an expiration badge and a tap-to-drill row. An FAB routes into
// the Join scanner; a second action opens Paste-Link for the fallback
// text-import path.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../ffi/community_models.dart';
import '../../providers/communities_provider.dart';
import '../../services/community_link_service.dart';

class CommunityListScreen extends ConsumerStatefulWidget {
  const CommunityListScreen({super.key});

  @override
  ConsumerState<CommunityListScreen> createState() =>
      _CommunityListScreenState();
}

class _CommunityListScreenState extends ConsumerState<CommunityListScreen> {
  @override
  void initState() {
    super.initState();
    // Kick off a refresh on first mount. Riverpod's
    // AsyncValue.loading is shown until it completes.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(communitiesProvider.notifier).refresh();
    });
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(communitiesProvider);
    return Scaffold(
      appBar: AppBar(
        title: const Text('Communities'),
        actions: [
          IconButton(
            icon: const Icon(Icons.verified_user_outlined),
            tooltip: 'Sign vouch request',
            onPressed: () =>
                Navigator.of(context).pushNamed('/community/vouch'),
          ),
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh',
            onPressed: () =>
                ref.read(communitiesProvider.notifier).refresh(),
          ),
        ],
      ),
      body: state.when(
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (err, _) => _errorView(err),
        data: (list) => list.isEmpty ? _emptyView() : _listView(list),
      ),
      floatingActionButton: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          FloatingActionButton.extended(
            heroTag: 'paste',
            onPressed: _pasteLink,
            icon: const Icon(Icons.content_paste),
            label: const Text('Paste link'),
          ),
          const SizedBox(height: 12),
          FloatingActionButton.extended(
            heroTag: 'scan',
            onPressed: () => Navigator.of(context).pushNamed('/community/join'),
            icon: const Icon(Icons.qr_code_scanner),
            label: const Text('Scan QR'),
          ),
        ],
      ),
    );
  }

  Widget _errorView(Object err) => Center(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Text(
            'Could not load communities: $err',
            textAlign: TextAlign.center,
          ),
        ),
      );

  Widget _emptyView() => const Center(
        child: Padding(
          padding: EdgeInsets.all(24.0),
          child: Text(
            'No communities yet.\n\nScan a Join QR from a trusted organizer, '
            'or paste a link received on a secure channel.',
            textAlign: TextAlign.center,
          ),
        ),
      );

  Widget _listView(List<CommunitySummary> list) => RefreshIndicator(
        onRefresh: () => ref.read(communitiesProvider.notifier).refresh(),
        child: ListView.separated(
          itemCount: list.length,
          separatorBuilder: (_, __) => const Divider(height: 1),
          itemBuilder: (_, i) => _CommunityTile(summary: list[i]),
        ),
      );

  Future<void> _pasteLink() async {
    final clip = await Clipboard.getData(Clipboard.kTextPlain);
    final text = clip?.text?.trim() ?? '';
    if (!mounted) return;
    if (text.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Clipboard is empty.')),
      );
      return;
    }
    try {
      final bytes = decodeJoinPayload(text);
      if (!mounted) return;
      Navigator.of(context).pushNamed('/community/confirm', arguments: bytes);
    } on LinkDecodeError catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(e.message)),
      );
    }
  }
}

class _CommunityTile extends ConsumerWidget {
  final CommunitySummary summary;

  const _CommunityTile({required this.summary});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final active = ref.watch(activeCommunityProvider);
    final isActive = active != null && active.id == summary.id;
    final expiry = _expiryLabel(summary);

    return ListTile(
      leading: isActive
          ? const Icon(Icons.verified, color: Colors.green)
          : const Icon(Icons.group_outlined),
      title: Text(summary.name),
      subtitle: Text(
        '${summary.memberCount} members • quorum ${summary.quorum} • ${summary.id.toShortHex()}',
      ),
      trailing: _ExpiryBadge(label: expiry.label, color: expiry.color),
      onTap: () {
        Navigator.of(context)
            .pushNamed('/community/detail', arguments: summary.id);
      },
      onLongPress: () {
        ref.read(activeCommunityProvider.notifier).state =
            isActive ? null : summary;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              isActive
                  ? 'Recording scope cleared.'
                  : 'Recording scope: ${summary.name}',
            ),
          ),
        );
      },
    );
  }

  _Expiry _expiryLabel(CommunitySummary s) {
    if (s.isExpired) {
      return _Expiry('expired', Colors.red);
    }
    final remaining = s.timeUntilExpiry!;
    if (remaining.inDays >= 7) {
      return _Expiry('${remaining.inDays}d', Colors.green);
    }
    if (remaining.inDays >= 1) {
      return _Expiry('${remaining.inDays}d', Colors.amber);
    }
    return _Expiry('${remaining.inHours}h', Colors.amber);
  }
}

class _Expiry {
  final String label;
  final Color color;
  _Expiry(this.label, this.color);
}

class _ExpiryBadge extends StatelessWidget {
  final String label;
  final Color color;
  const _ExpiryBadge({required this.label, required this.color});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.2),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color, width: 1),
      ),
      child: Text(
        label,
        style: TextStyle(color: color, fontSize: 12, fontWeight: FontWeight.w600),
      ),
    );
  }
}
