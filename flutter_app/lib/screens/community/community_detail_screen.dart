// Community detail screen. Shows the roster pulled from the live actor
// via `phalanx_get_community`. Dissolve is a destructive action — guarded
// by a confirm dialog.

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../ffi/community_models.dart';
import '../../providers/communities_provider.dart';

class CommunityDetailScreen extends ConsumerStatefulWidget {
  final CommunityId communityId;
  const CommunityDetailScreen({required this.communityId, super.key});

  @override
  ConsumerState<CommunityDetailScreen> createState() =>
      _CommunityDetailScreenState();
}

class _CommunityDetailScreenState extends ConsumerState<CommunityDetailScreen> {
  CommunityRoster? _roster;
  bool _loading = true;
  String? _error;
  bool _dissolving = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _load());
  }

  void _load() {
    try {
      final roster = ref
          .read(communitiesProvider.notifier)
          .getRoster(widget.communityId);
      setState(() {
        _roster = roster;
        _loading = false;
      });
    } catch (e) {
      setState(() {
        _error = 'Failed to load roster: $e';
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Community')),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_loading) return const Center(child: CircularProgressIndicator());
    if (_error != null) return Center(child: Text(_error!));
    if (_roster == null) {
      return const Center(
        child: Padding(
          padding: EdgeInsets.all(24.0),
          child: Text(
            'This community is no longer in the live roster — it may have '
            'been dissolved or expired.',
            textAlign: TextAlign.center,
          ),
        ),
      );
    }
    return _rosterView(_roster!);
  }

  Widget _rosterView(CommunityRoster roster) {
    final s = roster.summary;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Row(
          children: [
            Expanded(
              child: Text(
                s.name,
                style: const TextStyle(fontSize: 22, fontWeight: FontWeight.w600),
              ),
            ),
            _expiryBadge(s),
          ],
        ),
        const SizedBox(height: 4),
        SelectableText(
          'ID: ${s.id.toHex()}',
          style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
        ),
        const SizedBox(height: 4),
        Text('Quorum: ${s.quorum}/${s.memberCount}'),
        if (roster.strongholdDid != null) ...[
          const SizedBox(height: 4),
          SelectableText(
            'Stronghold DID: ${roster.strongholdDid!}',
            style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
          ),
        ],
        const Divider(height: 32),
        const Text('Members', style: TextStyle(fontWeight: FontWeight.bold)),
        const SizedBox(height: 8),
        for (final m in roster.members) _memberRow(m),
        const SizedBox(height: 32),
        _dissolveSection(roster),
      ],
    );
  }

  Widget _memberRow(MemberSummary m) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (m.petName != null)
            Text(
              m.petName!,
              style: const TextStyle(fontWeight: FontWeight.w600),
            ),
          SelectableText(
            m.did,
            style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
          ),
          Text(
            'vouches: ${m.vouchCount}',
            style: const TextStyle(fontSize: 12, color: Colors.grey),
          ),
        ],
      ),
    );
  }

  Widget _dissolveSection(CommunityRoster roster) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        OutlinedButton.icon(
          icon: const Icon(Icons.delete_forever, color: Colors.red),
          label: const Text(
            'Dissolve community',
            style: TextStyle(color: Colors.red),
          ),
          style: OutlinedButton.styleFrom(
            side: const BorderSide(color: Colors.red),
            padding: const EdgeInsets.symmetric(vertical: 14),
          ),
          onPressed: _dissolving ? null : () => _confirmDissolve(roster),
        ),
        const SizedBox(height: 8),
        const Text(
          'Dissolve zeroizes roster material on this device and removes the '
          'community from the routing table. Other devices are unaffected.',
          style: TextStyle(fontSize: 12, color: Colors.grey),
        ),
      ],
    );
  }

  Future<void> _confirmDissolve(CommunityRoster roster) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Dissolve community?'),
        content: Text(
          'Remove "${roster.summary.name}" from this device. Other members '
          'are not notified — they keep their own copies.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: Colors.red),
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Dissolve'),
          ),
        ],
      ),
    );
    if (ok != true) return;

    setState(() => _dissolving = true);
    try {
      final outcome =
          await ref.read(communitiesProvider.notifier).dissolve(roster.summary.id);
      if (!mounted) return;
      if (outcome is DissolveOutcomeOk) {
        Navigator.of(context).pop(); // back to list
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Community was already gone.')),
        );
        Navigator.of(context).pop();
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Dissolve failed: $e')),
      );
      setState(() => _dissolving = false);
    }
  }

  Widget _expiryBadge(CommunitySummary s) {
    final Color color;
    final String label;
    if (s.isExpired) {
      color = Colors.red;
      label = 'expired';
    } else {
      final remaining = s.timeUntilExpiry!;
      color = remaining.inDays >= 7 ? Colors.green : Colors.amber;
      label = remaining.inDays >= 1
          ? 'expires in ${remaining.inDays}d'
          : 'expires in ${remaining.inHours}h';
    }
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.2),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color),
      ),
      child: Text(label,
          style: TextStyle(color: color, fontWeight: FontWeight.w600)),
    );
  }
}
