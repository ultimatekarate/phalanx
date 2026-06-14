// Community Confirm screen (R1 phishing mitigation).
//
// Every Join path — QR scan, custom-scheme deep-link, Universal Link —
// funnels through this screen. It runs `phalanx_preview_community`,
// which verifies the token cryptographically *without* registering it,
// then shows the operator the community name, fingerprint, member list,
// and expiration. Only after the operator taps "Join this community"
// does the app call `phalanx_import_community`.
//
// A QR/link that is cryptographically valid can still be a phishing
// token — e.g. "ACLU-Portland adversary fork" that verifies its own
// vouch graph perfectly. The only defence is human-in-the-loop
// verification, which is what this screen implements.

import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../ffi/community_models.dart';
import '../../providers/communities_provider.dart';
import '../../providers/phalanx_provider.dart';

class CommunityConfirmScreen extends ConsumerStatefulWidget {
  final Uint8List payloadBytes;
  const CommunityConfirmScreen({required this.payloadBytes, super.key});

  @override
  ConsumerState<CommunityConfirmScreen> createState() =>
      _CommunityConfirmScreenState();
}

class _CommunityConfirmScreenState
    extends ConsumerState<CommunityConfirmScreen> {
  PreviewOutcome? _preview;
  String? _transportError;
  bool _importing = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _runPreview());
  }

  void _runPreview() {
    try {
      final outcome =
          ref.read(communitiesProvider.notifier).preview(widget.payloadBytes);
      setState(() => _preview = outcome);
    } catch (e) {
      setState(() => _transportError = 'Preview failed: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Review community')),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_transportError != null) return _errorView(_transportError!);
    if (_preview == null) {
      return const Center(child: CircularProgressIndicator());
    }
    return switch (_preview!) {
      PreviewOutcomeOk(roster: final r) => _rosterView(r),
      PreviewOutcomeErr(error: final e) => _verifyErrorView(e),
    };
  }

  Widget _errorView(String msg) => Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Text(msg, textAlign: TextAlign.center),
        ),
      );

  Widget _verifyErrorView(CommunityVerifyError err) {
    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.warning_amber_rounded, color: Colors.red, size: 64),
          const SizedBox(height: 16),
          const Text(
            'Token rejected',
            style: TextStyle(fontSize: 22, fontWeight: FontWeight.w600),
          ),
          const SizedBox(height: 8),
          Text(err.userMessage, textAlign: TextAlign.center),
          const SizedBox(height: 24),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Back'),
          ),
        ],
      ),
    );
  }

  Widget _rosterView(CommunityRoster roster) {
    final s = roster.summary;
    final warnings = _phishingWarnings(roster);

    return Column(
      children: [
        Expanded(
          child: ListView(
            padding: const EdgeInsets.all(16),
            children: [
              if (warnings.isNotEmpty) _warningsCard(warnings),
              Row(
                children: [
                  Expanded(
                    child: Text(
                      s.name,
                      style: const TextStyle(
                          fontSize: 22, fontWeight: FontWeight.w600),
                    ),
                  ),
                  _expiryBadge(s),
                ],
              ),
              const SizedBox(height: 8),
              const Text(
                'Fingerprint (verify with the organizer):',
                style: TextStyle(fontSize: 12, color: Colors.grey),
              ),
              SelectableText(
                _formatFingerprint(s.id.toHex()),
                style: const TextStyle(fontFamily: 'monospace'),
              ),
              const SizedBox(height: 12),
              Text('Quorum: ${s.quorum}/${s.memberCount} vouches required'),
              if (roster.strongholdDid != null) ...[
                const SizedBox(height: 8),
                const Text('Stronghold DID:',
                    style: TextStyle(fontSize: 12, color: Colors.grey)),
                SelectableText(
                  roster.strongholdDid!,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                ),
              ],
              const Divider(height: 32),
              Text('Members (${roster.members.length})',
                  style: const TextStyle(fontWeight: FontWeight.bold)),
              const SizedBox(height: 8),
              for (final m in roster.members) _memberRow(m),
            ],
          ),
        ),
        _actionBar(roster),
      ],
    );
  }

  Widget _warningsCard(List<String> warnings) {
    return Card(
      color: Colors.amber.shade100,
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Row(
              children: [
                Icon(Icons.warning_amber_rounded, color: Colors.orange),
                SizedBox(width: 8),
                Text('Review before joining',
                    style: TextStyle(fontWeight: FontWeight.bold)),
              ],
            ),
            const SizedBox(height: 8),
            for (final w in warnings) Text('• $w'),
          ],
        ),
      ),
    );
  }

  Widget _memberRow(MemberSummary m) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (m.petName != null)
            Text(m.petName!,
                style: const TextStyle(fontWeight: FontWeight.w600)),
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

  Widget _actionBar(CommunityRoster roster) {
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Row(
          children: [
            Expanded(
              child: OutlinedButton(
                onPressed:
                    _importing ? null : () => Navigator.of(context).pop(),
                child: const Text('Cancel'),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: FilledButton(
                onPressed: _importing ? null : () => _commit(roster),
                child: _importing
                    ? const SizedBox(
                        height: 16,
                        width: 16,
                        child: CircularProgressIndicator(
                            strokeWidth: 2, color: Colors.white),
                      )
                    : const Text('Join this community'),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _commit(CommunityRoster roster) async {
    setState(() => _importing = true);
    try {
      final outcome = await ref
          .read(communitiesProvider.notifier)
          .importToken(widget.payloadBytes);
      if (!mounted) return;
      switch (outcome) {
        case ImportOutcomeOk():
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Joined ${roster.summary.name}.')),
          );
          Navigator.of(context).popUntil((r) => r.isFirst);
          Navigator.of(context).pushNamed('/community');
          break;
        case ImportOutcomeErr(error: final e):
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text(e.userMessage)),
          );
          setState(() => _importing = false);
          break;
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Import failed: $e')),
      );
      setState(() => _importing = false);
    }
  }

  /// User-visible warnings flagged by reading the roster alone — these
  /// are *not* cryptographic rejections (the verify step already passed
  /// by the time we get here). They're common phishing tells that
  /// warrant a second look before the operator taps Join.
  List<String> _phishingWarnings(CommunityRoster roster) {
    final w = <String>[];
    if (roster.strongholdDid == null) {
      w.add(
        'No Stronghold DID declared — legitimate communities typically '
        'declare a Stronghold for corroboration export.',
      );
    }
    // Short expiration is a positive signal, but a >30-day expiration
    // is now blocked by `assemble_community` so it can't arrive here.
    if (roster.summary.timeUntilExpiry != null &&
        roster.summary.timeUntilExpiry!.inDays < 1) {
      w.add(
        'Community expires in under 24 hours — confirm the organizer '
        'meant to issue such a short-lived token.',
      );
    }
    // Your DID not in the member list — Trusted Community is join-by-
    // vouch, so a phone absent from the roster has nothing to
    // corroborate. The warning is unconditional: reference-only imports
    // are out of scope in v1. If that ever changes, gate this warning
    // on a "ref-only import" flow flag rather than removing it.
    try {
      final myDid = ref.read(phalanxProvider).nodeDid;
      final inRoster = roster.members.any((m) => m.did == myDid);
      if (!inRoster) {
        w.add(
          'Your device DID is not in this community — joining will not '
          'grant corroboration on your recordings. Ask the organizer to '
          'verify the roster before you accept.',
        );
      }
    } catch (_) {
      // Engine not yet ready — the confirm screen normally only renders
      // post-init, so this is a defensive fall-through rather than an
      // expected branch.
    }
    return w;
  }

  String _formatFingerprint(String hex) {
    // Group hex into 4-char blocks for readability — 64 hex → 16 blocks.
    final buf = StringBuffer();
    for (int i = 0; i < hex.length; i += 4) {
      if (i > 0) buf.write(i % 16 == 0 ? '\n' : ' ');
      buf.write(hex.substring(i, (i + 4).clamp(0, hex.length)));
    }
    return buf.toString();
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
          ? '${remaining.inDays}d'
          : '${remaining.inHours}h';
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
