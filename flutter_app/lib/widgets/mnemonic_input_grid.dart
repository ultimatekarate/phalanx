import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';

import '../services/bip39_wordlist.dart';
import '../services/screen_security.dart';

/// Per-cell validation indicator. Drives the ✓ / ✗ / empty marker shown
/// next to each input cell. Computed locally from the BIP-39 English
/// wordlist on every keystroke — no FFI roundtrip.
enum _CellState {
  /// Cell is empty — no indicator.
  empty,
  /// Word is a partial prefix of one or more BIP-39 words (still typing).
  partial,
  /// Word is a full BIP-39 wordlist hit.
  valid,
  /// Word is non-empty and not a prefix of any BIP-39 word.
  invalid,
}

/// Reusable 12-cell BIP-39 mnemonic input.
///
/// Built once for the revocation flow (`forget_dialog`) and the restore
/// flow (`restore_phrase_screen`). Properties:
///
/// - Each cell renders as an obscured `TextField` (`obscureText: true`).
///   A single eye-toggle on the grid header reveals/hides all cells. The
///   user verifies their phrase via per-cell ✓ indicators (computed from
///   the local wordlist) rather than by revealing text.
/// - Per-keystroke validation hits a `const Set<String>` of 2048 English
///   words; no FFI calls during typing.
/// - On submit, the assembled phrase is passed to [onChecksumValidate]
///   (typically `bridge.validateMnemonic`) for a single FFI checksum check.
/// - On success, [onSubmit] is invoked with the assembled phrase.
/// - On failure, [onSubmit] is NOT called; a local error message is shown.
/// - Cells set `autocorrect: false` and `enableSuggestions: false` to
///   prevent the OS from learning/suggesting the user's recovery words.
///
/// The phrase is held in [TextEditingController]s and assembled into a
/// `String` for the FFI call. Full memory hygiene requires a custom
/// secure-input widget (out of scope); R5 in the audit plan documents
/// this limitation. The grid clears all controllers after a successful
/// submit.
class MnemonicInputGrid extends StatefulWidget {
  /// Called when the user submits and the phrase passes both local
  /// wordlist checks and the FFI checksum check. Receives the assembled
  /// 12-word phrase as a UTF-8 byte buffer (not a Dart `String`) so the
  /// caller can pass it straight to a `Uint8List`-typed FFI method
  /// (`bridge.forgetRecording` / `bridge.restoreFromPhrase`) without
  /// going through an intermediate String. The grid zeros the buffer
  /// after [onSubmit] returns regardless of outcome, so callees should
  /// not retain the reference. Returns `null` on success; returns a
  /// user-facing error message on failure (rendered inline).
  final String? Function(Uint8List phrase) onSubmit;

  /// Optional FFI-backed checksum validator. Returns true if the phrase
  /// parses (wordlist + checksum). If null, the grid skips the final FFI
  /// check and submits as long as all 12 cells are wordlist-valid; useful
  /// for tests or for the partial verification widget. In production this
  /// is always `bridge.validateMnemonic`.
  final bool Function(Uint8List phrase)? onChecksumValidate;

  /// Submit button label. Defaults to "Submit"; callers typically pass
  /// "Forget Forever" or "Restore Identity".
  final String submitLabel;

  /// Submit button color. Defaults to red for destructive actions; the
  /// restore screen passes a non-destructive color.
  final Color submitColor;

  /// Optional informational text shown above the grid (e.g., "Enter your
  /// 12-word recovery phrase to authorize the destruction of this
  /// recording.").
  final String? headerText;

  const MnemonicInputGrid({
    super.key,
    required this.onSubmit,
    this.onChecksumValidate,
    this.submitLabel = 'Submit',
    this.submitColor = Colors.red,
    this.headerText,
  });

  @override
  State<MnemonicInputGrid> createState() => _MnemonicInputGridState();
}

class _MnemonicInputGridState extends State<MnemonicInputGrid> {
  static const _cellCount = 12;
  late final List<TextEditingController> _controllers;
  late final List<FocusNode> _focusNodes;
  late final List<_CellState> _states;
  bool _obscured = true;
  bool _processing = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _controllers =
        List.generate(_cellCount, (_) => TextEditingController());
    _focusNodes = List.generate(_cellCount, (_) => FocusNode());
    _states = List.filled(_cellCount, _CellState.empty);
    for (var i = 0; i < _cellCount; i++) {
      _controllers[i].addListener(() => _onCellChanged(i));
    }
    // Block screen capture for the lifetime of the grid. Ref-counted so
    // nested sensitive screens (e.g., the genesis phrase screen pushing
    // a verification dialog containing this grid) compose correctly.
    ScreenSecurity.enableSecure();
  }

  @override
  void dispose() {
    ScreenSecurity.disableSecure();
    for (final c in _controllers) {
      c.clear();
      c.dispose();
    }
    for (final f in _focusNodes) {
      f.dispose();
    }
    super.dispose();
  }

  void _onCellChanged(int index) {
    final raw = _controllers[index].text;
    // Paste handler: a 12-word payload pasted into any cell distributes
    // across all cells. Detect by counting whitespace-separated tokens.
    final tokens = raw.trim().split(RegExp(r'\s+'));
    if (tokens.length == _cellCount) {
      for (var i = 0; i < _cellCount; i++) {
        _controllers[i].text = tokens[i].toLowerCase();
      }
      // After distribute, focus the submit area (last cell loses focus).
      _focusNodes[_cellCount - 1].unfocus();
      // The other cells' listeners will fire and re-classify; we still
      // need to classify the originating cell here.
      setState(() {
        for (var i = 0; i < _cellCount; i++) {
          _states[i] = _classify(_controllers[i].text);
        }
        _error = null;
      });
      return;
    }
    setState(() {
      _states[index] = _classify(raw);
      _error = null;
    });
  }

  _CellState _classify(String raw) {
    final word = raw.trim().toLowerCase();
    if (word.isEmpty) return _CellState.empty;
    if (Bip39Wordlist.contains(word)) return _CellState.valid;
    // Partial match: any wordlist entry starts with this prefix. Cheap
    // linear scan; the wordlist is a const Set so iteration is fast and
    // typing is bounded.
    for (final w in Bip39Wordlist.english) {
      if (w.startsWith(word)) return _CellState.partial;
    }
    return _CellState.invalid;
  }

  bool get _allValid =>
      _states.every((s) => s == _CellState.valid);

  /// Build a `Uint8List` of UTF-8 bytes from the 12 cells, separated by
  /// single spaces. We avoid producing one big concatenated Dart `String`
  /// so the phrase doesn't live as a single contiguous immutable on the
  /// GC heap. Per-cell strings are still produced by `controller.text` —
  /// fully eliminating those would require a custom secure-input widget
  /// (out of scope; documented in audit R5).
  Uint8List _assemblePhraseBytes() {
    final builder = BytesBuilder(copy: false);
    final encoder = utf8.encoder;
    for (var i = 0; i < _cellCount; i++) {
      if (i > 0) builder.addByte(0x20); // ASCII space
      final word = _controllers[i].text.trim().toLowerCase();
      builder.add(encoder.convert(word));
    }
    return builder.toBytes();
  }

  void _clearAll() {
    for (final c in _controllers) {
      c.clear();
    }
    setState(() {
      for (var i = 0; i < _cellCount; i++) {
        _states[i] = _CellState.empty;
      }
    });
  }

  Future<void> _submit() async {
    if (!_allValid) return;
    setState(() {
      _processing = true;
      _error = null;
    });

    final phrase = _assemblePhraseBytes();
    try {
      final validator = widget.onChecksumValidate;
      final passes = validator == null ? true : validator(phrase);
      if (!passes) {
        setState(() {
          _processing = false;
          _error =
              'Checksum check failed. Verify each word against your written copy.';
        });
        return;
      }

      final submitError = widget.onSubmit(phrase);
      if (submitError == null) {
        // onSubmit's caller is responsible for dismissing the dialog/screen;
        // we just clear the controllers so the phrase doesn't linger in
        // visible state.
        _clearAll();
      } else {
        setState(() {
          _processing = false;
          _error = submitError;
        });
      }
    } finally {
      // Zero the byte buffer unconditionally — even when validation
      // failed or onSubmit returned an error. Caller-side native memory
      // is already zeroed inside `bridge._withZeroedNativeBytes`. The
      // Dart String fragments in the typing path are NOT reachable from
      // here (audit R5: partial mitigation).
      phrase.fillRange(0, phrase.length, 0);
    }
  }

  Widget _buildCell(int index) {
    final state = _states[index];
    final Color borderColor;
    final Widget? suffix;
    switch (state) {
      case _CellState.valid:
        borderColor = Colors.green;
        suffix = const Icon(Icons.check, size: 16, color: Colors.green);
        break;
      case _CellState.invalid:
        borderColor = Colors.red;
        suffix = const Icon(Icons.close, size: 16, color: Colors.red);
        break;
      case _CellState.partial:
        borderColor = Colors.amber;
        suffix = const Icon(Icons.more_horiz, size: 16, color: Colors.amber);
        break;
      case _CellState.empty:
        borderColor = Colors.grey;
        suffix = null;
        break;
    }
    return TextField(
      controller: _controllers[index],
      focusNode: _focusNodes[index],
      obscureText: _obscured,
      enabled: !_processing,
      autocorrect: false,
      enableSuggestions: false,
      autofillHints: const [],
      textInputAction: index == _cellCount - 1
          ? TextInputAction.done
          : TextInputAction.next,
      onSubmitted: (_) {
        if (index < _cellCount - 1) {
          _focusNodes[index + 1].requestFocus();
        } else if (_allValid) {
          _submit();
        }
      },
      style: const TextStyle(fontFamily: 'monospace', fontSize: 14),
      decoration: InputDecoration(
        labelText: '${index + 1}',
        labelStyle: const TextStyle(fontSize: 12),
        isDense: true,
        contentPadding:
            const EdgeInsets.symmetric(horizontal: 8, vertical: 10),
        border: OutlineInputBorder(borderSide: BorderSide(color: borderColor)),
        enabledBorder:
            OutlineInputBorder(borderSide: BorderSide(color: borderColor)),
        suffixIcon: suffix,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (widget.headerText != null) ...[
          Text(
            widget.headerText!,
            style: const TextStyle(fontSize: 13, color: Colors.grey),
          ),
          const SizedBox(height: 12),
        ],
        Row(
          mainAxisAlignment: MainAxisAlignment.end,
          children: [
            IconButton(
              icon: Icon(_obscured ? Icons.visibility : Icons.visibility_off),
              tooltip: _obscured ? 'Show phrase' : 'Hide phrase',
              onPressed: _processing
                  ? null
                  : () => setState(() => _obscured = !_obscured),
            ),
          ],
        ),
        GridView.count(
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          crossAxisCount: 3,
          childAspectRatio: 3.2,
          crossAxisSpacing: 6,
          mainAxisSpacing: 6,
          children: List.generate(_cellCount, _buildCell),
        ),
        if (_error != null) ...[
          const SizedBox(height: 12),
          Text(
            _error!,
            style: const TextStyle(color: Colors.redAccent, fontSize: 13),
          ),
        ],
        const SizedBox(height: 16),
        ElevatedButton(
          onPressed: _processing || !_allValid ? null : _submit,
          style: ElevatedButton.styleFrom(
            backgroundColor: widget.submitColor,
            foregroundColor: Colors.white,
            padding: const EdgeInsets.symmetric(vertical: 14),
          ),
          child: _processing
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(
                      strokeWidth: 2, color: Colors.white),
                )
              : Text(widget.submitLabel),
        ),
      ],
    );
  }
}

