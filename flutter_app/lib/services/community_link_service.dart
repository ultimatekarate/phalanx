// Community link service — decodes QR / deep-link payloads into raw bytes
// ready for `phalanx_preview_community`.
//
// Three accepted carriers all resolve to the same postcard envelope:
//   1. Raw base64url — QR scanner output.
//   2. `phalanx://community/join#data=<base64url>` — custom-scheme URI
//      (debug/offline builds only, R2).
//   3. `https://phalanx.app/c/join#data=<base64url>` — Universal Link.
//
// The payload lives in the URL **fragment** (`#data=`) rather than the
// query string. Fragments are never transmitted to the server by
// browsers, so a desktop browser hit on the Universal Link reaches
// phalanx.app with an empty path — server access logs never see the
// community bytes (R3).
//
// This module is pure Dart — no FFI, no platform channels. It is
// trivially unit-testable with `flutter test`.

import 'dart:convert';
import 'dart:typed_data';

/// Maximum payload size we accept before passing bytes to Rust.
/// Mirrors `QR_PAYLOAD_BUDGET_BYTES` in `phalanx-forensics::identity`
/// plus a 1-byte envelope version + a safety margin for large rosters
/// encoded at the ceiling.
const int maxCommunityPayloadBytes = 4096;

/// What went wrong when we tried to decode a Join link.
sealed class LinkDecodeError implements Exception {
  final String message;
  const LinkDecodeError(this.message);

  @override
  String toString() => 'LinkDecodeError: $message';
}

class LinkDecodeEmpty extends LinkDecodeError {
  const LinkDecodeEmpty() : super('Empty or whitespace-only input.');
}

class LinkDecodeUnsupportedCarrier extends LinkDecodeError {
  const LinkDecodeUnsupportedCarrier(super.message);
}

class LinkDecodeMissingData extends LinkDecodeError {
  const LinkDecodeMissingData() : super('Link is missing a `#data=` fragment.');
}

class LinkDecodeInQueryString extends LinkDecodeError {
  const LinkDecodeInQueryString()
      : super(
          'Link has `?data=` — payloads must be in the URL fragment '
          '(`#data=`) to prevent server-side leakage. Ask the sender to '
          'regenerate the link on an up-to-date Stronghold build.',
        );
}

class LinkDecodeInvalidBase64 extends LinkDecodeError {
  const LinkDecodeInvalidBase64(super.message);
}

class LinkDecodePayloadTooLarge extends LinkDecodeError {
  final int size;
  const LinkDecodePayloadTooLarge(this.size)
      : super('Payload is too large ($size bytes).');
}

/// Decode any accepted carrier form into the raw postcard bytes.
///
/// Callers then pass the bytes to `CommunityBridge.previewCommunity` —
/// no verification happens here, this service is only concerned with
/// unwrapping the carrier.
Uint8List decodeJoinPayload(String input) {
  final trimmed = input.trim();
  if (trimmed.isEmpty) throw const LinkDecodeEmpty();

  final base64url = _extractBase64url(trimmed);
  final bytes = _decodeBase64url(base64url);

  if (bytes.length > maxCommunityPayloadBytes) {
    throw LinkDecodePayloadTooLarge(bytes.length);
  }
  return bytes;
}

String _extractBase64url(String input) {
  // Raw base64url: no scheme prefix, no slashes. The set `[A-Za-z0-9_-]`
  // is the entire alphabet (plus optional trailing `=` padding).
  if (!input.contains('://') && !input.startsWith('#')) {
    return input;
  }

  Uri parsed;
  try {
    parsed = Uri.parse(input);
  } on FormatException catch (e) {
    throw LinkDecodeUnsupportedCarrier('Not a valid URI: ${e.message}');
  }

  // Guard rail: refuse `?data=` — that would leak to phalanx.app.
  if (parsed.queryParameters.containsKey('data')) {
    throw const LinkDecodeInQueryString();
  }

  // Reject unexpected schemes early so we don't decode something like
  // `mailto:` or `tel:` that happens to contain a `#`.
  final scheme = parsed.scheme.toLowerCase();
  const acceptedSchemes = {'phalanx', 'https', 'http'};
  if (!acceptedSchemes.contains(scheme)) {
    throw LinkDecodeUnsupportedCarrier('Scheme "$scheme" is not accepted.');
  }

  final fragment = parsed.fragment;
  if (fragment.isEmpty) throw const LinkDecodeMissingData();

  // The fragment is `data=<base64url>` or `data=<base64url>&k=v`.
  final fragmentPairs = Uri.splitQueryString(fragment);
  final data = fragmentPairs['data'];
  if (data == null || data.isEmpty) {
    throw const LinkDecodeMissingData();
  }
  return data;
}

Uint8List _decodeBase64url(String s) {
  // Dart's base64Url codec is strict about `=` padding. Postcard doesn't
  // care — we emit unpadded base64url on the Rust side. Pad to a
  // multiple of 4 before decoding.
  var padded = s;
  while (padded.length % 4 != 0) {
    padded += '=';
  }
  try {
    return base64Url.decode(padded);
  } on FormatException catch (e) {
    throw LinkDecodeInvalidBase64(e.message);
  }
}
