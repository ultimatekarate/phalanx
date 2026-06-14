// Pairing link service — decodes a Stronghold pairing carrier (scanned QR or
// pasted text) into the (multiaddr, did) the profile picker feeds into
// `archival_peers` for the Community profile.
//
// Carrier forms (all resolve to the same base64url payload `<addr>\n<did>`):
//   1. Raw base64url — QR scanner output.
//   2. `phalanx://pair#data=<base64url>` — custom-scheme URI.
//   3. `https://phalanx.app/p/pair#data=<base64url>` — Universal Link.
//
// Mirrors `community_link_service.dart`: the payload lives in the URL *fragment*
// (`#data=`), never the query string (a fragment is never sent to a server, so
// a desktop browser hit on the Universal Link cannot leak the pairing). The
// Stronghold's `stronghold pairing` subcommand emits exactly this carrier.
//
// Pure Dart — no FFI, no platform channels — so it is unit-testable with
// `flutter test`.

import 'dart:convert';
import 'dart:typed_data';

/// A reachable Stronghold pairing: a dialable multiaddr (with a `/p2p/<peer-id>`
/// tail) and the Stronghold's `did:key`.
class PairingInfo {
  final String addr;
  final String did;
  const PairingInfo(this.addr, this.did);
}

/// Generous ceiling on a pairing payload (a multiaddr + a did:key are short).
const int maxPairingPayloadBytes = 1024;

/// What went wrong decoding a pairing carrier.
sealed class PairingDecodeError implements Exception {
  final String message;
  const PairingDecodeError(this.message);

  @override
  String toString() => 'PairingDecodeError: $message';
}

class PairingDecodeEmpty extends PairingDecodeError {
  const PairingDecodeEmpty() : super('Empty or whitespace-only input.');
}

class PairingDecodeUnsupportedCarrier extends PairingDecodeError {
  const PairingDecodeUnsupportedCarrier(super.message);
}

class PairingDecodeMissingData extends PairingDecodeError {
  const PairingDecodeMissingData()
      : super('Pairing link is missing a `#data=` fragment.');
}

class PairingDecodeInQueryString extends PairingDecodeError {
  const PairingDecodeInQueryString()
      : super(
          'Pairing payload must be in the URL fragment (`#data=`), not the '
          'query string — ask the Stronghold operator to re-share it.',
        );
}

class PairingDecodeInvalidBase64 extends PairingDecodeError {
  const PairingDecodeInvalidBase64(super.message);
}

class PairingDecodeMalformed extends PairingDecodeError {
  const PairingDecodeMalformed(super.message);
}

/// Decode any accepted carrier form into a [PairingInfo]. Throws a
/// [PairingDecodeError] subtype on any malformed input. No verification of the
/// DID or reachability happens here — the caller cross-checks dialability with
/// `phalanx_validate_pairing` before use.
PairingInfo decodePairingPayload(String input) {
  final trimmed = input.trim();
  if (trimmed.isEmpty) throw const PairingDecodeEmpty();

  final base64url = _extractBase64url(trimmed);
  final bytes = _decodeBase64url(base64url);
  if (bytes.length > maxPairingPayloadBytes) {
    throw PairingDecodeMalformed('Payload is too large (${bytes.length} bytes).');
  }

  final String text;
  try {
    text = utf8.decode(bytes);
  } on FormatException catch (e) {
    throw PairingDecodeMalformed('Payload is not valid UTF-8: ${e.message}');
  }

  final newline = text.indexOf('\n');
  if (newline < 0) {
    throw const PairingDecodeMalformed(
      'Payload is not in the expected `<addr>` newline `<did>` form.',
    );
  }
  final addr = text.substring(0, newline);
  final did = text.substring(newline + 1);
  if (addr.isEmpty || did.isEmpty) {
    throw const PairingDecodeMalformed('Pairing address or DID is empty.');
  }
  // A pairing address must be a directed-push target — i.e. carry a /p2p/ tail.
  // This mirrors the Rust `ArchivalPeer::peer_id` / `validate_pairing` check.
  if (!addr.contains('/p2p/')) {
    throw const PairingDecodeMalformed(
      'Pairing address has no /p2p/<peer-id> tail — it is not dialable.',
    );
  }
  return PairingInfo(addr, did);
}

String _extractBase64url(String input) {
  // Raw base64url: no scheme, not a bare fragment.
  if (!input.contains('://') && !input.startsWith('#')) {
    return input;
  }

  Uri parsed;
  try {
    parsed = Uri.parse(input);
  } on FormatException catch (e) {
    throw PairingDecodeUnsupportedCarrier('Not a valid URI: ${e.message}');
  }

  // Guard rail: refuse `?data=` — that would leak to phalanx.app.
  if (parsed.queryParameters.containsKey('data')) {
    throw const PairingDecodeInQueryString();
  }

  final scheme = parsed.scheme.toLowerCase();
  const acceptedSchemes = {'phalanx', 'https', 'http'};
  if (!acceptedSchemes.contains(scheme)) {
    throw PairingDecodeUnsupportedCarrier('Scheme "$scheme" is not accepted.');
  }

  final fragment = parsed.fragment;
  if (fragment.isEmpty) throw const PairingDecodeMissingData();

  final fragmentPairs = Uri.splitQueryString(fragment);
  final data = fragmentPairs['data'];
  if (data == null || data.isEmpty) throw const PairingDecodeMissingData();
  return data;
}

Uint8List _decodeBase64url(String s) {
  // The Stronghold emits unpadded base64url; Dart's codec wants `=` padding.
  var padded = s;
  while (padded.length % 4 != 0) {
    padded += '=';
  }
  try {
    return base64Url.decode(padded);
  } on FormatException catch (e) {
    throw PairingDecodeInvalidBase64(e.message);
  }
}
