import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:phalanx/services/pairing_link_service.dart';

/// Build the carrier the Stronghold `pairing` subcommand emits: base64url
/// (unpadded) of `<addr>\n<did>`, in a `phalanx://pair#data=` fragment.
String carrier(String addr, String did) {
  final b64 = base64Url.encode(utf8.encode('$addr\n$did')).replaceAll('=', '');
  return 'phalanx://pair#data=$b64';
}

void main() {
  const addr = '/ip4/203.0.113.4/udp/4001/quic-v1/p2p/12D3KooWStronghold';
  const did = 'did:key:z6MkStronghold';

  test('round-trips a phalanx://pair#data= carrier to (addr, did)', () {
    final info = decodePairingPayload(carrier(addr, did));
    expect(info.addr, addr);
    expect(info.did, did);
  });

  test('accepts a raw (schemeless) base64url payload', () {
    final b64 =
        base64Url.encode(utf8.encode('$addr\n$did')).replaceAll('=', '');
    final info = decodePairingPayload(b64);
    expect(info.addr, addr);
    expect(info.did, did);
  });

  test('rejects empty / whitespace input', () {
    expect(
      () => decodePairingPayload('   '),
      throwsA(isA<PairingDecodeEmpty>()),
    );
  });

  test('rejects ?data= in the query string (server-leak guard)', () {
    final b64 =
        base64Url.encode(utf8.encode('$addr\n$did')).replaceAll('=', '');
    expect(
      () => decodePairingPayload('https://phalanx.app/p/pair?data=$b64'),
      throwsA(isA<PairingDecodeInQueryString>()),
    );
  });

  test('rejects an address with no /p2p/ tail (not dialable)', () {
    const bad = '/ip4/203.0.113.4/udp/4001/quic-v1';
    expect(
      () => decodePairingPayload(carrier(bad, did)),
      throwsA(isA<PairingDecodeMalformed>()),
    );
  });

  test('rejects a payload missing the newline separator', () {
    final b64 =
        base64Url.encode(utf8.encode('no-newline-here')).replaceAll('=', '');
    expect(
      () => decodePairingPayload(b64),
      throwsA(isA<PairingDecodeError>()),
    );
  });

  test('rejects a non-accepted URI scheme', () {
    final b64 =
        base64Url.encode(utf8.encode('$addr\n$did')).replaceAll('=', '');
    // A `scheme://…` carrier with a non-accepted scheme reaches the URI branch
    // and is rejected there. (A schemeless `mailto:`-style string has no `://`,
    // so it is treated as raw base64 and fails to decode instead — also a
    // rejection, just a different PairingDecodeError subtype.)
    expect(
      () => decodePairingPayload('ftp://phalanx.app/p/pair#data=$b64'),
      throwsA(isA<PairingDecodeUnsupportedCarrier>()),
    );
  });
}
