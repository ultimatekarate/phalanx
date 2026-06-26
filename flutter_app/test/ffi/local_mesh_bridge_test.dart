import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phalanx/ffi/local_mesh_bridge.dart';
import 'package:phalanx/ffi/phalanx_bridge.dart' show PhalanxError;

// Pure-value tests for the local-mesh bridge. The FFI marshalling itself needs
// the native library, so it is exercised by on-device integration, not here —
// these pin the value types and the status constants the bridge maps on.
void main() {
  group('local-mesh bridge value types', () {
    test('OutboundPacket holds peer and data', () {
      final pkt = OutboundPacket('did:key:zPeer', Uint8List.fromList([1, 2, 3]));
      expect(pkt.peer, 'did:key:zPeer');
      expect(pkt.data, equals(Uint8List.fromList([1, 2, 3])));
    });

    test('BleAdmit has exactly admitted and rejected', () {
      expect(BleAdmit.values, [BleAdmit.admitted, BleAdmit.rejected]);
    });

    test('admission status codes the bridge maps on are stable', () {
      // verifyAndAdmit/verifyPeer map ok -> admitted/true and
      // invalidState -> rejected/false; anything else throws.
      expect(PhalanxError.ok, 0);
      expect(PhalanxError.invalidState, -2);
    });
  });
}
