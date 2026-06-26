import 'dart:ffi';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phalanx/ffi/local_mesh_bridge.dart';
import 'package:phalanx/services/local_mesh_service.dart';

/// Fake [LocalMeshApi] — records calls and returns programmed results, so the
/// service is tested with no native library.
class _FakeApi implements LocalMeshApi {
  final List<String> calls = [];
  bool? lastAvailable;
  Pointer<Void>? lastHandle;
  BleAdmit admitResult = BleAdmit.admitted;
  bool verifyResult = true;
  Uint8List challengeResult = Uint8List.fromList([1, 2, 3]);
  Uint8List responseResult = Uint8List.fromList([4, 5, 6]);
  OutboundPacket? outbound;

  @override
  Uint8List makeChallenge(Pointer<Void> handle) {
    calls.add('makeChallenge');
    lastHandle = handle;
    return challengeResult;
  }

  @override
  Uint8List signChallenge(Pointer<Void> handle, Uint8List challenge) {
    calls.add('signChallenge');
    return responseResult;
  }

  @override
  bool verifyPeer(Pointer<Void> handle, Uint8List challenge, Uint8List response) {
    calls.add('verifyPeer');
    return verifyResult;
  }

  @override
  BleAdmit verifyAndAdmit(
    Pointer<Void> handle,
    Uint8List challenge,
    Uint8List response,
  ) {
    calls.add('verifyAndAdmit');
    return admitResult;
  }

  @override
  void pushDataReceived(
    Pointer<Void> handle,
    String peer,
    String topic,
    Uint8List data,
  ) {
    calls.add('pushDataReceived:$peer:$topic');
  }

  @override
  void pushPeerDisconnected(Pointer<Void> handle, String peer) {
    calls.add('pushPeerDisconnected:$peer');
  }

  @override
  OutboundPacket? pollOutbound(Pointer<Void> handle) {
    calls.add('pollOutbound');
    return outbound;
  }

  @override
  void setAvailable(Pointer<Void> handle, bool available) {
    calls.add('setAvailable:$available');
    lastAvailable = available;
  }
}

void main() {
  // A non-null stub handle ("engine ready") and the null handle ("engine gone").
  // Neither is ever dereferenced — the fake ignores it.
  final ready = Pointer<Void>.fromAddress(0x1000);

  group('LocalMeshService with a live engine', () {
    late _FakeApi api;
    late LocalMeshService svc;
    setUp(() {
      api = _FakeApi();
      svc = LocalMeshService(api: api, handleSource: () => ready);
    });

    test('reports engine ready', () {
      expect(svc.isEngineReady, isTrue);
    });

    test('makeChallenge delegates and passes the engine handle', () {
      final blob = svc.makeChallenge();
      expect(blob, equals(api.challengeResult));
      expect(api.calls, contains('makeChallenge'));
      expect(api.lastHandle, equals(ready));
    });

    test('verifyAndAdmit returns the api result', () {
      api.admitResult = BleAdmit.rejected;
      expect(svc.verifyAndAdmit(Uint8List(0), Uint8List(0)), BleAdmit.rejected);
      api.admitResult = BleAdmit.admitted;
      expect(svc.verifyAndAdmit(Uint8List(0), Uint8List(0)), BleAdmit.admitted);
    });

    test('setAvailable toggles through to the api', () {
      svc.setAvailable(true);
      expect(api.lastAvailable, isTrue);
      svc.setAvailable(false);
      expect(api.lastAvailable, isFalse);
    });

    test('push methods delegate', () {
      svc.pushDataReceived('peerA', 'topicX', Uint8List.fromList([9]));
      svc.pushPeerDisconnected('peerA');
      expect(
        api.calls,
        containsAll(['pushDataReceived:peerA:topicX', 'pushPeerDisconnected:peerA']),
      );
    });

    test('pollOutbound returns the queued packet', () {
      api.outbound = OutboundPacket('peerB', Uint8List.fromList([7, 8]));
      final pkt = svc.pollOutbound();
      expect(pkt?.peer, 'peerB');
      expect(pkt?.data, equals(Uint8List.fromList([7, 8])));
    });
  });

  group('LocalMeshService with no engine (null handle)', () {
    late _FakeApi api;
    late LocalMeshService svc;
    setUp(() {
      api = _FakeApi();
      svc = LocalMeshService(api: api, handleSource: () => nullptr);
    });

    test('reports engine not ready', () {
      expect(svc.isEngineReady, isFalse);
    });

    test('byte-returning calls yield null and never reach the api', () {
      expect(svc.makeChallenge(), isNull);
      expect(svc.signChallenge(Uint8List(0)), isNull);
      expect(svc.pollOutbound(), isNull);
      expect(api.calls, isEmpty);
    });

    test('verifyAndAdmit defaults to rejected; verifyPeer to false', () {
      expect(svc.verifyAndAdmit(Uint8List(0), Uint8List(0)), BleAdmit.rejected);
      expect(svc.verifyPeer(Uint8List(0), Uint8List(0)), isFalse);
      expect(api.calls, isEmpty);
    });

    test('push / setAvailable are no-ops', () {
      svc.pushDataReceived('p', 't', Uint8List(0));
      svc.pushPeerDisconnected('p');
      svc.setAvailable(true);
      expect(api.calls, isEmpty);
    });
  });
}
