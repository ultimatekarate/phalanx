import 'package:flutter_test/flutter_test.dart';
import 'package:phalanx/ffi/models.dart';

void main() {
  group('PowerState', () {
    test('fromInt maps all valid values', () {
      expect(PowerState.fromInt(0), PowerState.normal);
      expect(PowerState.fromInt(1), PowerState.conserving);
      expect(PowerState.fromInt(2), PowerState.leaf);
      expect(PowerState.fromInt(3), PowerState.dormant);
    });

    test('fromInt defaults to normal for unknown values', () {
      expect(PowerState.fromInt(-1), PowerState.normal);
      expect(PowerState.fromInt(4), PowerState.normal);
      expect(PowerState.fromInt(999), PowerState.normal);
    });
  });

  group('TrustLevel', () {
    test('toInt returns correct integer codes', () {
      expect(TrustLevel.blocked.toInt(), 0);
      expect(TrustLevel.ignored.toInt(), 1);
      expect(TrustLevel.verified.toInt(), 2);
      expect(TrustLevel.ally.toInt(), 3);
    });

    test('fromString maps all known levels', () {
      expect(TrustLevel.fromString('Blocked'), TrustLevel.blocked);
      expect(TrustLevel.fromString('Ignored'), TrustLevel.ignored);
      expect(TrustLevel.fromString('Verified'), TrustLevel.verified);
      expect(TrustLevel.fromString('Ally'), TrustLevel.ally);
    });

    test('fromString defaults to ignored for unknown strings', () {
      expect(TrustLevel.fromString(''), TrustLevel.ignored);
      expect(TrustLevel.fromString('unknown'), TrustLevel.ignored);
      expect(TrustLevel.fromString('BLOCKED'), TrustLevel.ignored);
    });

    test('toInt and fromString are consistent', () {
      // Verify the int→string→int round-trip makes sense
      for (final level in TrustLevel.values) {
        final name = level.name[0].toUpperCase() + level.name.substring(1);
        expect(TrustLevel.fromString(name), level);
      }
    });
  });

  group('PeerInfo', () {
    test('fromJson parses complete peer data', () {
      final json = {
        'did': 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        'pet_name': 'Alice',
        'level': 'Verified',
        'score': 42,
        'is_blacklisted': false,
      };

      final peer = PeerInfo.fromJson(json);

      expect(peer.did, 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK');
      expect(peer.petName, 'Alice');
      expect(peer.level, TrustLevel.verified);
      expect(peer.score, 42);
      expect(peer.isBlacklisted, false);
    });

    test('fromJson handles null pet_name', () {
      final json = {
        'did': 'did:key:z6Mk1234',
        'pet_name': null,
        'level': 'Ignored',
        'score': 0,
        'is_blacklisted': false,
      };

      final peer = PeerInfo.fromJson(json);
      expect(peer.petName, isNull);
    });

    test('fromJson handles blacklisted peer', () {
      final json = {
        'did': 'did:key:z6MkEvil',
        'pet_name': null,
        'level': 'Blocked',
        'score': -10,
        'is_blacklisted': true,
      };

      final peer = PeerInfo.fromJson(json);
      expect(peer.level, TrustLevel.blocked);
      expect(peer.isBlacklisted, true);
      expect(peer.score, -10);
    });

    group('displayName', () {
      test('returns pet name when available', () {
        final peer = PeerInfo(
          did: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          petName: 'Alice',
          level: TrustLevel.verified,
          score: 0,
          isBlacklisted: false,
        );
        expect(peer.displayName, 'Alice');
      });

      test('returns truncated DID when no pet name', () {
        final peer = PeerInfo(
          did: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          petName: null,
          level: TrustLevel.ignored,
          score: 0,
          isBlacklisted: false,
        );
        expect(peer.displayName, 'did:key:z6MkhaXg...');
      });

      test('returns truncated DID for empty pet name', () {
        final peer = PeerInfo(
          did: 'did:key:z6MkhaXgBZDvotDkL5257',
          petName: '',
          level: TrustLevel.ignored,
          score: 0,
          isBlacklisted: false,
        );
        expect(peer.displayName, 'did:key:z6MkhaXg...');
      });

      test('returns full DID when 16 chars or shorter', () {
        final peer = PeerInfo(
          did: 'did:key:short',
          petName: null,
          level: TrustLevel.ignored,
          score: 0,
          isBlacklisted: false,
        );
        expect(peer.displayName, 'did:key:short');
      });
    });
  });
}
