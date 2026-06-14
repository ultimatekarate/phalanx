// Paired golden-byte fixtures for the hand-rolled postcard decoders in
// `lib/ffi/community_models.dart`.
//
// Every byte literal below is identical to the one emitted by
// `crates/phalanx-proto/tests/dart_golden_fixtures.rs`. That pairing is
// the whole point: Rust verifies its serializer still produces the
// known bytes; Dart verifies its decoder still maps those bytes to the
// known field values. A schema change on either side that isn't
// mirrored on the other fails exactly one of the two tests.
//
// To update a fixture: regenerate the Rust EXPECTED_BYTES via
// `cargo test -p phalanx-proto --test dart_golden_fixtures`, paste the
// new bytes here, and re-check the field-level asserts still hold.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phalanx/ffi/community_models.dart';

void main() {
  group('CommunityRoster golden', () {
    // Canonical roster produced by `canonical_roster()` in the paired
    // Rust test. Keep field values in lockstep — if you change either
    // side, the paired assertions below stop holding.
    final rosterBytes = Uint8List.fromList(const [
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, //
      1, 1, 1, 1, 1, 1, 1, 1, 4, 68, 101, 109, 111, 3, 128, 226, 207, 170, 6, //
      2, 2, 10, 100, 105, 100, 58, 107, 101, 121, 58, 122, 65, 128, 222, 160, //
      203, 5, 2, 0, 10, 100, 105, 100, 58, 107, 101, 121, 58, 122, 66, 129, //
      222, 160, 203, 5, 2, 1, 3, 66, 111, 98, 1, 0, 1, 10, 100, 105, 100, 58, //
      107, 101, 121, 58, 122, 83,
    ]);

    test('decodes into the canonical field values', () {
      final roster = CommunityRoster.decode(PostcardReader(rosterBytes));

      // summary.id == [0x01; 32]
      expect(roster.summary.id.bytes, Uint8List.fromList(List.filled(32, 1)));
      expect(roster.summary.name, 'Demo');
      expect(roster.summary.memberCount, 3);
      expect(roster.summary.expiresAtMillis, 1700000000);
      expect(roster.summary.quorum, 2);

      expect(roster.members, hasLength(2));
      expect(roster.members[0].did, 'did:key:zA');
      expect(roster.members[0].joinedAtMillis, 1500000000);
      expect(roster.members[0].vouchCount, 2);
      expect(roster.members[0].petName, isNull);

      expect(roster.members[1].did, 'did:key:zB');
      expect(roster.members[1].joinedAtMillis, 1500000001);
      expect(roster.members[1].vouchCount, 2);
      expect(roster.members[1].petName, 'Bob');

      expect(roster.grants.exportToStronghold, isTrue);
      expect(roster.grants.meshTrustElevation, isFalse);

      expect(roster.strongholdDid, 'did:key:zS');
    });
  });

  group('VouchRequestPreview golden', () {
    final previewBytes = Uint8List.fromList(const [
      2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, //
      2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, //
      3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 68, 101, 109, 111, 2, //
      2, 10, 100, 105, 100, 58, 107, 101, 121, 58, 122, 65, 10, 100, 105, 100, //
      58, 107, 101, 121, 58, 122, 66, 10, 100, 105, 100, 58, 107, 101, 121, //
      58, 122, 65, 128, 226, 207, 170, 6, 228, 226, 207, 170, 6,
    ]);

    test('decodes into the canonical field values', () {
      final preview = VouchRequestPreview.decode(PostcardReader(previewBytes));

      expect(preview.requestId, Uint8List.fromList(List.filled(32, 2)));
      expect(
        preview.tentativeFingerprint.bytes,
        Uint8List.fromList(List.filled(32, 3)),
      );
      expect(preview.name, 'Demo');
      expect(preview.quorum, 2);
      expect(preview.members, ['did:key:zA', 'did:key:zB']);
      expect(preview.memberDid, 'did:key:zA');
      expect(preview.issuedAtMillis, 1700000000);
      expect(preview.memberJoinedAtMillis, 1700000100);
    });
  });

  group('CeremonyError variant goldens', () {
    // Helper: decode a raw CeremonyError payload (no outer `Result`
    // wrap) straight from the fixture bytes.
    CeremonyError decode(List<int> bytes) {
      return CeremonyError.decode(PostcardReader(Uint8List.fromList(bytes)));
    }

    test('RequestIdMismatch (discriminant 0)', () {
      final err = decode(const [0]);
      expect(err, isA<CeremonyErrorRequestIdMismatch>());
    });

    test('ResponseStale (discriminant 1)', () {
      final err = decode(const [1, 160, 56]);
      expect(err, isA<CeremonyErrorResponseStale>());
      expect((err as CeremonyErrorResponseStale).ageSeconds, 7200);
    });

    test('UnsupportedVersion (discriminant 2)', () {
      final err = decode(const [2, 2]);
      expect(err, isA<CeremonyErrorUnsupportedVersion>());
      expect((err as CeremonyErrorUnsupportedVersion).version, 0x02);
    });

    test('FingerprintMismatch (discriminant 3)', () {
      final err = decode(const [3]);
      expect(err, isA<CeremonyErrorFingerprintMismatch>());
    });

    test('DuplicateVoucher (discriminant 4)', () {
      final err = decode(const [
        4, 10, 100, 105, 100, 58, 107, 101, 121, 58, 122, 65,
      ]);
      expect(err, isA<CeremonyErrorDuplicateVoucher>());
      expect((err as CeremonyErrorDuplicateVoucher).voucher, 'did:key:zA');
    });

    test('UnknownSlot (discriminant 5)', () {
      final err = decode(const [
        5, 10, 100, 105, 100, 58, 107, 101, 121, 58, 122, 77,
      ]);
      expect(err, isA<CeremonyErrorUnknownSlot>());
      expect((err as CeremonyErrorUnknownSlot).member, 'did:key:zM');
    });

    test('VoucherMismatch (discriminant 6)', () {
      final err = decode(const [
        6, 10, 100, 105, 100, 58, 107, 101, 121, 58, 122, 69, 10, 100, 105,
        100, 58, 107, 101, 121, 58, 122, 65,
      ]);
      expect(err, isA<CeremonyErrorVoucherMismatch>());
      final mismatch = err as CeremonyErrorVoucherMismatch;
      expect(mismatch.expected, 'did:key:zE');
      expect(mismatch.actual, 'did:key:zA');
    });

    test('Verify(Expired) (discriminant 7 wrapping CommunityVerifyError.Expired)', () {
      final err = decode(const [
        7, 0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 128, 226, 207, 170, 6, 128, 160, 248,
        250, 5,
      ]);
      expect(err, isA<CeremonyErrorVerify>());
      final verify = err as CeremonyErrorVerify;
      expect(verify.inner, isA<CommunityVerifyErrorExpired>());
      final expired = verify.inner as CommunityVerifyErrorExpired;
      expect(
        expired.communityId.bytes,
        Uint8List.fromList(List.filled(32, 4)),
      );
      expect(expired.nowMillis, 1700000000);
      expect(expired.expiresAtMillis, 1600000000);
    });

    test('Assembly (discriminant 8 — decoded opaquely on Dart)', () {
      // Dart collapses every `CommunityAssemblyError` variant to the
      // opaque `CeremonyErrorAssembly`. The byte body is consumed by
      // `CeremonyError.decode`'s case-8 arm without parsing — the Rust
      // fixture pins the shape so any change in
      // `CommunityAssemblyError` breaks Rust's side first, making the
      // silent-drift case impossible.
      final err = decode(const [
        8, 0, 10, 100, 105, 100, 58, 107, 101, 121, 58, 122, 65, 160, 56,
      ]);
      expect(err, isA<CeremonyErrorAssembly>());
    });

    test('ImportFailed (discriminant 9)', () {
      final err = decode(const [
        9, 17, 115, 116, 114, 111, 110, 103, 104, 111, 108, 100, 32, 108, 111,
        99, 107, 101, 100,
      ]);
      expect(err, isA<CeremonyErrorImportFailed>());
      expect(
        (err as CeremonyErrorImportFailed).reason,
        'stronghold locked',
      );
    });
  });

  group('CommunityVerifyError variant goldens', () {
    CommunityVerifyError decode(List<int> bytes) {
      return CommunityVerifyError.decode(
        PostcardReader(Uint8List.fromList(bytes)),
      );
    }

    test('BadVouch (discriminant 1)', () {
      final err = decode(const [
        1, 10, 100, 105, 100, 58, 107, 101, 121, 58, 122, 65, 10, 100, 105,
        100, 58, 107, 101, 121, 58, 122, 66,
      ]);
      expect(err, isA<CommunityVerifyErrorBadVouch>());
      final bad = err as CommunityVerifyErrorBadVouch;
      expect(bad.member, 'did:key:zA');
      expect(bad.voucher, 'did:key:zB');
    });

    test('QuorumViolation (discriminant 2)', () {
      final err = decode(const [
        2, 10, 100, 105, 100, 58, 107, 101, 121, 58, 122, 65,
      ]);
      expect(err, isA<CommunityVerifyErrorQuorumViolation>());
      expect(
        (err as CommunityVerifyErrorQuorumViolation).member,
        'did:key:zA',
      );
    });

    test('UnsupportedVersion (discriminant 3)', () {
      final err = decode(const [3, 2]);
      expect(err, isA<CommunityVerifyErrorUnsupportedVersion>());
      expect(
        (err as CommunityVerifyErrorUnsupportedVersion).version,
        0x02,
      );
    });
  });
}
