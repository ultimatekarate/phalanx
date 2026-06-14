// Community wire types — hand-rolled Dart mirrors of the postcard-encoded
// Rust shapes defined in `phalanx-proto/src/identity/community.rs`.
//
// Postcard is a schema-free binary Serde format. Integers are LEB128 varints,
// strings are `varint-len || utf-8 bytes`, enums are `varint discriminant ||
// variant payload`, fixed arrays (like `[u8; 32]`) are emitted raw with no
// length prefix. Option<T> is `0` (None) or `1 || T` (Some). Bools are 1 byte.
//
// **Schema drift is caught by a paired golden-bytes test.**
// `crates/phalanx-proto/tests/dart_golden_fixtures.rs` serializes canonical
// Rust values and pins the bytes; `test/ffi/community_models_golden_test.dart`
// embeds the same byte literals, runs the Dart decoders below, and asserts
// field-by-field. A Rust-side reshape that isn't mirrored here fails the
// Dart golden; a Dart-side decoder edit that doesn't match the wire fails
// the Dart golden; a Rust-side change with no matching byte literal update
// fails the Rust golden. Run both before shipping any change to these
// decoders or to the matching Rust structs. Prefer adding a
// `#[non_exhaustive]` variant with a new discriminant over reshuffling
// existing fields.

import 'dart:convert';
import 'dart:typed_data';

// ── Postcard primitives ────────────────────────────────────────────────

/// Stateful cursor over a postcard byte stream. Used by every decoder.
class PostcardReader {
  final Uint8List _bytes;
  int _offset = 0;

  PostcardReader(this._bytes);

  int get offset => _offset;
  bool get isExhausted => _offset >= _bytes.length;

  int _byte() {
    if (_offset >= _bytes.length) {
      throw const FormatException('PostcardReader: unexpected end of input');
    }
    final b = _bytes[_offset];
    _offset += 1;
    return b;
  }

  /// LEB128 varint (unsigned). Postcard never emits more than 10 continuation
  /// bytes for a u64, so that bounds the loop.
  int readVarint() {
    int result = 0;
    int shift = 0;
    for (int i = 0; i < 10; i++) {
      final b = _byte();
      result |= (b & 0x7f) << shift;
      if ((b & 0x80) == 0) return result;
      shift += 7;
    }
    throw const FormatException('PostcardReader: varint overflow');
  }

  bool readBool() {
    final b = _byte();
    if (b == 0) return false;
    if (b == 1) return true;
    throw FormatException('PostcardReader: invalid bool byte $b');
  }

  int readU8() => _byte();

  int readU16() => readVarint();

  int readU64() => readVarint();

  String readString() {
    final len = readVarint();
    if (len < 0 || _offset + len > _bytes.length) {
      throw FormatException('PostcardReader: string length $len out of range');
    }
    final slice = _bytes.sublist(_offset, _offset + len);
    _offset += len;
    return utf8.decode(slice);
  }

  /// Fixed-size byte array: postcard emits raw bytes with no length prefix.
  Uint8List readBytes(int n) {
    if (_offset + n > _bytes.length) {
      throw FormatException('PostcardReader: not enough bytes for array of $n');
    }
    final slice = Uint8List.fromList(_bytes.sublist(_offset, _offset + n));
    _offset += n;
    return slice;
  }

  /// `Option<T>`: `0` = None, `1` = Some(T).
  T? readOption<T>(T Function(PostcardReader) decode) {
    final tag = _byte();
    if (tag == 0) return null;
    if (tag == 1) return decode(this);
    throw FormatException('PostcardReader: invalid Option tag $tag');
  }

  List<T> readVec<T>(T Function(PostcardReader) decode) {
    final len = readVarint();
    final out = <T>[];
    for (int i = 0; i < len; i++) {
      out.add(decode(this));
    }
    return out;
  }
}

// ── Noun mirrors ───────────────────────────────────────────────────────

/// `CommunityId(pub [u8; 32])` — deterministic BLAKE3 fingerprint.
class CommunityId {
  final Uint8List bytes;

  CommunityId(this.bytes) {
    if (bytes.length != 32) {
      throw ArgumentError('CommunityId must be 32 bytes, got ${bytes.length}');
    }
  }

  static CommunityId decode(PostcardReader r) => CommunityId(r.readBytes(32));

  /// Lower-case hex, 64 chars. Matches `hex_encode` on the Rust side.
  String toHex() {
    final sb = StringBuffer();
    for (final b in bytes) {
      sb.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return sb.toString();
  }

  /// First 16 hex chars — the shortened fingerprint used in list views.
  String toShortHex() => toHex().substring(0, 16);

  @override
  bool operator ==(Object other) {
    if (other is! CommunityId) return false;
    if (other.bytes.length != bytes.length) return false;
    for (int i = 0; i < bytes.length; i++) {
      if (other.bytes[i] != bytes[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode => Object.hashAll(bytes);
}

/// Compact view of a community for list screens.
class CommunitySummary {
  final CommunityId id;
  final String name;
  final int memberCount;
  /// Epoch milliseconds (mirrors Rust `PhalanxTimestamp(u64)`).
  final int expiresAtMillis;
  final int quorum;

  const CommunitySummary({
    required this.id,
    required this.name,
    required this.memberCount,
    required this.expiresAtMillis,
    required this.quorum,
  });

  static CommunitySummary decode(PostcardReader r) {
    final id = CommunityId.decode(r);
    final name = r.readString();
    final memberCount = r.readU16();
    final expiresAtMillis = r.readU64();
    final quorum = r.readU8();
    return CommunitySummary(
      id: id,
      name: name,
      memberCount: memberCount,
      expiresAtMillis: expiresAtMillis,
      quorum: quorum,
    );
  }

  Duration? get timeUntilExpiry {
    final now = DateTime.now().millisecondsSinceEpoch;
    final remaining = expiresAtMillis - now;
    if (remaining <= 0) return null;
    return Duration(milliseconds: remaining);
  }

  bool get isExpired => timeUntilExpiry == null;
}

/// Per-member row in a roster.
class MemberSummary {
  final String did;
  final int joinedAtMillis;
  final int vouchCount;
  final String? petName;

  const MemberSummary({
    required this.did,
    required this.joinedAtMillis,
    required this.vouchCount,
    this.petName,
  });

  static MemberSummary decode(PostcardReader r) {
    final did = r.readString();
    final joinedAtMillis = r.readU64();
    final vouchCount = r.readU16();
    final petName = r.readOption<String>((r) => r.readString());
    return MemberSummary(
      did: did,
      joinedAtMillis: joinedAtMillis,
      vouchCount: vouchCount,
      petName: petName,
    );
  }

  String get displayName {
    if (petName != null && petName!.isNotEmpty) return petName!;
    if (did.length > 20) return '${did.substring(0, 16)}...${did.substring(did.length - 4)}';
    return did;
  }
}

/// `CommunityGrants { export_to_stronghold: bool, mesh_trust_elevation: bool }`.
class CommunityGrants {
  final bool exportToStronghold;
  final bool meshTrustElevation;

  const CommunityGrants({
    required this.exportToStronghold,
    required this.meshTrustElevation,
  });

  static CommunityGrants decode(PostcardReader r) {
    return CommunityGrants(
      exportToStronghold: r.readBool(),
      meshTrustElevation: r.readBool(),
    );
  }
}

/// Full roster returned by `phalanx_get_community` / `phalanx_preview_community`.
class CommunityRoster {
  final CommunitySummary summary;
  final List<MemberSummary> members;
  final CommunityGrants grants;
  final String? strongholdDid;

  const CommunityRoster({
    required this.summary,
    required this.members,
    required this.grants,
    this.strongholdDid,
  });

  static CommunityRoster decode(PostcardReader r) {
    final summary = CommunitySummary.decode(r);
    final members = r.readVec<MemberSummary>((r) => MemberSummary.decode(r));
    final grants = CommunityGrants.decode(r);
    final strongholdDid = r.readOption<String>((r) => r.readString());
    return CommunityRoster(
      summary: summary,
      members: members,
      grants: grants,
      strongholdDid: strongholdDid,
    );
  }
}

// ── Error surfaces ─────────────────────────────────────────────────────

/// Mirrors Rust `CommunityVerifyError` — `#[non_exhaustive]` on the Rust
/// side means a later build may emit a new variant. The Dart decoder
/// catches unknown discriminants and reports them as [unknownVariant].
sealed class CommunityVerifyError {
  const CommunityVerifyError();

  static CommunityVerifyError decode(PostcardReader r) {
    final tag = r.readVarint();
    switch (tag) {
      case 0:
        final communityId = CommunityId.decode(r);
        final nowMillis = r.readU64();
        final expiresAtMillis = r.readU64();
        return CommunityVerifyErrorExpired(
          communityId: communityId,
          nowMillis: nowMillis,
          expiresAtMillis: expiresAtMillis,
        );
      case 1:
        final member = r.readString();
        final voucher = r.readString();
        return CommunityVerifyErrorBadVouch(member: member, voucher: voucher);
      case 2:
        final member = r.readString();
        return CommunityVerifyErrorQuorumViolation(member: member);
      case 3:
        final version = r.readU8();
        return CommunityVerifyErrorUnsupportedVersion(version: version);
      default:
        return CommunityVerifyErrorUnknown(variant: tag);
    }
  }

  String get userMessage;
}

class CommunityVerifyErrorExpired extends CommunityVerifyError {
  final CommunityId communityId;
  final int nowMillis;
  final int expiresAtMillis;

  const CommunityVerifyErrorExpired({
    required this.communityId,
    required this.nowMillis,
    required this.expiresAtMillis,
  });

  @override
  String get userMessage => 'This community has expired. Ask the organizer for a fresh token.';
}

class CommunityVerifyErrorBadVouch extends CommunityVerifyError {
  final String member;
  final String voucher;

  const CommunityVerifyErrorBadVouch({required this.member, required this.voucher});

  @override
  String get userMessage => 'A vouch signature is invalid — the community token is corrupted or tampered.';
}

class CommunityVerifyErrorQuorumViolation extends CommunityVerifyError {
  final String member;

  const CommunityVerifyErrorQuorumViolation({required this.member});

  @override
  String get userMessage => 'Insufficient vouches for a member. Token does not meet quorum.';
}

class CommunityVerifyErrorUnsupportedVersion extends CommunityVerifyError {
  final int version;

  const CommunityVerifyErrorUnsupportedVersion({required this.version});

  @override
  String get userMessage => 'Community token uses envelope version $version, which this build does not understand. Update the app.';
}

class CommunityVerifyErrorUnknown extends CommunityVerifyError {
  final int variant;

  const CommunityVerifyErrorUnknown({required this.variant});

  @override
  String get userMessage => 'Verification failed (unknown reason code $variant).';
}

// ── FFI outcomes ───────────────────────────────────────────────────────

/// Mirrors Rust `ImportOutcome::Ok(CommunityId) | Err(CommunityVerifyError)`.
sealed class ImportOutcome {
  const ImportOutcome();

  static ImportOutcome decode(Uint8List bytes) {
    final r = PostcardReader(bytes);
    final tag = r.readVarint();
    switch (tag) {
      case 0:
        return ImportOutcomeOk(id: CommunityId.decode(r));
      case 1:
        return ImportOutcomeErr(error: CommunityVerifyError.decode(r));
      default:
        throw FormatException('ImportOutcome: unknown variant $tag');
    }
  }
}

class ImportOutcomeOk extends ImportOutcome {
  final CommunityId id;
  const ImportOutcomeOk({required this.id});
}

class ImportOutcomeErr extends ImportOutcome {
  final CommunityVerifyError error;
  const ImportOutcomeErr({required this.error});
}

/// Mirrors Rust `DissolveOutcome::Ok(CommunityId) | NotFound`.
sealed class DissolveOutcome {
  const DissolveOutcome();

  static DissolveOutcome decode(Uint8List bytes) {
    final r = PostcardReader(bytes);
    final tag = r.readVarint();
    switch (tag) {
      case 0:
        return DissolveOutcomeOk(id: CommunityId.decode(r));
      case 1:
        return const DissolveOutcomeNotFound();
      default:
        throw FormatException('DissolveOutcome: unknown variant $tag');
    }
  }
}

class DissolveOutcomeOk extends DissolveOutcome {
  final CommunityId id;
  const DissolveOutcomeOk({required this.id});
}

class DissolveOutcomeNotFound extends DissolveOutcome {
  const DissolveOutcomeNotFound();
}

/// Mirrors `Result<CommunityRoster, CommunityVerifyError>` returned by
/// `phalanx_preview_community`. Postcard encodes `Result<T, E>` as a Rust
/// enum: `0 || T` for Ok, `1 || E` for Err.
sealed class PreviewOutcome {
  const PreviewOutcome();

  static PreviewOutcome decode(Uint8List bytes) {
    final r = PostcardReader(bytes);
    final tag = r.readVarint();
    switch (tag) {
      case 0:
        return PreviewOutcomeOk(roster: CommunityRoster.decode(r));
      case 1:
        return PreviewOutcomeErr(error: CommunityVerifyError.decode(r));
      default:
        throw FormatException('PreviewOutcome: unknown variant $tag');
    }
  }
}

class PreviewOutcomeOk extends PreviewOutcome {
  final CommunityRoster roster;
  const PreviewOutcomeOk({required this.roster});
}

class PreviewOutcomeErr extends PreviewOutcome {
  final CommunityVerifyError error;
  const PreviewOutcomeErr({required this.error});
}

/// `Option<CommunityRoster>` — returned by `phalanx_get_community`.
CommunityRoster? decodeOptionalRoster(Uint8List bytes) {
  final r = PostcardReader(bytes);
  return r.readOption<CommunityRoster>((r) => CommunityRoster.decode(r));
}

/// `Vec<CommunitySummary>` — returned by `phalanx_list_communities`.
List<CommunitySummary> decodeSummaryList(Uint8List bytes) {
  final r = PostcardReader(bytes);
  return r.readVec<CommunitySummary>((r) => CommunitySummary.decode(r));
}

// ── Ceremony Nouns ─────────────────────────────────────────────────────
//
// Mirrors of `phalanx_proto::community::{VouchRequestPreview, CeremonyError}`.
// The Vouch screen consumes `VouchRequestPreview` from
// `phalanx_preview_vouch_request`, then hands the raw request bytes to
// `phalanx_sign_vouch_request` and receives a wrapped `VouchResponse` byte
// buffer it can display as a QR or write to a file.
//
// The Dart side never decodes `VouchRequest` or `VouchResponse` itself —
// the raw wrapped bytes round-trip straight through FFI. Keeping those
// opaque on Dart keeps the postcard surface here small and the schema
// drift blast radius narrow.

/// `VouchRequestPreview` — review-safe projection of a `VouchRequest`.
///
/// Postcard layout: `request_id || fingerprint || name || quorum ||
/// members || member_did || issued_at || member_joined_at`. The Rust
/// shape is at `phalanx-proto/src/identity/community.rs`.
class VouchRequestPreview {
  /// 32-byte BLAKE3 request id; equal to the initiator's
  /// `VouchRequest::compute_id` output.
  final Uint8List requestId;

  /// Community fingerprint the signature will bind.
  final CommunityId tentativeFingerprint;

  /// Human-readable community name (PetName newtype on the Rust side).
  final String name;

  /// Quorum threshold the organiser chose.
  final int quorum;

  /// Full ceremony roster — shown at Review so the voucher knows who
  /// else is in the web of trust.
  final List<String> members;

  /// The member this request vouches *for*.
  final String memberDid;

  /// Wall-clock time the initiator issued the request. Drives the UX
  /// freshness countdown — the *signed* freshness gate uses
  /// `memberJoinedAtMillis`.
  final int issuedAtMillis;

  /// The `joined_at` value the voucher's signature binds. Checked on
  /// the initiator side against `CEREMONY_RESPONSE_FRESHNESS_SECS`.
  final int memberJoinedAtMillis;

  const VouchRequestPreview({
    required this.requestId,
    required this.tentativeFingerprint,
    required this.name,
    required this.quorum,
    required this.members,
    required this.memberDid,
    required this.issuedAtMillis,
    required this.memberJoinedAtMillis,
  });

  static VouchRequestPreview decode(PostcardReader r) {
    final requestId = r.readBytes(32);
    final tentative = CommunityId.decode(r);
    final name = r.readString();
    final quorum = r.readU8();
    final members = r.readVec<String>((r) => r.readString());
    final memberDid = r.readString();
    final issuedAt = r.readU64();
    final memberJoinedAt = r.readU64();
    return VouchRequestPreview(
      requestId: requestId,
      tentativeFingerprint: tentative,
      name: name,
      quorum: quorum,
      members: members,
      memberDid: memberDid,
      issuedAtMillis: issuedAt,
      memberJoinedAtMillis: memberJoinedAt,
    );
  }

  /// First 16 hex chars of `requestId` — matches the Stronghold's
  /// `short_hex` helper used in the Ceremony panel row labels.
  String requestIdShortHex() {
    final sb = StringBuffer();
    for (int i = 0; i < 8 && i < requestId.length; i++) {
      sb.write(requestId[i].toRadixString(16).padLeft(2, '0'));
    }
    return sb.toString();
  }
}

/// Mirrors Rust `CeremonyError`. `#[non_exhaustive]` on the Rust side
/// means a future build may ship a new variant — the decoder catches
/// unknown discriminants and surfaces them as [CeremonyErrorUnknown].
///
/// Variant ordering MUST match the Rust source declaration order —
/// postcard assigns discriminants positionally. See
/// `phalanx-proto/src/identity/community.rs`.
sealed class CeremonyError {
  const CeremonyError();

  static CeremonyError decode(PostcardReader r) {
    final tag = r.readVarint();
    switch (tag) {
      case 0:
        return const CeremonyErrorRequestIdMismatch();
      case 1:
        final age = r.readU64();
        return CeremonyErrorResponseStale(ageSeconds: age);
      case 2:
        final version = r.readU8();
        return CeremonyErrorUnsupportedVersion(version: version);
      case 3:
        return const CeremonyErrorFingerprintMismatch();
      case 4:
        final voucher = r.readString();
        return CeremonyErrorDuplicateVoucher(voucher: voucher);
      case 5:
        final member = r.readString();
        return CeremonyErrorUnknownSlot(member: member);
      case 6:
        final expected = r.readString();
        final actual = r.readString();
        return CeremonyErrorVoucherMismatch(
          expected: expected,
          actual: actual,
        );
      case 7:
        return CeremonyErrorVerify(inner: CommunityVerifyError.decode(r));
      case 8:
        // `Assembly(CommunityAssemblyError)` — sign_vouch_response never
        // produces this on the mobile side (assembly lives on the
        // Stronghold). Surface opaquely rather than maintain a parallel
        // decoder for `CommunityAssemblyError`'s seven variants.
        return const CeremonyErrorAssembly();
      case 9:
        // `ImportFailed { reason: String }` — fires when assembly
        // succeeds but the subsequent import into the Stronghold
        // roster fails (post-assembly `StrongholdError`). The phone
        // only sees this via mirrored toast copy from the Stronghold,
        // but decode it here so the Dart side does not degrade to
        // the opaque `Unknown` fallback.
        final reason = r.readString();
        return CeremonyErrorImportFailed(reason: reason);
      default:
        return CeremonyErrorUnknown(variant: tag);
    }
  }

  String get userMessage;
}

class CeremonyErrorRequestIdMismatch extends CeremonyError {
  const CeremonyErrorRequestIdMismatch();

  @override
  String get userMessage =>
      'This response was signed for a different ceremony.';
}

class CeremonyErrorResponseStale extends CeremonyError {
  final int ageSeconds;
  const CeremonyErrorResponseStale({required this.ageSeconds});

  @override
  String get userMessage =>
      'This request is past the one-hour freshness window '
      '(${ageSeconds}s old). Ask the organiser for a fresh one.';
}

class CeremonyErrorUnsupportedVersion extends CeremonyError {
  final int version;
  const CeremonyErrorUnsupportedVersion({required this.version});

  @override
  String get userMessage =>
      'This request uses envelope version $version, which this build '
      'does not understand. Update the app.';
}

class CeremonyErrorFingerprintMismatch extends CeremonyError {
  const CeremonyErrorFingerprintMismatch();

  @override
  String get userMessage =>
      'The response signs a different community than the request.';
}

class CeremonyErrorDuplicateVoucher extends CeremonyError {
  final String voucher;
  const CeremonyErrorDuplicateVoucher({required this.voucher});

  @override
  String get userMessage => 'This device has already signed this slot.';
}

class CeremonyErrorUnknownSlot extends CeremonyError {
  final String member;
  const CeremonyErrorUnknownSlot({required this.member});

  @override
  String get userMessage => 'The response references an unknown slot.';
}

class CeremonyErrorVoucherMismatch extends CeremonyError {
  final String expected;
  final String actual;
  const CeremonyErrorVoucherMismatch({
    required this.expected,
    required this.actual,
  });

  @override
  String get userMessage =>
      'This request is addressed to another device — '
      'ask the organiser for the request that targets this phone.';
}

class CeremonyErrorVerify extends CeremonyError {
  final CommunityVerifyError inner;
  const CeremonyErrorVerify({required this.inner});

  @override
  String get userMessage => inner.userMessage;
}

class CeremonyErrorAssembly extends CeremonyError {
  const CeremonyErrorAssembly();

  @override
  String get userMessage =>
      'Community assembly failed on the coordinator. '
      'This should not reach the voucher — please report.';
}

class CeremonyErrorImportFailed extends CeremonyError {
  final String reason;
  const CeremonyErrorImportFailed({required this.reason});

  @override
  String get userMessage =>
      'Community assembled but failed to install on the coordinator: '
      '$reason';
}

class CeremonyErrorUnknown extends CeremonyError {
  final int variant;
  const CeremonyErrorUnknown({required this.variant});

  @override
  String get userMessage =>
      'Ceremony failed (unknown reason code $variant — the coordinator '
      'may be running a newer build).';
}

// ── Ceremony FFI outcomes ──────────────────────────────────────────────

/// Mirrors `Result<VouchRequestPreview, CeremonyError>` from
/// `phalanx_preview_vouch_request`.
sealed class PreviewVouchOutcome {
  const PreviewVouchOutcome();

  static PreviewVouchOutcome decode(Uint8List bytes) {
    final r = PostcardReader(bytes);
    final tag = r.readVarint();
    switch (tag) {
      case 0:
        return PreviewVouchOutcomeOk(preview: VouchRequestPreview.decode(r));
      case 1:
        return PreviewVouchOutcomeErr(error: CeremonyError.decode(r));
      default:
        throw FormatException('PreviewVouchOutcome: unknown variant $tag');
    }
  }
}

class PreviewVouchOutcomeOk extends PreviewVouchOutcome {
  final VouchRequestPreview preview;
  const PreviewVouchOutcomeOk({required this.preview});
}

class PreviewVouchOutcomeErr extends PreviewVouchOutcome {
  final CeremonyError error;
  const PreviewVouchOutcomeErr({required this.error});
}

/// Mirrors `Result<Vec<u8>, CeremonyError>` from
/// `phalanx_sign_vouch_request`. On `Ok`, the inner `Vec<u8>` is the
/// already-wrapped `VouchResponse` envelope — ready to hand to a QR
/// renderer, a file writer, or the share-sheet.
sealed class SignVouchOutcome {
  const SignVouchOutcome();

  static SignVouchOutcome decode(Uint8List bytes) {
    final r = PostcardReader(bytes);
    final tag = r.readVarint();
    switch (tag) {
      case 0:
        final len = r.readVarint();
        return SignVouchOutcomeOk(wrappedResponse: r.readBytes(len));
      case 1:
        return SignVouchOutcomeErr(error: CeremonyError.decode(r));
      default:
        throw FormatException('SignVouchOutcome: unknown variant $tag');
    }
  }
}

class SignVouchOutcomeOk extends SignVouchOutcome {
  /// Raw `[VOUCH_RESPONSE_VERSION] || postcard(VouchResponse)` bytes.
  final Uint8List wrappedResponse;
  const SignVouchOutcomeOk({required this.wrappedResponse});
}

class SignVouchOutcomeErr extends SignVouchOutcome {
  final CeremonyError error;
  const SignVouchOutcomeErr({required this.error});
}
