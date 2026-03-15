/// Dart-side models mirroring the Rust FFI types.

/// Power state of the homeostatic governor.
enum PowerState {
  normal,    // 0
  conserving, // 1
  leaf,      // 2
  dormant;   // 3

  static PowerState fromInt(int value) {
    return switch (value) {
      0 => PowerState.normal,
      1 => PowerState.conserving,
      2 => PowerState.leaf,
      3 => PowerState.dormant,
      _ => PowerState.normal,
    };
  }
}

/// Trust levels for peer management.
enum TrustLevel {
  blocked,  // 0
  ignored,  // 1
  verified, // 2
  ally;     // 3

  int toInt() {
    return switch (this) {
      TrustLevel.blocked => 0,
      TrustLevel.ignored => 1,
      TrustLevel.verified => 2,
      TrustLevel.ally => 3,
    };
  }

  static TrustLevel fromString(String s) {
    return switch (s) {
      'Blocked' => TrustLevel.blocked,
      'Ignored' => TrustLevel.ignored,
      'Verified' => TrustLevel.verified,
      'Ally' => TrustLevel.ally,
      _ => TrustLevel.ignored,
    };
  }
}

/// Peer information from the trust registry.
class PeerInfo {
  final String did;
  final String? petName;
  final TrustLevel level;
  final int score;
  final bool isBlacklisted;

  const PeerInfo({
    required this.did,
    this.petName,
    required this.level,
    required this.score,
    required this.isBlacklisted,
  });

  factory PeerInfo.fromJson(Map<String, dynamic> json) {
    return PeerInfo(
      did: json['did'] as String,
      petName: json['pet_name'] as String?,
      level: TrustLevel.fromString(json['level'] as String),
      score: json['score'] as int,
      isBlacklisted: json['is_blacklisted'] as bool,
    );
  }

  /// Display name: pet name if available, otherwise truncated DID.
  String get displayName {
    if (petName != null && petName!.isNotEmpty) return petName!;
    if (did.length > 16) return '${did.substring(0, 16)}...';
    return did;
  }
}
