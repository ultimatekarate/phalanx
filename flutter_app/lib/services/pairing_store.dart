// Keystore-backed persistence for the deployment-profile choice and the
// Stronghold pairing (Community profile). Backed by flutter_secure_storage
// (iOS Keychain / Android Keymaster-wrapped EncryptedSharedPreferences).
//
// Threat-model note (see the plan): the pairing is durable infrastructure — a
// reachable multiaddr plus a *public* did:key — not a person-implicating
// roster, and the evidence it relates to is meant to be public. So this is
// persisted for usability; the keystore over a plain file is cheap hardening on
// the path threat-model §16 names, not a load-bearing secret.

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'pairing_link_service.dart' show PairingInfo;

class PairingStore {
  static const _profileKey = 'phalanx.deployment_profile';
  static const _addrKey = 'phalanx.stronghold_addr';
  static const _didKey = 'phalanx.stronghold_did';

  final FlutterSecureStorage _storage;

  PairingStore([FlutterSecureStorage? storage])
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
            );

  /// The persisted profile name, or null if none has been chosen yet.
  Future<String?> profile() => _storage.read(key: _profileKey);

  Future<void> setProfile(String profile) =>
      _storage.write(key: _profileKey, value: profile);

  /// The persisted Stronghold pairing, or null if unpaired.
  Future<PairingInfo?> pairing() async {
    final addr = await _storage.read(key: _addrKey);
    final did = await _storage.read(key: _didKey);
    if (addr == null || addr.isEmpty || did == null || did.isEmpty) {
      return null;
    }
    return PairingInfo(addr, did);
  }

  Future<void> setPairing(String addr, String did) async {
    await _storage.write(key: _addrKey, value: addr);
    await _storage.write(key: _didKey, value: did);
  }

  Future<void> clearPairing() async {
    await _storage.delete(key: _addrKey);
    await _storage.delete(key: _didKey);
  }
}
