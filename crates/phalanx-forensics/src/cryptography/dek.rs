// Deterministic per-recording DEK derivation.
//
// Laboratory verb. Pure logic — no IO, no time, no randomness consumed.
//
// The recovery promise: a sentinel's BIP39 phrase, applied to a fresh device,
// must yield not just the identity keypair but the ability to decrypt any
// recording previously captured under that identity. We satisfy it by
// deriving every per-recording DEK from the BIP39 seed via HKDF-SHA256.
//
// Two-stage derivation, conventional HKDF parameter ordering (RFC 5869):
//   IKM    = secret with possibly-low entropy
//   salt   = optional non-secret randomizer (None here — domain string in info is enough)
//   info   = per-derivation context
//
// Stage 1 (master):    HKDF(seed)         info=HKDF_MASTER_INFO       -> DekMaster
// Stage 2 (recording): HKDF(dek_master)   info=prefix||recording_id   -> SymmetricKey

use hkdf::Hkdf;
use phalanx_proto::crypto::{DekMaster, SymmetricKey};
use phalanx_proto::identity::RecordingId;
use sha2::Sha256;

/// Domain-separator info string for the master extraction.
///
/// Bumping the version pins the derivation to a particular HKDF construction.
/// A future v2 (different hash, different layout, additional context) gets a
/// fresh string so old recordings keep deriving under v1.
pub const HKDF_MASTER_INFO: &[u8] = b"phalanx.dek.v1.master";

/// Per-recording info-prefix. Concatenated with `recording_id.as_bytes()`
/// before being passed to `Hkdf::expand` for the per-recording DEK.
pub const HKDF_RECORDING_INFO_PREFIX: &[u8] = b"phalanx.dek.v1.recording:";

/// Domain-separator info string for the per-identity manifest's
/// deterministic RecordingId. Distinct from `HKDF_RECORDING_INFO_PREFIX` —
/// the two strings share an 8-byte `"phalanx."` head and then diverge at
/// byte 8 (`m` vs `d`), so no completion of the per-recording prefix can
/// ever equal this constant. Cross-derivation collision is impossible.
pub const HKDF_MANIFEST_ID_INFO: &[u8] = b"phalanx.manifest.v1.recording-id";

/// Derive the per-identity DEK master from a BIP39 seed.
///
/// Input: 64-byte BIP39 seed (`Mnemonic::to_seed`).
/// Output: 32-byte master, used only as input to `derive_recording_dek`.
///
/// Domain-separated from the keypair derivation (which is `seed[0..32]`) and
/// the revocation key derivation (`seed[32..64]`): we feed the entire seed
/// through HKDF with a distinct info string, so this output is uncorrelated
/// from those window-slice derivations even though the input overlaps.
pub fn derive_dek_master(seed: &[u8; 64]) -> DekMaster {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut master = [0u8; 32];
    #[allow(clippy::expect_used)]
    // HKDF-SHA256 expand to 32 bytes is mathematically infallible
    // (output length <= 255 * HashLen). expect() here is a hardcoded invariant.
    hk.expand(HKDF_MASTER_INFO, &mut master)
        .expect("HKDF expand to 32 bytes never fails");
    DekMaster::from_bytes(master)
}

/// Derive the per-recording AEAD key from the identity's `DekMaster`.
///
/// Input: identity's DekMaster + RecordingId. Output: 32-byte SymmetricKey
/// suitable for use with XChaCha20-Poly1305.
///
/// Determinism: identical (master, recording_id) → identical key, forever.
/// This is the load-bearing property of the recovery promise.
pub fn derive_recording_dek(master: &DekMaster, recording_id: &RecordingId) -> SymmetricKey {
    let hk = Hkdf::<Sha256>::new(None, master.as_bytes());
    let id_bytes = recording_id.as_str().as_bytes();
    // Capacity hint — saturating to avoid the workspace clippy
    // arithmetic-side-effects ban. The actual bytes always fit.
    let cap = HKDF_RECORDING_INFO_PREFIX
        .len()
        .saturating_add(id_bytes.len());
    let mut info = Vec::with_capacity(cap);
    info.extend_from_slice(HKDF_RECORDING_INFO_PREFIX);
    info.extend_from_slice(id_bytes);
    let mut dek = [0u8; 32];
    #[allow(clippy::expect_used)]
    // Same invariant as derive_dek_master.
    hk.expand(&info, &mut dek)
        .expect("HKDF expand to 32 bytes never fails");
    SymmetricKey::from_bytes(dek)
}

/// Derive the per-identity manifest's deterministic `RecordingId`.
///
/// Pure function of `dek_master`. A fresh-restored sentinel can compute
/// the same id from the BIP39 phrase alone, with zero local state — this
/// is the entire "discovery trick" for closing the recovery loop without
/// inventing a new mesh protocol.
///
/// The returned RecordingId has the form `manifest-{hex32}` (hyphen, not
/// colon — the colon is invalid in Windows filenames and would corrupt
/// any path that embeds the raw RecordingId string).
pub fn derive_manifest_recording_id(master: &DekMaster) -> RecordingId {
    let hk = Hkdf::<Sha256>::new(None, master.as_bytes());
    let mut id_bytes = [0u8; 32];
    #[allow(clippy::expect_used)]
    // HKDF-SHA256 expand to 32 bytes is mathematically infallible.
    hk.expand(HKDF_MANIFEST_ID_INFO, &mut id_bytes)
        .expect("HKDF expand to 32 bytes never fails");
    RecordingId::new(format!("manifest-{}", hex::encode(id_bytes)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn fixed_seed(byte: u8) -> [u8; 64] {
        [byte; 64]
    }

    #[test]
    fn master_derivation_is_deterministic() {
        let seed = fixed_seed(0x42);
        let a = derive_dek_master(&seed);
        let b = derive_dek_master(&seed);
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn master_changes_with_seed() {
        let a = derive_dek_master(&fixed_seed(0x01));
        let b = derive_dek_master(&fixed_seed(0x02));
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn recording_dek_is_deterministic() {
        let master = derive_dek_master(&fixed_seed(0xAB));
        let rid = RecordingId::new("my-recording-1");
        let a = derive_recording_dek(&master, &rid);
        let b = derive_recording_dek(&master, &rid);
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn distinct_recordings_get_distinct_deks() {
        let master = derive_dek_master(&fixed_seed(0xCD));
        let a = derive_recording_dek(&master, &RecordingId::new("rec-A"));
        let b = derive_recording_dek(&master, &RecordingId::new("rec-B"));
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn distinct_masters_yield_distinct_deks_for_same_recording() {
        let master_a = derive_dek_master(&fixed_seed(0x11));
        let master_b = derive_dek_master(&fixed_seed(0x22));
        let rid = RecordingId::new("shared-id");
        let dek_a = derive_recording_dek(&master_a, &rid);
        let dek_b = derive_recording_dek(&master_b, &rid);
        assert_ne!(dek_a.as_bytes(), dek_b.as_bytes());
    }

    #[test]
    fn one_thousand_distinct_ids_yield_one_thousand_distinct_deks() {
        // Defense against accidental collision in the per-recording
        // derivation. HKDF-SHA256 makes this trivially true; the test guards
        // against future refactors that might (e.g.) drop the ID from the
        // info input.
        let master = derive_dek_master(&fixed_seed(0xEE));
        let mut deks = std::collections::HashSet::new();
        for i in 0..1000 {
            let rid = RecordingId::new(format!("rec-{i}"));
            let dek = derive_recording_dek(&master, &rid);
            assert!(deks.insert(*dek.as_bytes()), "collision at i={i}");
        }
    }

    #[test]
    fn domain_change_changes_output() {
        // Soft canary: an alternate domain string yields a different master.
        // Cheap defense against accidental collapse of the version label —
        // the actual byte-pin would require a one-time capture and is left
        // to a follow-up CI artifact.
        let seed = fixed_seed(0xFF);
        let canonical = derive_dek_master(&seed);

        let hk = Hkdf::<Sha256>::new(None, &seed);
        let mut alt = [0u8; 32];
        hk.expand(b"phalanx.dek.v2.master", &mut alt).unwrap();
        assert_ne!(canonical.as_bytes(), &alt);
    }

    // ── Manifest RecordingId derivation (PR C) ─────────────────────────

    #[test]
    fn manifest_id_is_deterministic() {
        let master = derive_dek_master(&fixed_seed(0xA1));
        let a = derive_manifest_recording_id(&master);
        let b = derive_manifest_recording_id(&master);
        assert_eq!(a, b);
    }

    #[test]
    fn manifest_id_differs_per_master() {
        let m1 = derive_dek_master(&fixed_seed(0xA1));
        let m2 = derive_dek_master(&fixed_seed(0xA2));
        assert_ne!(
            derive_manifest_recording_id(&m1),
            derive_manifest_recording_id(&m2),
        );
    }

    #[test]
    fn manifest_id_is_windows_safe() {
        // The id flows into recording_log filenames; the prefix and the
        // hex body must avoid Windows-illegal characters (`:`, `\`, `/`,
        // `*`, `?`, `<`, `>`, `|`, `"`). hex::encode produces only
        // `[0-9a-f]`, and the prefix is `manifest-` (alphanumeric +
        // hyphen) — pin both.
        let id = derive_manifest_recording_id(&derive_dek_master(&fixed_seed(0x55)));
        let s = id.as_str();
        assert!(
            s.starts_with("manifest-"),
            "expected `manifest-` prefix, got {s}"
        );
        let hex_part = &s["manifest-".len()..];
        assert_eq!(hex_part.len(), 64, "expected 64 hex chars, got {hex_part}");
        assert!(
            hex_part
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "hex part must be lowercase [0-9a-f], got {hex_part}",
        );
        // Every char in the full id should be alphanumeric or hyphen.
        assert!(
            s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "manifest id contains non-portable character: {s}",
        );
    }

    #[test]
    fn manifest_id_is_disjoint_from_per_recording_dek_derivation() {
        // Sanity: the manifest-id derivation must produce different bytes
        // than the per-recording DEK derivation when fed the same master,
        // even if a recording_id happens to collide with the manifest-id
        // info string. Cross-derivation collision check at a fixed input.
        let master = derive_dek_master(&fixed_seed(0x77));
        let manifest_id = derive_manifest_recording_id(&master);
        // Treat the manifest id as a recording id and derive its DEK; the
        // raw HKDF outputs must differ because the info strings differ in
        // their first 13 bytes (`phalanx.dek` vs `phalanx.manifest`).
        let dek_under_manifest_id = derive_recording_dek(&master, &manifest_id);

        let hk = Hkdf::<Sha256>::new(None, master.as_bytes());
        let mut manifest_id_bytes = [0u8; 32];
        hk.expand(HKDF_MANIFEST_ID_INFO, &mut manifest_id_bytes)
            .unwrap();
        assert_ne!(dek_under_manifest_id.as_bytes(), &manifest_id_bytes);
    }
}
