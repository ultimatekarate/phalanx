// crates/phalanx-ffi/src/mnemonic.rs
//
// Pure-function FFI: BIP-39 mnemonic validation.
//
// The Flutter `MnemonicInputGrid` widget calls this once when all 12 cells
// contain a wordlist-valid word, to verify the checksum (the one property
// the local Dart-side check can't do without re-implementing the bip39
// crate's PBKDF2/SHA256-truncate algorithm). Per-keystroke wordlist lookup
// is done locally against a vendored Dart set; keeping the FFI to one call
// at submit time avoids hundreds of cheap roundtrips while keeping `bip39`
// as the single source of truth for the checksum algorithm.
//
// Stateless: no PhalanxHandle, callable before/without `phalanx_create`.

use crate::error::PhalanxError;

use std::ffi::CStr;
use std::os::raw::c_char;

use phalanx_forensics::cryptography::mnemonic::{MnemonicValidation, validate_mnemonic};
use zeroize::Zeroize;

/// Validate a BIP-39 mnemonic phrase. Checks wordlist membership AND checksum
/// against the `bip39` crate's auto-detected language (English, Japanese,
/// Korean, Spanish, Chinese-Simplified, Chinese-Traditional, French, Italian,
/// Czech, or Portuguese).
///
/// Returns:
/// * `PhalanxError::Ok` (0) — phrase parses cleanly and the checksum is valid.
/// * `PhalanxError::NullPointer` (-1) — `phrase` is null.
/// * `PhalanxError::InvalidUtf8` (-3) — `phrase` is not valid UTF-8.
/// * `PhalanxError::MnemonicParseError` (-19) — wordlist violation or
///   checksum failure. Distinguishing between the two is intentionally
///   omitted from the FFI surface: the Flutter caller already knows wordlist
///   membership per cell from its local lookup, so a -19 after all cells
///   pass the local check is necessarily a checksum failure.
///
/// The phrase is zeroized immediately after parsing.
///
/// # Safety
/// * `phrase` must be a valid null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_validate_mnemonic(phrase: *const c_char) -> i32 {
    // SAFETY: caller upholds the # Safety contract on the parent
    // `unsafe extern "C" fn`. `phrase` is null-checked before
    // `CStr::from_ptr` reads it as a caller-guaranteed NUL-terminated C
    // string that outlives the call.
    unsafe {
        if phrase.is_null() {
            return PhalanxError::NullPointer.code();
        }

        let phrase_str = match CStr::from_ptr(phrase).to_str() {
            Ok(s) => s,
            Err(_) => return PhalanxError::InvalidUtf8.code(),
        };

        let mut owned = phrase_str.to_string();
        let outcome = validate_mnemonic(&owned);
        owned.zeroize();

        match outcome {
            MnemonicValidation::Valid => PhalanxError::Ok.code(),
            MnemonicValidation::Invalid => PhalanxError::MnemonicParseError.code(),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::undocumented_unsafe_blocks
)]
mod tests {
    use super::*;
    use std::ffi::CString;

    const VALID_ENGLISH: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn null_phrase_returns_null_pointer() {
        unsafe {
            assert_eq!(
                phalanx_validate_mnemonic(std::ptr::null()),
                PhalanxError::NullPointer.code()
            );
        }
    }

    #[test]
    fn valid_phrase_returns_ok() {
        unsafe {
            let phrase = CString::new(VALID_ENGLISH).expect("valid");
            assert_eq!(
                phalanx_validate_mnemonic(phrase.as_ptr()),
                PhalanxError::Ok.code()
            );
        }
    }

    #[test]
    fn bad_checksum_returns_mnemonic_parse_error() {
        unsafe {
            // 12 valid English wordlist words but with a wrong checksum
            // (last word swapped to one whose entropy bits don't match).
            let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
            let phrase = CString::new(bad).expect("valid");
            assert_eq!(
                phalanx_validate_mnemonic(phrase.as_ptr()),
                PhalanxError::MnemonicParseError.code()
            );
        }
    }

    #[test]
    fn out_of_wordlist_word_returns_mnemonic_parse_error() {
        unsafe {
            let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzz";
            let phrase = CString::new(bad).expect("valid");
            assert_eq!(
                phalanx_validate_mnemonic(phrase.as_ptr()),
                PhalanxError::MnemonicParseError.code()
            );
        }
    }

    #[test]
    fn wrong_word_count_returns_mnemonic_parse_error() {
        unsafe {
            let too_short = "abandon abandon abandon";
            let phrase = CString::new(too_short).expect("valid");
            assert_eq!(
                phalanx_validate_mnemonic(phrase.as_ptr()),
                PhalanxError::MnemonicParseError.code()
            );
        }
    }
}
