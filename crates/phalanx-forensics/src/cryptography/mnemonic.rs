// crates/phalanx-forensics/src/cryptography/mnemonic.rs
//
// Pure-function BIP-39 mnemonic validation. Laboratory layer — no IO, no
// state. Exists so callers (the FFI Larynx in particular) can validate a
// phrase end-to-end (wordlist + checksum) without pulling in `bip39` as a
// direct dependency or duplicating the algorithm in a sister language.
//
// The system accepts any of the 10 BIP-39 wordlists: `Mnemonic::parse`
// auto-detects language. All 12 words must come from the same wordlist.

use bip39::Mnemonic;
use zeroize::Zeroize;

/// Outcome of validating a BIP-39 mnemonic phrase. Intentionally narrow:
/// the FFI translates `Err(_)` into a single `MnemonicParseError` code.
/// Distinguishing wordlist-violation from checksum-failure is done by the
/// caller's local wordlist lookup before reaching this function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MnemonicValidation {
    /// Phrase parses against one of the 10 BIP-39 wordlists and the
    /// checksum bits match.
    Valid,
    /// Phrase failed to parse: wordlist violation, wrong word count, or
    /// checksum mismatch.
    Invalid,
}

/// Validate a BIP-39 mnemonic phrase. Pure function — no IO, no logging,
/// no observable side effects beyond the returned value. The phrase is
/// zeroized in the local copy after parsing; callers are still
/// responsible for wiping their own buffers.
#[must_use]
pub fn validate_mnemonic(phrase: &str) -> MnemonicValidation {
    let mut owned = phrase.to_string();
    let result = Mnemonic::parse(&owned);
    owned.zeroize();
    match result {
        Ok(_) => MnemonicValidation::Valid,
        Err(_) => MnemonicValidation::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_ENGLISH: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn valid_english_phrase_validates() {
        assert_eq!(validate_mnemonic(VALID_ENGLISH), MnemonicValidation::Valid);
    }

    #[test]
    fn bad_checksum_is_invalid() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert_eq!(validate_mnemonic(bad), MnemonicValidation::Invalid);
    }

    #[test]
    fn out_of_wordlist_is_invalid() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzz";
        assert_eq!(validate_mnemonic(bad), MnemonicValidation::Invalid);
    }

    #[test]
    fn empty_string_is_invalid() {
        assert_eq!(validate_mnemonic(""), MnemonicValidation::Invalid);
    }

    #[test]
    fn wrong_word_count_is_invalid() {
        let short = "abandon abandon abandon";
        assert_eq!(validate_mnemonic(short), MnemonicValidation::Invalid);
    }
}
