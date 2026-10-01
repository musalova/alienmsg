//! Recovery: mnemonic phrase -> deterministic 32-byte root seed.
//!
//! The mnemonic is the ONLY secret the user must safeguard. It regenerates the
//! long-term identity keys. Session/ratchet state is intentionally NOT
//! recoverable from it, which is what preserves forward secrecy of past
//! messages even if the mnemonic is later compromised.

use crate::error::{Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use bip39::{Language, Mnemonic};

const WORD_COUNT: usize = 24;
const SALT_DOMAIN: &[u8] = b"AlienMsg/recovery/v1";

/// Generate a fresh 24-word Italian mnemonic (BIP-39 checksummed).
pub fn generate_mnemonic() -> Result<String> {
    let m = Mnemonic::generate_in(Language::Italian, WORD_COUNT).map_err(|_| Error::Mnemonic)?;
    Ok(m.to_string())
}

fn parse_phrase(phrase: &str) -> Result<Mnemonic> {
    let p = phrase.trim();
    Mnemonic::parse_in_normalized(Language::Italian, p)
        .or_else(|_| Mnemonic::parse_in_normalized(Language::English, p))
        .map_err(|_| Error::Mnemonic)
}

/// Validate checksum and stretch the phrase into the root identity seed.
/// `passphrase` is an optional extra word ("25th word"); may be empty.
pub fn seed_from_mnemonic(phrase: &str, passphrase: &str) -> Result<[u8; 32]> {
    let m = parse_phrase(phrase)?;

    // Fixed deterministic salt (required so recovery is reproducible).
    // Entropy lives entirely in the 256-bit mnemonic; Argon2id raises the cost
    // of brute-force over weak passphrases.
    use sha2::Digest;
    let entropy = m.to_entropy();
    let mut salt_input = Vec::with_capacity(SALT_DOMAIN.len() + 32);
    salt_input.extend_from_slice(SALT_DOMAIN);
    salt_input.extend_from_slice(&entropy);
    let salt_full = sha2::Sha256::digest(&salt_input);

    let params = Params::new(64 * 1024, 3, 1, Some(32)).map_err(|_| Error::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut pwd = Vec::new();
    pwd.extend_from_slice(&entropy);
    pwd.extend_from_slice(passphrase.as_bytes());

    let mut seed = [0u8; 32];
    argon
        .hash_password_into(&pwd, &salt_full[..16], &mut seed)
        .map_err(|_| Error::Kdf)?;
    for b in pwd.iter_mut() {
        *b = 0;
    }
    Ok(seed)
}

/// True iff the phrase parses and its checksum is valid (Italian or English).
pub fn validate_mnemonic(phrase: &str) -> bool {
    parse_phrase(phrase).is_ok()
}
