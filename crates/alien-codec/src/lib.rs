//! alien-codec: renders ciphertext envelopes for copy/paste transport.
//!
//! - `Blob`  : "AYA1:" + base64url — compact, obviously encoded data.
//! - `Emoji` : 👽 + one emoji per byte — doesn't look like encryption.
//! - `Words` : pseudo-word syllables — resembles nonsense natural language.
//!
//! Stealth formats add *opacity*, not security: the AEAD ciphertext underneath
//! is already indistinguishable from random noise.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Blob,
    Emoji,
    Words,
}

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("unrecognized payload format")]
    Unknown,
    #[error("malformed payload")]
    Malformed,
}

pub const BLOB_PREFIX: &str = "AYA1:";
/// Marker emoji signalling an emoji-encoded AlienMsg payload.
const EMOJI_MARKER: char = '👽';
/// Emoji alphabet: scalars U+1F300..=U+1F3FF (Misc Symbols & Pictographs).
/// All are single Unicode scalars — no ZWJ sequences, no modifiers — so each
/// encodes exactly one byte and survives copy/paste intact.
const EMOJI_BASE: u32 = 0x1F300;

const CONSONANTS: [char; 16] = [
    'b', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'v', 'z',
];
const VOWELS: [&str; 16] = [
    "a", "e", "i", "o", "u", "ai", "au", "ei", "ia", "ie", "io", "oa", "oi", "ua", "ue", "ui",
];

pub fn encode(data: &[u8], format: Format) -> String {
    match format {
        Format::Blob => {
            let mut s = String::with_capacity(BLOB_PREFIX.len() + data.len() * 4 / 3 + 4);
            s.push_str(BLOB_PREFIX);
            s.push_str(&URL_SAFE_NO_PAD.encode(data));
            s
        }
        Format::Emoji => {
            let mut s = String::with_capacity(data.len() * 4 + 4);
            s.push(EMOJI_MARKER);
            for &b in data {
                s.push(char::from_u32(EMOJI_BASE + b as u32).expect("valid scalar"));
            }
            s
        }
        Format::Words => {
            let mut s = String::with_capacity(data.len() * 4);
            for (i, &b) in data.iter().enumerate() {
                if i > 0 {
                    // Space every syllable, period+space every 8 for texture.
                    if i % 8 == 0 {
                        s.push_str(". ");
                    } else {
                        s.push(' ');
                    }
                }
                s.push(CONSONANTS[(b >> 4) as usize]);
                s.push_str(VOWELS[(b & 0x0F) as usize]);
            }
            s
        }
    }
}

/// Auto-detect the format and decode back to the envelope bytes.
pub fn decode(input: &str) -> Result<Vec<u8>, CodecError> {
    let trimmed = input.trim();
    if let Some(rest) = trimmed.strip_prefix(BLOB_PREFIX) {
        return URL_SAFE_NO_PAD
            .decode(rest.trim())
            .map_err(|_| CodecError::Malformed);
    }
    if trimmed.starts_with(EMOJI_MARKER) {
        return decode_emoji(trimmed);
    }
    decode_words(trimmed)
}

fn decode_emoji(s: &str) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    let mut seen_marker = false;
    for ch in s.chars() {
        if !seen_marker {
            if ch == EMOJI_MARKER {
                seen_marker = true;
            }
            continue;
        }
        let cp = ch as u32;
        if (EMOJI_BASE..EMOJI_BASE + 256).contains(&cp) {
            out.push((cp - EMOJI_BASE) as u8);
        } else if ch.is_whitespace() {
            continue; // tolerate whitespace injected by carriers
        } else {
            return Err(CodecError::Malformed);
        }
    }
    if out.is_empty() {
        return Err(CodecError::Malformed);
    }
    Ok(out)
}

fn decode_words(s: &str) -> Result<Vec<u8>, CodecError> {
    let letters: Vec<char> = s
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if letters.is_empty() {
        return Err(CodecError::Unknown);
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < letters.len() {
        let ci = CONSONANTS
            .iter()
            .position(|&c| c == letters[i])
            .ok_or(CodecError::Malformed)?;
        i += 1;
        // consume vowel letters until next consonant
        let start = i;
        while i < letters.len() && !CONSONANTS.contains(&letters[i]) {
            i += 1;
        }
        let vowel: String = letters[start..i].iter().collect();
        let vi = VOWELS
            .iter()
            .position(|&v| v == vowel)
            .ok_or(CodecError::Malformed)?;
        out.push(((ci << 4) | vi) as u8);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        (0u8..=255).collect()
    }

    #[test]
    fn blob_roundtrip() {
        let d = sample();
        assert_eq!(decode(&encode(&d, Format::Blob)).unwrap(), d);
    }

    #[test]
    fn emoji_roundtrip() {
        let d = sample();
        assert_eq!(decode(&encode(&d, Format::Emoji)).unwrap(), d);
    }

    #[test]
    fn words_roundtrip() {
        let d = sample();
        assert_eq!(decode(&encode(&d, Format::Words)).unwrap(), d);
    }

    #[test]
    fn words_with_noise_punctuation() {
        let d = vec![0x12, 0xAB, 0x00, 0xFF];
        let enc = encode(&d, Format::Words);
        let noisy = enc.replace(' ', "  ,  ");
        assert_eq!(decode(&noisy).unwrap(), d);
    }
}
