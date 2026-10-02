//! alien-codec: renders ciphertext envelopes for copy/paste transport.
//!
//! - `Blob`  : "AYA1:" + base64url — compact, obviously encoded data.
//! - `Emoji` : 👽 + one emoji per byte — doesn't look like encryption.
//! - `Words` : pseudo-word syllables — resembles nonsense natural language.
//! - `Frasi` : grammatical Italian cover sentences, unrelated to the message.
//!
//! Stealth formats add *opacity*, not security: the AEAD ciphertext underneath
//! is already indistinguishable from random noise.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

mod sentences;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Blob,
    Emoji,
    Words,
    Frasi,
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
/// Emoji alphabet, 256 standalone scalars:
///   bytes 0x00..=0x7F -> U+1F300..=U+1F37F (Misc Symbols)
///   bytes 0x80..=0xFF -> U+1F400..=U+1F47F (Animals & Nature)
/// The range U+1F3FB..=U+1F3FF is deliberately excluded: those are Fitzpatrick
/// skin-tone *modifiers*, which renderers merge with the preceding emoji and
/// carriers may normalize away — corrupting the payload.
const EMOJI_BASE_A: u32 = 0x1F300;
const EMOJI_BASE_B: u32 = 0x1F400;

fn emoji_of(b: u8) -> char {
    let cp = if b < 0x80 {
        EMOJI_BASE_A + b as u32
    } else {
        EMOJI_BASE_B + (b as u32 - 0x80)
    };
    char::from_u32(cp).expect("valid scalar")
}

fn byte_of(cp: u32) -> Option<u8> {
    if (EMOJI_BASE_A..EMOJI_BASE_A + 0x80).contains(&cp) {
        Some((cp - EMOJI_BASE_A) as u8)
    } else if (EMOJI_BASE_B..EMOJI_BASE_B + 0x80).contains(&cp) {
        Some((cp - EMOJI_BASE_B + 0x80) as u8)
    } else {
        None
    }
}

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
                s.push(emoji_of(b));
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
        Format::Frasi => sentences::encode(data),
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
    // Tolerate leading text before the marker (chat apps often prepend quotes,
    // sender names, etc.) — decode_emoji skips everything up to it.
    if trimmed.contains(EMOJI_MARKER) {
        return decode_emoji(trimmed);
    }
    // Frasi first: its decoder is strict (every word must resolve to a
    // dictionary slot or a carrier), while a pseudo-words payload almost
    // never does. A words payload conversely starts with a consonant+
    // vowel pair that fails the frasi dictionary lookup.
    if let Ok(bytes) = sentences::decode(trimmed) {
        return Ok(bytes);
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
        if let Some(b) = byte_of(cp) {
            out.push(b);
        } else if ch.is_whitespace()
            || cp == 0xFE0F            // emoji variation selector
            || cp == 0x200D            // ZWJ
            || (0x1F3FB..=0x1F3FF).contains(&cp)
        // stray skin-tone modifiers
        {
            continue; // tolerate decorations injected by carriers
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
    fn frasi_roundtrip() {
        let d = sample();
        let enc = encode(&d, Format::Frasi);
        assert_eq!(decode(&enc).unwrap(), d);
    }

    #[test]
    fn frasi_output_is_italian_prose() {
        let enc = encode(b"hello world", Format::Frasi);
        // no blob prefix, no emoji marker; looks like sentences
        assert!(!enc.contains(BLOB_PREFIX));
        assert!(!enc.contains(EMOJI_MARKER));
        assert!(enc.ends_with('.'));
        assert!(enc.chars().all(|c| c.is_alphabetic() || c.is_whitespace() || ".'’".contains(c)));
    }

    #[test]
    fn frasi_mutation_is_rejected() {
        let d = vec![0x12, 0xAB, 0x00, 0xFF, 0x77];
        let enc = encode(&d, Format::Frasi);
        // a token not in the dictionary fails the whole decode
        let broken = format!("{enc} xylophone.");
        assert!(decode(&broken).is_err());
    }

    #[test]
    fn words_with_noise_punctuation() {
        let d = vec![0x12, 0xAB, 0x00, 0xFF];
        let enc = encode(&d, Format::Words);
        let noisy = enc.replace(' ', "  ,  ");
        assert_eq!(decode(&noisy).unwrap(), d);
    }

    #[test]
    fn emoji_avoids_modifier_scalars() {
        // Bytes 0xFB..=0xFF must NOT map to the Fitzpatrick modifiers
        // U+1F3FB..=U+1F3FF, which carriers can merge/normalize away.
        for b in 0xFBu8..=0xFF {
            let cp = emoji_of(b) as u32;
            assert!(
                !(0x1F3FB..=0x1F3FF).contains(&cp),
                "byte {b:#x} -> modifier"
            );
        }
        // And every scalar in the alphabet is a standalone emoji.
        for b in 0u8..=255 {
            let cp = emoji_of(b);
            assert!(
                (0x1F300..=0x1F37F).contains(&(cp as u32))
                    || (0x1F400..=0x1F47F).contains(&(cp as u32))
            );
        }
    }

    #[test]
    fn emoji_tolerates_variation_selectors_and_prefix_text() {
        let d = sample();
        let mut enc = encode(&d, Format::Emoji);
        // Carriers may append U+FE0F after emoji scalars, and chat apps may
        // prepend sender/quote text before the marker.
        enc = enc.chars().flat_map(|c| [c, '\u{FE0F}']).collect();
        let noisy = format!("da Marco: {enc}");
        assert_eq!(decode(&noisy).unwrap(), d);
    }
}
