//! serde helpers for fixed-size byte arrays beyond serde's built-in 32 limit.
//! Encoded as bytes (compact under postcard), tolerant to seq encoding.

use serde::de::{Error as DeError, SeqAccess, Visitor};
use serde::{Deserializer, Serializer};

pub mod arr64 {
    use super::*;
    use std::fmt;

    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = [u8; 64];
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("64 bytes")
            }
            fn visit_bytes<E: DeError>(self, v: &[u8]) -> Result<[u8; 64], E> {
                v.try_into().map_err(|_| E::custom("expected 64 bytes"))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; 64], A::Error> {
                let mut out = [0u8; 64];
                for (i, b) in out.iter_mut().enumerate() {
                    *b = seq
                        .next_element()?
                        .ok_or_else(|| DeError::custom("short array"))?;
                    let _ = i;
                }
                Ok(out)
            }
        }
        d.deserialize_bytes(V)
    }
}
