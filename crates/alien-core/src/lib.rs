//! alien-core: cryptographic engine for AlienMsg.
//!
//! Layers:
//! - `recovery`  : mnemonic -> deterministic identity seed (Argon2id)
//! - `identity`  : long-term Ed25519 + X25519 identity keys
//! - `card`      : signed contact cards carrying one-time hybrid prekeys
//! - `handshake` : PQXDH-style hybrid key agreement (X25519 + ML-KEM-1024)
//! - `ratchet`   : Double Ratchet sessions with forward secrecy
//! - `wire`      : envelope framing/serialization
//! - `message`   : pairwise message encrypt/decrypt
//! - `group`     : sender-key group encryption with member rotation

pub mod card;
pub mod error;
pub mod group;
pub mod handshake;
pub mod identity;
pub mod message;
pub mod ratchet;
pub mod recovery;
pub mod serutil;
pub mod wire;

pub use error::{Error, Result};
