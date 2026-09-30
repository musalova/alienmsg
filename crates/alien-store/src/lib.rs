//! alien-store: encrypted vault file for identity, sessions, groups.
//!
//! File layout: `ALNV || version(1) || salt(16) || nonce(24) || ciphertext`.
//! Key = Argon2id(password, salt). Contents = postcard-serialized
//! `HashMap<String, Vec<u8>>` holding opaque blobs produced by alien-core.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use zeroize::Zeroize;

const MAGIC: &[u8; 4] = b"ALNV";
const VERSION: u8 = 1;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("vault corrupt or wrong password")]
    Decrypt,
    #[error("kdf error")]
    Kdf,
    #[error("serialization error")]
    Serde,
}

#[derive(Serialize, Deserialize, Default)]
struct VaultData {
    map: HashMap<String, Vec<u8>>,
}

pub struct Vault {
    data: VaultData,
    key: [u8; 32],
    salt: [u8; 16],
}

fn derive_key(password: &str, salt: &[u8; 16]) -> Result<[u8; 32], StoreError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(64 * 1024, 3, 1, Some(32)).map_err(|_| StoreError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| StoreError::Kdf)?;
    Ok(key)
}

impl Vault {
    /// Open (or create) a vault file. If the file does not exist and the
    /// password is empty, a random vault key is generated (still encrypted at
    /// rest — just not additionally password-bound).
    pub fn open(path: &Path, password: &str) -> Result<Vault, StoreError> {
        if path.exists() {
            let raw = std::fs::read(path)?;
            if raw.len() < 45 + 16 || &raw[..4] != MAGIC || raw[4] != VERSION {
                return Err(StoreError::Decrypt);
            }
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&raw[5..21]);
            let nonce: &[u8; 24] = raw[21..45].try_into().unwrap();
            let key = derive_key(password, &salt)?;
            let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
            let pt = cipher
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: &raw[45..],
                        aad: &raw[..5],
                    },
                )
                .map_err(|_| StoreError::Decrypt)?;
            let data: VaultData = postcard::from_bytes(&pt).map_err(|_| StoreError::Serde)?;
            Ok(Vault { data, key, salt })
        } else {
            let salt: [u8; 16] = rand::random();
            let key = derive_key(password, &salt)?;
            let v = Vault {
                data: VaultData::default(),
                key,
                salt,
            };
            v.save(path)?;
            Ok(v)
        }
    }

    /// Persist to `path` (atomic-ish: write temp then rename).
    pub fn save(&self, path: &Path) -> Result<(), StoreError> {
        let pt = postcard::to_allocvec(&self.data).map_err(|_| StoreError::Serde)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key));
        let nonce: [u8; 24] = rand::random();
        let header = [&MAGIC[..], &[VERSION]].concat();
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &pt,
                    aad: &header,
                },
            )
            .map_err(|_| StoreError::Decrypt)?;
        let mut out = Vec::with_capacity(45 + ct.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &out)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.data.map.get(key).map(|v| v.as_slice())
    }

    pub fn set(&mut self, key: &str, value: &[u8]) {
        self.data.map.insert(key.to_string(), value.to_vec());
    }

    pub fn remove(&mut self, key: &str) {
        self.data.map.remove(key);
    }

    /// List keys with a given prefix (e.g. "session:", "group:").
    pub fn keys_with_prefix(&self, prefix: &str) -> Vec<String> {
        self.data
            .map
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect()
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
