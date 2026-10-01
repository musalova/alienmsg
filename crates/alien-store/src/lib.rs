//! alien-store: encrypted vault file for identity, sessions, groups.
//!
//! File layout: `ALNV || version(1) || salt(16) || nonce(24) || ciphertext`.
//! Key = Argon2id(password, salt). Contents = postcard-serialized
//! `HashMap<String, Vec<u8>>` holding opaque blobs produced by alien-core.
//!
//! `version` doubles as a protection flag, readable without the key:
//! - `1` — unprotected vault: key derived from the empty password
//! - `2` — password-bound vault: key derived from the user password
//!
//! That lets the UI distinguish "wrong/corrupt file" from "password needed"
//! without attempting decryption.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use zeroize::Zeroize;

/// Pluggable byte-level storage behind the vault "file".
/// Native: real files via `std::fs` (atomic write-temp-rename).
/// WASM (browser): `localStorage` entries keyed `alienmsg.fs:<path>` holding
/// base64 blobs — synchronous like `std::fs`, durable across reloads.
#[cfg(not(target_arch = "wasm32"))]
mod backend {
    use std::io;
    use std::path::Path;

    pub fn exists(path: &Path) -> io::Result<bool> {
        match std::fs::metadata(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
            Ok(_) => Ok(true),
        }
    }

    pub fn read(path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    /// Atomic-ish: write temp then rename.
    pub fn write(path: &Path, data: &[u8]) -> io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, path)
    }

    pub fn remove(path: &Path) -> io::Result<()> {
        match std::fs::remove_file(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            r => r,
        }
    }

    pub fn rename(from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }
}

#[cfg(target_arch = "wasm32")]
mod backend {
    use std::io;
    use std::path::Path;
    use wasm_bindgen::JsCast;

    fn ls() -> io::Result<web_sys::Storage> {
        // globalThis.localStorage works both in a real browser window and in
        // host environments (tests, workers) that only define the shim.
        let g = js_sys::global();
        let ls = js_sys::Reflect::get(&g, &wasm_bindgen::JsValue::from_str("localStorage"))
            .map_err(js_err)?;
        if ls.is_null() || ls.is_undefined() {
            return Err(io::Error::new(io::ErrorKind::Other, "no localStorage"));
        }
        Ok(ls.unchecked_into())
    }

    fn key(p: &Path) -> String {
        format!("alienmsg.fs:{}", p.to_string_lossy())
    }

    fn js_err(e: wasm_bindgen::JsValue) -> io::Error {
        io::Error::new(io::ErrorKind::Other, format!("{e:?}"))
    }

    pub fn exists(path: &Path) -> io::Result<bool> {
        Ok(ls()?.get_item(&key(path)).map_err(js_err)?.is_some())
    }

    pub fn read(path: &Path) -> io::Result<Vec<u8>> {
        match ls()?.get_item(&key(path)).map_err(js_err)? {
            None => Err(io::Error::new(io::ErrorKind::NotFound, "not found")),
            Some(s) => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(s)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad b64"))
            }
        }
    }

    /// localStorage setItem is already atomic per key.
    pub fn write(path: &Path, data: &[u8]) -> io::Result<()> {
        use base64::Engine;
        let s = base64::engine::general_purpose::STANDARD.encode(data);
        ls()?.set_item(&key(path), &s).map_err(js_err)
    }

    pub fn remove(path: &Path) -> io::Result<()> {
        ls()?.remove_item(&key(path)).map_err(js_err)
    }

    pub fn rename(from: &Path, to: &Path) -> io::Result<()> {
        let st = ls()?;
        if let Some(v) = st.get_item(&key(from)).map_err(js_err)? {
            st.set_item(&key(to), &v).map_err(js_err)?;
            st.remove_item(&key(from)).map_err(js_err)?;
        }
        Ok(())
    }
}

const MAGIC: &[u8; 4] = b"ALNV";
const VER_PLAIN: u8 = 1;
const VER_PROTECTED: u8 = 2;
const HEADER_LEN: usize = 4 + 1 + 16 + 24; // magic + ver + salt + nonce

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
    #[error("vault requires a password")]
    Locked,
}

/// Metadata readable without unlocking the vault.
pub struct VaultProbe {
    pub exists: bool,
    /// True when the file claims password protection (version 2).
    pub needs_password: bool,
}

/// Inspect a vault path without decrypting it.
pub fn probe(path: &Path) -> Result<VaultProbe, StoreError> {
    if !backend::exists(path)? {
        return Ok(VaultProbe {
            exists: false,
            needs_password: false,
        });
    }
    let raw = backend::read(path)?;
    let valid =
        raw.len() >= 5 && &raw[..4] == MAGIC && (raw[4] == VER_PLAIN || raw[4] == VER_PROTECTED);
    Ok(VaultProbe {
        exists: true,
        // Unknown/corrupt header -> treated as unprotected; decryption will
        // fail and the caller decides it is corrupt, not locked.
        needs_password: valid && raw[4] == VER_PROTECTED,
    })
}

/// Delete a vault blob. Missing is not an error (wipe paths call this
/// unconditionally).
pub fn delete(path: &Path) -> Result<(), StoreError> {
    backend::remove(path)?;
    Ok(())
}

/// Move a vault blob aside (corrupt-file quarantine). Missing source is not
/// an error — there is nothing to quarantine.
pub fn rename(from: &Path, to: &Path) -> Result<(), StoreError> {
    if backend::exists(from)? {
        backend::rename(from, to)?;
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Default)]
struct VaultData {
    map: HashMap<String, Vec<u8>>,
}

pub struct Vault {
    data: VaultData,
    key: [u8; 32],
    salt: [u8; 16],
    protected: bool,
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
    /// Open (or create) a vault file.
    ///
    /// An empty `password` creates/opens a *plain* vault (v1): still AEAD
    /// encrypted at rest, but with a key anyone can derive — it protects the
    /// file format, not the secrets. A non-empty password creates a
    /// *protected* vault (v2) that only that password can open.
    ///
    /// Opening a protected vault with an empty or wrong password returns
    /// [`StoreError::Decrypt`]; use [`probe`] first to tell the cases apart.
    pub fn open(path: &Path, password: &str) -> Result<Vault, StoreError> {
        if backend::exists(path)? {
            let raw = backend::read(path)?;
            if raw.len() < HEADER_LEN + 16 || &raw[..4] != MAGIC {
                return Err(StoreError::Decrypt);
            }
            let ver = raw[4];
            if ver != VER_PLAIN && ver != VER_PROTECTED {
                return Err(StoreError::Decrypt);
            }
            let protected = ver == VER_PROTECTED;
            // v1 vaults are defined as empty-password: a supplied password is
            // ignored rather than silently producing a different key.
            let effective_pw = if protected { password } else { "" };
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&raw[5..21]);
            let nonce: &[u8; 24] = raw[21..45].try_into().unwrap();
            let key = derive_key(effective_pw, &salt)?;
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
            Ok(Vault {
                data,
                key,
                salt,
                protected,
            })
        } else {
            let protected = !password.is_empty();
            let salt: [u8; 16] = rand::random();
            let key = derive_key(password, &salt)?;
            let v = Vault {
                data: VaultData::default(),
                key,
                salt,
                protected,
            };
            v.save(path)?;
            Ok(v)
        }
    }

    /// True when this vault is bound to a password.
    pub fn is_protected(&self) -> bool {
        self.protected
    }

    /// Set or clear (empty string) the vault password. Takes effect on the
    /// next [`Vault::save`]: re-salts and re-keys. When removing protection
    /// the vault becomes v1 (empty-password derivation).
    pub fn set_password(&mut self, password: &str) -> Result<(), StoreError> {
        self.salt = rand::random();
        self.key = derive_key(password, &self.salt)?;
        self.protected = !password.is_empty();
        Ok(())
    }

    /// Persist to `path` (atomic-ish: write temp then rename).
    pub fn save(&self, path: &Path) -> Result<(), StoreError> {
        let pt = postcard::to_allocvec(&self.data).map_err(|_| StoreError::Serde)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key));
        let nonce: [u8; 24] = rand::random();
        let ver = if self.protected {
            VER_PROTECTED
        } else {
            VER_PLAIN
        };
        let header = [&MAGIC[..], &[ver]].concat();
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &pt,
                    aad: &header,
                },
            )
            .map_err(|_| StoreError::Decrypt)?;
        let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        backend::write(path, &out)?;
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
        for v in self.data.map.values_mut() {
            v.zeroize();
        }
    }
}

// --- PIN-wrapped secrets ---------------------------------------------------
//
// A small standalone envelope to protect a secret (the device key) with a
// user PIN: `ALNP || salt(16) || nonce(24) || XChaCha20-Poly1305(secret)`.
// Key = Argon2id(pin, salt) — same derivation strength as the vault itself.
// Wrong PIN = AEAD failure, so verification is cryptographic: nothing needs
// to be stored in plaintext to check the PIN.

const PIN_MAGIC: &[u8; 4] = b"ALNP";

/// Wrap `data` under `pin`. Output is self-contained (salt + nonce inside).
pub fn pin_wrap(pin: &str, data: &[u8]) -> Result<Vec<u8>, StoreError> {
    let salt: [u8; 16] = rand::random();
    let nonce: [u8; 24] = rand::random();
    let key = derive_key(pin, &salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: data,
                aad: PIN_MAGIC,
            },
        )
        .map_err(|_| StoreError::Decrypt)?;
    let mut out = Vec::with_capacity(4 + 16 + 24 + ct.len());
    out.extend_from_slice(PIN_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unwrap a [`pin_wrap`] blob. Wrong PIN or corrupt data → `Err(Decrypt)`.
pub fn pin_unwrap(pin: &str, blob: &[u8]) -> Result<Vec<u8>, StoreError> {
    if blob.len() < 4 + 16 + 24 + 16 || &blob[..4] != PIN_MAGIC {
        return Err(StoreError::Decrypt);
    }
    let salt: &[u8; 16] = blob[4..20].try_into().unwrap();
    let nonce: &[u8; 24] = blob[20..44].try_into().unwrap();
    let key = derive_key(pin, salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: &blob[44..],
                aad: PIN_MAGIC,
            },
        )
        .map_err(|_| StoreError::Decrypt)
}
