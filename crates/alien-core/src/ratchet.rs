//! Double Ratchet (Signal-style): symmetric HKDF chains per direction +
//! X25519 DH ratchet on every reply. Each message key is used once and erased,
//! giving forward secrecy and break-in recovery for past traffic.

use crate::error::{Error, Result};
use crate::handshake::PendingInit;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

const MAX_SKIP_PER_CALL: u32 = 400;
const MAX_SKIPPED_TOTAL: usize = 2000;

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize, Clone)]
pub struct MsgHeader {
    /// Sender's current DH ratchet public key.
    pub dh: [u8; 32],
    /// Message number within the sending chain.
    pub n: u32,
    /// Length of the sender's previous sending chain.
    pub pn: u32,
    /// Session identifier = truncated hash of the shared root key.
    pub session_id: [u8; 16],
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SkippedKey {
    pub dh: [u8; 32],
    pub n: u32,
    pub mk: [u8; 32],
}

/// A pairwise Double Ratchet session. Serializable: secrets are raw scalars,
/// the whole blob lives inside the encrypted vault.
///
/// `Clone` is required by the forge-resistant decrypt path: a DH ratchet step
/// is performed on a scratch copy and committed only after AEAD success.
#[derive(Serialize, Deserialize, Clone)]
pub struct SessionState {
    pub version: u8,
    pub rk: [u8; 32],
    pub my_ratchet_secret: [u8; 32],
    pub send_ck: Option<[u8; 32]>,
    pub send_n: u32,
    pub recv_ck: Option<[u8; 32]>,
    pub recv_n: u32,
    pub remote_ratchet_pub: Option<[u8; 32]>,
    /// Length of our previous sending chain (sent in headers as `pn`).
    pub pn: u32,
    /// Message count of the remote's previous sending chain (from its headers).
    pub remote_pn: u32,
    pub skipped: Vec<SkippedKey>,
    pub session_id: [u8; 16],
    pub peer_id: [u8; 32],
    pub peer_ed: [u8; 32],
    pub peer_name: String,
    pub my_id: [u8; 32],
    pub initiator: bool,
    pub confirmed: bool,
    /// Present only until the first message is sent (initiator side).
    pub pending_init: Option<PendingInit>,
    /// Unix timestamp of creation (informational).
    pub created: u64,
}

impl Drop for SessionState {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.rk.zeroize();
        self.my_ratchet_secret.zeroize();
        self.send_ck.zeroize();
        self.recv_ck.zeroize();
        for s in &mut self.skipped {
            s.mk.zeroize();
        }
    }
}

fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let hk = Hkdf::<Sha256>::new(Some(rk), dh_out);
    let mut okm = [0u8; 64];
    hk.expand(b"AlienMsg/RatchetRoot/v1", &mut okm)
        .map_err(|_| Error::Kdf)?;
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&okm[..32]);
    b.copy_from_slice(&okm[32..]);
    Ok((a, b))
}

fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(ck).expect("hmac key");
    mac.update(&[0x01]);
    let mk: [u8; 32] = mac.finalize().into_bytes().into();
    let mut mac = <HmacSha256 as Mac>::new_from_slice(ck).expect("hmac key");
    mac.update(&[0x02]);
    let ck2: [u8; 32] = mac.finalize().into_bytes().into();
    (ck2, mk)
}

/// Derive the session id both peers compute from the handshake root key.
pub fn session_id_from_root(rk: &[u8; 32]) -> [u8; 16] {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(b"alienmsg/session-id/v1");
    h.update(rk);
    let d = h.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&d[..16]);
    id
}

pub fn aead_open(mk: &[u8; 32], nonce: &[u8; 24], ad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(mk));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: ad })
        .map_err(|_| Error::Decrypt)
}

pub fn aead_seal(mk: &[u8; 32], ad: &[u8], pt: &[u8]) -> ([u8; 24], Vec<u8>) {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(mk));
    let nonce_bytes: [u8; 24] = rand::random();
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload { msg: pt, aad: ad },
        )
        .expect("aead encrypt");
    (nonce_bytes, ct)
}

impl SessionState {
    /// Initializer ("Alice"): root key from handshake, remote ratchet key =
    /// responder's signed prekey.
    pub fn init_alice(
        root: [u8; 32],
        remote_ratchet_pub: [u8; 32],
        my_id: [u8; 32],
        peer_id: [u8; 32],
        peer_ed: [u8; 32],
        pending: PendingInit,
    ) -> Result<SessionState> {
        let my_ratchet = StaticSecret::random_from_rng(OsRng);
        let dh = my_ratchet
            .diffie_hellman(&PublicKey::from(remote_ratchet_pub))
            .to_bytes();
        let (rk, send_ck) = kdf_rk(&root, &dh)?;
        Ok(SessionState {
            version: 1,
            rk,
            my_ratchet_secret: my_ratchet.to_bytes(),
            send_ck: Some(send_ck),
            send_n: 0,
            recv_ck: None,
            recv_n: 0,
            remote_ratchet_pub: Some(remote_ratchet_pub),
            pn: 0,
            remote_pn: 0,
            skipped: Vec::new(),
            session_id: session_id_from_root(&root),
            peer_id,
            peer_ed,
            peer_name: String::new(),
            my_id,
            initiator: true,
            confirmed: false,
            pending_init: Some(pending),
            created: now_unix(),
        })
    }

    /// Responder ("Bob"): initial ratchet key = own signed prekey; the first
    /// incoming header triggers the DH ratchet step.
    pub fn init_bob(
        root: [u8; 32],
        my_spk_secret: [u8; 32],
        my_id: [u8; 32],
        peer_id: [u8; 32],
        peer_ed: [u8; 32],
    ) -> SessionState {
        SessionState {
            version: 1,
            rk: root,
            my_ratchet_secret: my_spk_secret,
            send_ck: None,
            send_n: 0,
            recv_ck: None,
            recv_n: 0,
            remote_ratchet_pub: None,
            pn: 0,
            remote_pn: 0,
            skipped: Vec::new(),
            session_id: session_id_from_root(&root),
            peer_id,
            peer_ed,
            peer_name: String::new(),
            my_id,
            initiator: false,
            confirmed: true,
            pending_init: None,
            created: now_unix(),
        }
    }

    fn my_ratchet_pub(&self) -> [u8; 32] {
        let sk = StaticSecret::from(self.my_ratchet_secret);
        *PublicKey::from(&sk).as_bytes()
    }

    fn store_skipped(&mut self, remote_dh: [u8; 32], until: u32) -> Result<()> {
        let Some(mut ck) = self.recv_ck else {
            return Ok(());
        };
        if until <= self.recv_n {
            return Ok(());
        }
        if until - self.recv_n > MAX_SKIP_PER_CALL {
            return Err(Error::Ratchet("too many skipped messages"));
        }
        // Pre-check capacity so the update below is atomic: a failure mid-loop
        // would advance recv_n without committing recv_ck, corrupting the chain.
        if self.skipped.len() + (until - self.recv_n) as usize > MAX_SKIPPED_TOTAL {
            return Err(Error::Ratchet("skipped-key store full"));
        }
        while self.recv_n < until {
            let (next, mk) = kdf_ck(&ck);
            ck = next;
            self.skipped.push(SkippedKey {
                dh: remote_dh,
                n: self.recv_n,
                mk,
            });
            self.recv_n += 1;
        }
        self.recv_ck = Some(ck);
        Ok(())
    }

    /// A new remote ratchet key arrived: finish the old receive chain (using
    /// `remote_pn` = advertised length of the remote's previous chain), then
    /// move both directions forward.
    fn dh_ratchet_step(&mut self, new_remote: [u8; 32], remote_pn: u32) -> Result<()> {
        if let Some(remote) = self.remote_ratchet_pub {
            self.store_skipped(remote, remote_pn)?;
        }
        let my = StaticSecret::from(self.my_ratchet_secret);
        let dh = my.diffie_hellman(&PublicKey::from(new_remote)).to_bytes();
        let (rk, recv_ck) = kdf_rk(&self.rk, &dh)?;
        self.rk = rk;
        self.recv_ck = Some(recv_ck);
        self.recv_n = 0;
        self.remote_ratchet_pub = Some(new_remote);
        self.remote_pn = remote_pn;

        let fresh = StaticSecret::random_from_rng(OsRng);
        let dh2 = fresh
            .diffie_hellman(&PublicKey::from(new_remote))
            .to_bytes();
        let (rk2, send_ck) = kdf_rk(&self.rk, &dh2)?;
        self.rk = rk2;
        self.pn = self.send_n;
        self.send_ck = Some(send_ck);
        self.send_n = 0;
        self.my_ratchet_secret = fresh.to_bytes();
        Ok(())
    }

    /// Encrypt `pt`; `ad` is authenticated context (envelope framing bytes).
    /// Returns the header to transmit plus nonce and ciphertext.
    pub fn encrypt(&mut self, ad: &[u8], pt: &[u8]) -> Result<(MsgHeader, [u8; 24], Vec<u8>)> {
        let ck = self.send_ck.ok_or(Error::Ratchet("no sending chain yet"))?;
        let (new_ck, mk) = kdf_ck(&ck);
        self.send_ck = Some(new_ck);
        let header = MsgHeader {
            dh: self.my_ratchet_pub(),
            n: self.send_n,
            pn: self.pn,
            session_id: self.session_id,
        };
        self.send_n += 1;
        let header_bytes = postcard::to_allocvec(&header).map_err(|_| Error::Serde)?;
        let mut full_ad = Vec::with_capacity(ad.len() + header_bytes.len());
        full_ad.extend_from_slice(ad);
        full_ad.extend_from_slice(&header_bytes);
        let (nonce, ct) = aead_seal(&mk, &full_ad, pt);
        Ok((header, nonce, ct))
    }

    /// Decrypt one message. Handles in-order, out-of-order (skipped store) and
    /// DH ratchet steps. `ad` = same envelope framing bytes used by the sender.
    pub fn decrypt(
        &mut self,
        ad: &[u8],
        header: &MsgHeader,
        nonce: &[u8; 24],
        ct: &[u8],
    ) -> Result<Vec<u8>> {
        if header.session_id != self.session_id {
            return Err(Error::Ratchet("wrong session"));
        }
        let header_bytes = postcard::to_allocvec(header).map_err(|_| Error::Serde)?;
        let mut full_ad = Vec::with_capacity(ad.len() + header_bytes.len());
        full_ad.extend_from_slice(ad);
        full_ad.extend_from_slice(&header_bytes);

        // Skipped-key path: remove the stored key only *after* a successful
        // decrypt. Otherwise a tampered in-transit message would burn the key
        // and make the legit re-delivery permanently undecryptable.
        if let Some(pos) = self
            .skipped
            .iter()
            .position(|s| s.dh == header.dh && s.n == header.n)
        {
            let pt = aead_open(&self.skipped[pos].mk, nonce, &full_ad, ct)?;
            self.skipped.remove(pos);
            return Ok(pt);
        }

        if self.remote_ratchet_pub != Some(header.dh) {
            // A new remote ratchet key mixes the received DH into the root
            // key. If we committed the step before authenticating the message,
            // one forged header would permanently desynchronize `rk` between
            // the peers (each subsequent step derives from the diverged root)
            // — a single malicious packet would kill the session forever.
            // So the step runs on a scratch copy and is committed only after
            // a successful AEAD open on the new chain.
            let mut next = self.clone();
            next.dh_ratchet_step(header.dh, header.pn)?;
            let pt = next.decrypt_on_current_chain(&full_ad, header, nonce, ct)?;
            *self = next;
            return Ok(pt);
        }

        self.decrypt_on_current_chain(&full_ad, header, nonce, ct)
    }

    /// Decrypt on the *current* receiving chain (no DH ratchet step).
    /// Commits the chain advance only after a successful AEAD open.
    fn decrypt_on_current_chain(
        &mut self,
        full_ad: &[u8],
        header: &MsgHeader,
        nonce: &[u8; 24],
        ct: &[u8],
    ) -> Result<Vec<u8>> {
        if header.n < self.recv_n {
            return Err(Error::Ratchet("replayed or duplicated message"));
        }
        self.store_skipped(header.dh, header.n)?;
        // derive mk at index n; commit the chain advance only if AEAD succeeds,
        // so a tampered message does not destroy the slot forever.
        let ck = self.recv_ck.ok_or(Error::Ratchet("no receiving chain"))?;
        let (next_ck, mk) = kdf_ck(&ck);
        let pt = aead_open(&mk, nonce, full_ad, ct)?;
        self.recv_ck = Some(next_ck);
        self.recv_n = header.n + 1;
        Ok(pt)
    }

    /// Serialize the session (opaque blob for the vault / FFI).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|_| Error::Serde)
    }

    pub fn from_bytes(b: &[u8]) -> Result<SessionState> {
        postcard::from_bytes(b).map_err(|_| Error::Serde)
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(target_arch = "wasm32")]
fn now_unix() -> u64 {
    // wasm32-unknown-unknown has no std clock; use the JS Date via wasm-bindgen.
    (js_sys::Date::now() / 1000.0) as u64
}
