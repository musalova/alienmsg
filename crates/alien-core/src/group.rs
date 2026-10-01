//! Group encryption: shared group key `K_g` per epoch + per-sender HKDF
//! chains (sender-key scheme). Membership changes rotate `K_g`; departed
//! members keep only old epochs and cannot read new traffic.
//!
//! Sender-key chains are derivable by every member, so AEAD alone cannot
//! authenticate *which* member sent a message. Every message is therefore
//! Ed25519-signed by the sender's long-term identity key; the signature key
//! self-certifies via `public_id(ed ‖ x) == claimed sender`.

use crate::error::{Error, Result};
use crate::identity::{self, Identity};
use crate::ratchet::{aead_open, aead_seal};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const MAX_GROUP_SKIP: u32 = 400;
const MAX_GROUP_SKIPPED: usize = 500;
const MAX_EXCLUDED: usize = 256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize, Clone)]
pub struct RecvChain {
    pub sender: [u8; 32],
    pub ck: [u8; 32],
    pub n: u32,
    pub skipped: Vec<(u32, [u8; 32])>,
}

/// Serializable group session. All chains derive deterministically from the
/// current epoch key `k_g`, so receivers lazily create sender chains.
///
/// `Clone` enables atomic rotation: `group_rotate` works on a scratch copy
/// and commits only after every member wrap succeeded.
#[derive(Serialize, Deserialize, Clone)]
pub struct GroupState {
    pub version: u8,
    pub group_id: [u8; 16],
    pub epoch: u64,
    pub admin: [u8; 32],
    pub k_g: [u8; 32],
    pub my_id: [u8; 32],
    pub send_ck: [u8; 32],
    pub send_n: u32,
    pub recv: Vec<RecvChain>,
    pub members: Vec<[u8; 32]>,
    pub name: String,
    /// Epochs retained for reading late-arriving old messages (bounded).
    pub old_keys: Vec<(u64, [u8; 32])>,
    /// Members removed by past rotations: they may still hold old-epoch keys
    /// but must not be able to post on them after removal.
    pub excluded: Vec<[u8; 32]>,
}

impl Drop for GroupState {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.k_g.zeroize();
        self.send_ck.zeroize();
        for ch in &mut self.recv {
            ch.ck.zeroize();
            for (_, mk) in &mut ch.skipped {
                mk.zeroize();
            }
        }
        for (_, k) in &mut self.old_keys {
            k.zeroize();
        }
    }
}

fn sender_ck(k_g: &[u8; 32], sender: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"AlienMsg/GroupSend/v1"), k_g);
    let mut info = Vec::with_capacity(32);
    info.extend_from_slice(sender);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).expect("hkdf expand");
    out
}

/// Sender authentication material carried by every group message:
/// the long-term (Ed25519, X25519) public pair — which must hash to the
/// claimed `sender` pub_id — and the signature over the message.
pub struct SenderProof {
    pub ed: [u8; 32],
    pub x: [u8; 32],
    pub sig: [u8; 64],
}

/// Header + authentication + body of an inbound group message.
pub struct InboundMsg<'a> {
    pub epoch: u64,
    /// Claimed sender pub_id (self-certified by `proof`).
    pub sender: &'a [u8; 32],
    pub proof: &'a SenderProof,
    pub n: u32,
    pub nonce: &'a [u8; 24],
    pub ct: &'a [u8],
}

/// Domain-separated payload signed by the sender's identity key.
/// `full_ad` already binds framing, group_id, epoch, sender and n.
fn sig_msg(full_ad: &[u8], nonce: &[u8; 24], ct: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(24 + full_ad.len() + 24 + ct.len());
    v.extend_from_slice(b"AlienMsg/GroupSig/v1");
    v.extend_from_slice(full_ad);
    v.extend_from_slice(nonce);
    v.extend_from_slice(ct);
    v
}

fn kdf_gck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(ck).expect("hmac");
    mac.update(b"gmk");
    let mk: [u8; 32] = mac.finalize().into_bytes().into();
    let mut mac = <HmacSha256 as Mac>::new_from_slice(ck).expect("hmac");
    mac.update(b"gck");
    let ck2: [u8; 32] = mac.finalize().into_bytes().into();
    (ck2, mk)
}

impl GroupState {
    /// Create a new group as admin; sole member = creator.
    pub fn create(my_id: [u8; 32], name: &str) -> GroupState {
        let k_g: [u8; 32] = rand::random();
        let group_id: [u8; 16] = rand::random();
        GroupState {
            version: 2,
            group_id,
            epoch: 1,
            admin: my_id,
            k_g,
            my_id,
            send_ck: sender_ck(&k_g, &my_id),
            send_n: 0,
            recv: Vec::new(),
            members: vec![my_id],
            name: name.to_string(),
            old_keys: Vec::new(),
            excluded: Vec::new(),
        }
    }

    /// Build from an accepted invite/rotation.
    pub fn from_invite(
        group_id: [u8; 16],
        epoch: u64,
        k_g: [u8; 32],
        admin: [u8; 32],
        members: Vec<[u8; 32]>,
        name: &str,
        my_id: [u8; 32],
    ) -> GroupState {
        GroupState {
            version: 2,
            group_id,
            epoch,
            admin,
            k_g,
            my_id,
            send_ck: sender_ck(&k_g, &my_id),
            send_n: 0,
            recv: Vec::new(),
            members,
            name: name.to_string(),
            old_keys: Vec::new(),
            excluded: Vec::new(),
        }
    }

    fn mark_excluded(&mut self, new_members: &[[u8; 32]]) {
        for m in &self.members {
            if !new_members.contains(m) && !self.excluded.contains(m) {
                self.excluded.push(*m);
            }
        }
        while self.excluded.len() > MAX_EXCLUDED {
            self.excluded.remove(0);
        }
    }

    /// Rotate to a new epoch with a fresh key (after membership change).
    /// Returns the new key material; caller wraps it for remaining members.
    pub fn rotate(&mut self, new_members: Vec<[u8; 32]>) -> [u8; 32] {
        self.old_keys.push((self.epoch, self.k_g));
        if self.old_keys.len() > 8 {
            self.old_keys.remove(0);
        }
        self.mark_excluded(&new_members);
        self.epoch += 1;
        self.k_g = rand::random();
        self.members = new_members;
        self.send_ck = sender_ck(&self.k_g, &self.my_id);
        self.send_n = 0;
        self.recv.clear();
        self.k_g
    }

    /// Apply a rotation received from the admin. `name` refreshes the
    /// display name when the admin carries a new one (empty = keep).
    pub fn apply_rotate(
        &mut self,
        epoch: u64,
        k_g: [u8; 32],
        members: Vec<[u8; 32]>,
        name: &str,
    ) -> Result<()> {
        if epoch <= self.epoch {
            return Err(Error::Group("stale rotation epoch"));
        }
        self.old_keys.push((self.epoch, self.k_g));
        if self.old_keys.len() > 8 {
            self.old_keys.remove(0);
        }
        self.mark_excluded(&members);
        self.epoch = epoch;
        self.k_g = k_g;
        self.members = members;
        if !name.is_empty() {
            self.name = name.to_string();
        }
        self.send_ck = sender_ck(&self.k_g, &self.my_id);
        self.send_n = 0;
        self.recv.clear();
        Ok(())
    }

    /// Encrypt `pt` for the whole group, signed with `me`'s identity key.
    /// `ad` = framing bytes. Returns (n, nonce, ct, signature).
    pub fn encrypt(
        &mut self,
        me: &Identity,
        ad: &[u8],
        pt: &[u8],
    ) -> (u32, [u8; 24], Vec<u8>, [u8; 64]) {
        let (new_ck, mk) = kdf_gck(&self.send_ck);
        self.send_ck = new_ck;
        let n = self.send_n;
        self.send_n += 1;
        let mut full_ad = Vec::with_capacity(ad.len() + 24 + 8 + 4);
        full_ad.extend_from_slice(ad);
        full_ad.extend_from_slice(&self.group_id);
        full_ad.extend_from_slice(&self.epoch.to_be_bytes());
        full_ad.extend_from_slice(&self.my_id);
        full_ad.extend_from_slice(&n.to_be_bytes());
        let (nonce, ct) = aead_seal(&mk, &full_ad, pt);
        let sig = me.sign(&sig_msg(&full_ad, &nonce, &ct));
        (n, nonce, ct, sig)
    }

    /// Decrypt a group message described by `msg` (epoch, sender, proof, n,
    /// nonce, ciphertext). The sender is authenticated before any state
    /// mutation: the proof key pair must self-certify `sender` (hash ==
    /// pub_id) and sign this exact message.
    pub fn decrypt(&mut self, ad: &[u8], msg: &InboundMsg<'_>) -> Result<Vec<u8>> {
        let sender = msg.sender;
        let n = msg.n;
        // Resolve key material for the message's epoch.
        let (k_g, fresh_chain) = if msg.epoch == self.epoch {
            (self.k_g, false)
        } else if let Some((_, k)) = self.old_keys.iter().find(|(e, _)| *e == msg.epoch) {
            (*k, true)
        } else {
            return Err(Error::Group("unknown epoch"));
        };

        let mut full_ad = Vec::with_capacity(ad.len() + 24 + 8 + 4);
        full_ad.extend_from_slice(ad);
        full_ad.extend_from_slice(&self.group_id);
        full_ad.extend_from_slice(&msg.epoch.to_be_bytes());
        full_ad.extend_from_slice(sender);
        full_ad.extend_from_slice(&n.to_be_bytes());

        // Sender authentication (before any state mutation):
        // the (ed, x) pair must hash to the claimed pub_id, and the signature
        // must cover framing, indices, nonce and ciphertext.
        if identity::public_id_of(&msg.proof.ed, &msg.proof.x) != *sender {
            return Err(Error::Group("sender identity does not match keys"));
        }
        if !identity::verify(
            &msg.proof.ed,
            &sig_msg(&full_ad, msg.nonce, msg.ct),
            &msg.proof.sig,
        ) {
            return Err(Error::Group("bad sender signature"));
        }
        if fresh_chain {
            // Removed members still hold old-epoch keys but may not post.
            if self.excluded.contains(sender) {
                return Err(Error::Group("sender was removed from the group"));
            }
        } else if !self.members.contains(sender) {
            return Err(Error::Group("sender is not a member"));
        }

        if fresh_chain {
            // Old-epoch message: derive a throwaway chain, advance to n.
            if n > MAX_GROUP_SKIP {
                return Err(Error::Group("too many skipped messages"));
            }
            let mut ck = sender_ck(&k_g, sender);
            for _ in 0..n {
                let (next, _) = kdf_gck(&ck);
                ck = next;
            }
            let (_, mk) = kdf_gck(&ck);
            return aead_open(&mk, msg.nonce, &full_ad, msg.ct);
        }

        // Current epoch: persistent per-sender chain with skipped-key store.
        if !self.recv.iter().any(|c| &c.sender == sender) {
            self.recv.push(RecvChain {
                sender: *sender,
                ck: sender_ck(&self.k_g, sender),
                n: 0,
                skipped: Vec::new(),
            });
        }
        let chain = self.recv.iter_mut().find(|c| &c.sender == sender).unwrap();

        // Remove a skipped key only after it successfully decrypts, so a
        // tampered copy cannot burn it.
        if let Some(pos) = chain.skipped.iter().position(|(sn, _)| *sn == n) {
            let mk = chain.skipped[pos].1;
            let pt = aead_open(&mk, msg.nonce, &full_ad, msg.ct)?;
            chain.skipped.remove(pos);
            return Ok(pt);
        }
        if n < chain.n {
            return Err(Error::Group("replayed group message"));
        }
        if n - chain.n > MAX_GROUP_SKIP {
            return Err(Error::Group("too many skipped messages"));
        }
        if chain.skipped.len() + (n - chain.n) as usize > MAX_GROUP_SKIPPED {
            return Err(Error::Group("skipped store full"));
        }
        while chain.n < n {
            let (next, mk) = kdf_gck(&chain.ck);
            chain.ck = next;
            chain.skipped.push((chain.n, mk));
            chain.n += 1;
        }
        // Commit the chain advance only on successful decrypt.
        let (next, mk) = kdf_gck(&chain.ck);
        let pt = aead_open(&mk, msg.nonce, &full_ad, msg.ct)?;
        chain.ck = next;
        chain.n += 1;
        Ok(pt)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|_| Error::Serde)
    }
    pub fn from_bytes(b: &[u8]) -> Result<GroupState> {
        postcard::from_bytes(b).map_err(|_| Error::Serde)
    }
}
