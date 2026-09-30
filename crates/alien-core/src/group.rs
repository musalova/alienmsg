//! Group encryption: shared group key `K_g` per epoch + per-sender HKDF
//! chains (sender-key scheme). Membership changes rotate `K_g`; departed
//! members keep only old epochs and cannot read new traffic.

use crate::error::{Error, Result};
use crate::ratchet::{aead_open, aead_seal};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const MAX_GROUP_SKIP: u32 = 400;
const MAX_GROUP_SKIPPED: usize = 500;

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
#[derive(Serialize, Deserialize)]
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
}

fn sender_ck(k_g: &[u8; 32], sender: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"AlienMsg/GroupSend/v1"), k_g);
    let mut info = Vec::with_capacity(32);
    info.extend_from_slice(sender);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).expect("hkdf expand");
    out
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
            version: 1,
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
            version: 1,
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
        }
    }

    /// Rotate to a new epoch with a fresh key (after membership change).
    /// Returns the new key material; caller wraps it for remaining members.
    pub fn rotate(&mut self, new_members: Vec<[u8; 32]>) -> [u8; 32] {
        self.old_keys.push((self.epoch, self.k_g));
        if self.old_keys.len() > 8 {
            self.old_keys.remove(0);
        }
        self.epoch += 1;
        self.k_g = rand::random();
        self.members = new_members;
        self.send_ck = sender_ck(&self.k_g, &self.my_id);
        self.send_n = 0;
        self.recv.clear();
        self.k_g
    }

    /// Apply a rotation received from the admin.
    pub fn apply_rotate(&mut self, epoch: u64, k_g: [u8; 32], members: Vec<[u8; 32]>) -> Result<()> {
        if epoch <= self.epoch {
            return Err(Error::Group("stale rotation epoch"));
        }
        self.old_keys.push((self.epoch, self.k_g));
        if self.old_keys.len() > 8 {
            self.old_keys.remove(0);
        }
        self.epoch = epoch;
        self.k_g = k_g;
        self.members = members;
        self.send_ck = sender_ck(&self.k_g, &self.my_id);
        self.send_n = 0;
        self.recv.clear();
        Ok(())
    }

    /// Encrypt `pt` for the whole group. `ad` = framing bytes.
    pub fn encrypt(&mut self, ad: &[u8], pt: &[u8]) -> (u32, [u8; 24], Vec<u8>) {
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
        (n, nonce, ct)
    }

    /// Decrypt a group message from `sender` at chain index `n`.
    pub fn decrypt(
        &mut self,
        ad: &[u8],
        epoch: u64,
        sender: &[u8; 32],
        n: u32,
        nonce: &[u8; 24],
        ct: &[u8],
    ) -> Result<Vec<u8>> {
        // Resolve key material for the message's epoch.
        let (k_g, fresh_chain) = if epoch == self.epoch {
            (self.k_g, false)
        } else if let Some((_, k)) = self.old_keys.iter().find(|(e, _)| *e == epoch) {
            (*k, true)
        } else {
            return Err(Error::Group("unknown epoch"));
        };

        let mut full_ad = Vec::with_capacity(ad.len() + 24 + 8 + 4);
        full_ad.extend_from_slice(ad);
        full_ad.extend_from_slice(&self.group_id);
        full_ad.extend_from_slice(&epoch.to_be_bytes());
        full_ad.extend_from_slice(sender);
        full_ad.extend_from_slice(&n.to_be_bytes());

        if fresh_chain {
            // Old-epoch message: derive a throwaway chain, advance to n.
            let mut ck = sender_ck(&k_g, sender);
            let mut i = 0u32;
            while i < n {
                if n - i > MAX_GROUP_SKIP {
                    return Err(Error::Group("too many skipped messages"));
                }
                let (next, _) = kdf_gck(&ck);
                ck = next;
                i += 1;
            }
            let (_, mk) = kdf_gck(&ck);
            return aead_open(&mk, nonce, &full_ad, ct);
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

        if let Some(pos) = chain.skipped.iter().position(|(sn, _)| *sn == n) {
            let (_, mk) = chain.skipped.remove(pos);
            return aead_open(&mk, nonce, &full_ad, ct);
        }
        if n < chain.n {
            return Err(Error::Group("replayed group message"));
        }
        if n - chain.n > MAX_GROUP_SKIP {
            return Err(Error::Group("too many skipped messages"));
        }
        while chain.n < n {
            if chain.skipped.len() >= MAX_GROUP_SKIPPED {
                return Err(Error::Group("skipped store full"));
            }
            let (next, mk) = kdf_gck(&chain.ck);
            chain.ck = next;
            chain.skipped.push((chain.n, mk));
            chain.n += 1;
        }
        let (next, mk) = kdf_gck(&chain.ck);
        chain.ck = next;
        chain.n += 1;
        aead_open(&mk, nonce, &full_ad, ct)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|_| Error::Serde)
    }
    pub fn from_bytes(b: &[u8]) -> Result<GroupState> {
        postcard::from_bytes(b).map_err(|_| Error::Serde)
    }
}
