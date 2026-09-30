//! Long-term identity: Ed25519 signing key + X25519 identity key, both
//! deterministically derived from the recovery seed via HKDF domain separation.

use crate::error::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct Identity {
    ed: SigningKey,
    x: StaticSecret,
    pub_id: [u8; 32],
}

impl Identity {
    pub fn from_seed(seed: &[u8; 32]) -> Result<Identity> {
        let ed_seed = expand(seed, b"alienmsg/identity/ed25519/v1")?;
        let x_seed = expand(seed, b"alienmsg/identity/x25519/v1")?;
        let ed = SigningKey::from_bytes(&ed_seed);
        let x = StaticSecret::from(x_seed);
        let mut h = Sha256::new();
        h.update(b"alienmsg/pubid/v1");
        h.update(ed.verifying_key().as_bytes());
        h.update(PublicKey::from(&x).as_bytes());
        let pub_id: [u8; 32] = h.finalize().into();
        Ok(Identity { ed, x, pub_id })
    }

    /// Stable public identifier (fingerprint root), safe to share.
    pub fn public_id(&self) -> [u8; 32] {
        self.pub_id
    }

    pub fn ed_public(&self) -> [u8; 32] {
        *self.ed.verifying_key().as_bytes()
    }

    pub fn x_public(&self) -> [u8; 32] {
        *PublicKey::from(&self.x).as_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.ed.sign(msg).to_bytes()
    }

    pub fn dh(&self, peer_x_pub: &[u8; 32]) -> [u8; 32] {
        self.x.diffie_hellman(&PublicKey::from(*peer_x_pub)).to_bytes()
    }

    pub fn x_secret_bytes(&self) -> [u8; 32] {
        self.x.to_bytes()
    }
}

/// Verify a detached Ed25519 signature.
pub fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    vk.verify(msg, &Signature::from_bytes(sig)).is_ok()
}

fn expand(seed: &[u8; 32], info: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(b"alienmsg/identity"), seed);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).map_err(|_| crate::Error::Kdf)?;
    Ok(out)
}
