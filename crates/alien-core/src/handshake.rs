//! Hybrid key agreement, PQXDH-style: classical X25519 triple-DH combined with
//! an ML-KEM-1024 encapsulation against the responder's signed post-quantum
//! prekey. The resulting root key seeds the Double Ratchet. The shared secret
//! is bound to both long-term identity ids, preventing unknown-key-share.

use crate::card::{CardBundle, ContactCard};
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::ratchet::SessionState;
use hkdf::Hkdf;
use kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, MlKem1024};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// Initiator data carried inside the first PairInit envelope so the responder
/// can derive the same root key and identify the sender.
#[derive(Serialize, Deserialize, Clone)]
pub struct PendingInit {
    /// Initiator's ephemeral X25519 public key.
    pub eph: [u8; 32],
    /// ML-KEM-1024 ciphertext to the responder's pq prekey.
    pub pq_ct: Vec<u8>,
    /// card_id of the *responder* card that was targeted.
    pub recipient_card_id: [u8; 16],
    /// Initiator's own contact card (authenticates identity + prekeys).
    pub card: ContactCard,
}

fn mix_root(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    ss_pq: &[u8],
    id_a: &[u8; 32],
    id_b: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut ikm = Vec::with_capacity(96 + ss_pq.len());
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    ikm.extend_from_slice(ss_pq);
    let hk = Hkdf::<Sha256>::new(Some(b"AlienMsg/PQXDH/v1"), &ikm);
    let (lo, hi) = if id_a < id_b { (id_a, id_b) } else { (id_b, id_a) };
    let mut info = Vec::with_capacity(64 + 32);
    info.extend_from_slice(b"AlienMsg/root/v1");
    info.extend_from_slice(lo);
    info.extend_from_slice(hi);
    let mut root = [0u8; 32];
    hk.expand(&info, &mut root).map_err(|_| Error::Kdf)?;
    Ok(root)
}

/// Initiator side: build the shared root and an Alice ratchet session.
/// Returns `(session, pending_init)` — `pending_init` is embedded in the first
/// outgoing envelope automatically.
pub fn initiate(
    me: &Identity,
    my_card: &ContactCard,
    peer_card: &ContactCard,
) -> Result<SessionState> {
    peer_card.verify()?;

    let eph = StaticSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph);

    let dh1 = me.dh(&peer_card.spk_x);
    let dh2 = eph
        .diffie_hellman(&PublicKey::from(peer_card.identity_x))
        .to_bytes();
    let dh3 = eph
        .diffie_hellman(&PublicKey::from(peer_card.spk_x))
        .to_bytes();

    let ek_bytes: ml_kem::Encoded<
        ml_kem::kem::EncapsulationKey<ml_kem::MlKem1024Params>,
    > = peer_card
        .pq_ek
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidCard)?;
    let ek = ml_kem::kem::EncapsulationKey::<ml_kem::MlKem1024Params>::from_bytes(&ek_bytes);
    let (pq_ct, ss_pq) = ek
        .encapsulate(&mut OsRng)
        .map_err(|_| Error::Kem)?;

    let peer_id = peer_card.owner_id();
    let root = mix_root(&dh1, &dh2, &dh3, &ss_pq, &me.public_id(), &peer_id)?;

    let pending = PendingInit {
        eph: *eph_pub.as_bytes(),
        pq_ct: pq_ct.to_vec(),
        recipient_card_id: peer_card.card_id,
        card: my_card.clone(),
    };

    SessionState::init_alice(
        root,
        peer_card.spk_x,
        me.public_id(),
        peer_id,
        peer_card.identity_ed,
        pending,
    )
}

/// Responder side: reconstruct the root from the initiator's pending data and
/// the private bundle matching `pending.recipient_card_id`.
pub fn accept(
    me: &Identity,
    bundles: &[CardBundle],
    pending: &PendingInit,
) -> Result<SessionState> {
    pending.card.verify()?;
    let bundle = bundles
        .iter()
        .find(|b| b.card.card_id == pending.recipient_card_id)
        .ok_or(Error::InvalidCard)?;

    let spk = bundle.spk_secret();

    let dh1 = spk
        .diffie_hellman(&PublicKey::from(pending.card.identity_x))
        .to_bytes();
    let dh2 = me.dh(&pending.eph);
    let dh3 = spk
        .diffie_hellman(&PublicKey::from(pending.eph))
        .to_bytes();

    let dk = bundle.decapsulation_key();
    let ct_bytes: ml_kem::Ciphertext<MlKem1024> = pending
        .pq_ct
        .as_slice()
        .try_into()
        .map_err(|_| Error::Kem)?;
    let ss_pq = dk.decapsulate(&ct_bytes).map_err(|_| Error::Kem)?;

    let peer_id = pending.card.owner_id();
    let root = mix_root(&dh1, &dh2, &dh3, &ss_pq, &peer_id, &me.public_id())?;

    Ok(SessionState::init_bob(
        root,
        bundle.spk_secret_bytes(),
        me.public_id(),
        peer_id,
        pending.card.identity_ed,
    ))
}

/// Fingerprint string both sides can compare out-of-band (QR / in person).
/// Order-independent: same output for both peers.
pub fn safety_fingerprint(id_a: &[u8; 32], ed_a: &[u8; 32], id_b: &[u8; 32], ed_b: &[u8; 32]) -> String {
    use sha2::Digest;
    let pair = |id: &[u8; 32], ed: &[u8; 32]| {
        let mut v = Vec::with_capacity(64);
        v.extend_from_slice(id);
        v.extend_from_slice(ed);
        v
    };
    let (a, b) = (pair(id_a, ed_a), pair(id_b, ed_b));
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let mut h = Sha256::new();
    h.update(b"alienmsg/fingerprint/v1");
    h.update(&lo);
    h.update(&hi);
    let d = h.finalize();
    // render as 12 groups of 5 digits (SAS-style, order-independent)
    let mut out = String::new();
    for i in 0..12 {
        let v = u32::from_be_bytes([d[2 * i], d[2 * i + 1], 0, 0]) % 100000;
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{:05}", v));
    }
    out
}


