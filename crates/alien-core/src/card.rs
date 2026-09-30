//! Contact cards: signed public-key bundles exchanged out-of-band (paste / QR).
//!
//! A card carries the long-term identity plus fresh *per-pairing* prekeys:
//! a signed X25519 prekey (doubles as the responder's initial ratchet key)
//! and a signed ML-KEM-1024 encapsulation key. Regenerate a card for each new
//! pairing so prekeys are effectively one-time.

use crate::error::{Error, Result};
use crate::identity::{self, Identity};
use ml_kem::{EncodedSizeUser, KemCore, MlKem1024};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

const CARD_DOMAIN: &[u8] = b"AlienMsg/ContactCard/v1";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ContactCard {
    pub version: u8,
    pub card_id: [u8; 16],
    pub identity_ed: [u8; 32],
    pub identity_x: [u8; 32],
    pub spk_x: [u8; 32],
    pub pq_ek: Vec<u8>,
    #[serde(with = "crate::serutil::arr64")]
    pub signature: [u8; 64],
}

impl ContactCard {
    fn signing_payload(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(CARD_DOMAIN.len() + 32 + 32 + self.pq_ek.len());
        v.extend_from_slice(CARD_DOMAIN);
        v.extend_from_slice(&self.identity_x);
        v.extend_from_slice(&self.spk_x);
        v.extend_from_slice(&self.pq_ek);
        v
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|_| Error::Serde)
    }

    pub fn from_bytes(b: &[u8]) -> Result<ContactCard> {
        postcard::from_bytes(b).map_err(|_| Error::Serde)
    }

    /// Verify the prekey signature against the claimed identity key.
    pub fn verify(&self) -> Result<()> {
        if self.version != 1 || self.pq_ek.len() != 1568 {
            return Err(Error::InvalidCard);
        }
        if identity::verify(&self.identity_ed, &self.signing_payload(), &self.signature) {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }

    /// Stable id of the card's owner (must match `Identity::public_id`).
    pub fn owner_id(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"alienmsg/pubid/v1");
        h.update(self.identity_ed);
        h.update(self.identity_x);
        h.finalize().into()
    }
}

/// Private companion of a `ContactCard` — stays on-device, vault-encrypted.
#[derive(Serialize, Deserialize)]
pub struct CardBundle {
    pub card: ContactCard,
    spk_secret: [u8; 32],
    pq_dk: Vec<u8>,
}

impl CardBundle {
    pub fn spk_secret(&self) -> StaticSecret {
        StaticSecret::from(self.spk_secret)
    }
    pub fn spk_secret_bytes(&self) -> [u8; 32] {
        self.spk_secret
    }
    /// Serialize the bundle (vault / FFI opaque blob).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|_| Error::Serde)
    }
    pub fn from_bytes(b: &[u8]) -> Result<CardBundle> {
        postcard::from_bytes(b).map_err(|_| Error::Serde)
    }
    pub fn pq_dk_bytes(&self) -> &[u8] {
        &self.pq_dk
    }
    pub fn decapsulation_key(
        &self,
    ) -> ml_kem::kem::DecapsulationKey<ml_kem::MlKem1024Params> {
        let enc: ml_kem::Encoded<ml_kem::kem::DecapsulationKey<ml_kem::MlKem1024Params>> =
            self.pq_dk.as_slice().try_into().expect("pq_dk length checked at build");
        ml_kem::kem::DecapsulationKey::from_bytes(&enc)
    }
}

/// Generate a fresh card + private bundle. One per pairing.
pub fn create_card(identity: &Identity) -> CardBundle {
    let spk = StaticSecret::random_from_rng(OsRng);
    let (pq_dk, pq_ek) = MlKem1024::generate(&mut OsRng);

    let mut card = ContactCard {
        version: 1,
        card_id: rand::random::<[u8; 16]>(),
        identity_ed: identity.ed_public(),
        identity_x: identity.x_public(),
        spk_x: *PublicKey::from(&spk).as_bytes(),
        pq_ek: pq_ek.as_bytes().to_vec(),
        signature: [0u8; 64],
    };
    card.signature = identity.sign(&card.signing_payload());

    CardBundle {
        card,
        spk_secret: spk.to_bytes(),
        pq_dk: pq_dk.as_bytes().to_vec(),
    }
}

/// Self-consistency check (also used in tests).
pub fn verify_card(card: &ContactCard) -> Result<()> {
    card.verify()
}
