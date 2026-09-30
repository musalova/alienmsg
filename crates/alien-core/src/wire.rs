//! Wire format: `[MAGIC 'A1'][version u8][type u8][postcard payload]`.
//! The payload is a postcard-serialized struct per type. Everything after the
//! header is either public-key material or AEAD ciphertext — indistinguishable
//! from random noise to outsiders, especially after the stealth codec.

use crate::error::{Error, Result};
use crate::handshake::PendingInit;
use crate::ratchet::MsgHeader;
use serde::{Deserialize, Serialize};

pub const MAGIC: u8 = 0xA1;
pub const VERSION: u8 = 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum EnvType {
    /// Bare contact card being shared (pairing bootstrap).
    Card = 0x01,
    /// First pairwise message: carries handshake data + first ciphertext.
    PairInit = 0x02,
    /// Subsequent pairwise ratchet message.
    PairMsg = 0x03,
    /// Group invite: per-member wrapped copies of the group key.
    GroupInvite = 0x10,
    /// Group data message.
    GroupMsg = 0x11,
    /// Group key rotation (member set changed).
    GroupRotate = 0x12,
}

impl EnvType {
    pub fn from_u8(v: u8) -> Option<EnvType> {
        Some(match v {
            0x01 => EnvType::Card,
            0x02 => EnvType::PairInit,
            0x03 => EnvType::PairMsg,
            0x10 => EnvType::GroupInvite,
            0x11 => EnvType::GroupMsg,
            0x12 => EnvType::GroupRotate,
            _ => return None,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct PairInitPayload {
    pub init: PendingInit,
    pub header: MsgHeader,
    pub nonce: [u8; 24],
    pub ct: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct PairMsgPayload {
    pub header: MsgHeader,
    pub nonce: [u8; 24],
    pub ct: Vec<u8>,
}

/// One wrapped copy of group key material for a single member.
/// `env` is a complete PairMsg envelope whose plaintext is `InviteInner`.
#[derive(Serialize, Deserialize)]
pub struct MemberWrap {
    pub member: [u8; 32],
    pub env: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct GroupInvitePayload {
    pub group_id: [u8; 16],
    pub epoch: u64,
    pub items: Vec<MemberWrap>,
}

#[derive(Serialize, Deserialize)]
pub struct GroupRotatePayload {
    pub group_id: [u8; 16],
    pub epoch: u64,
    pub items: Vec<MemberWrap>,
}

#[derive(Serialize, Deserialize)]
pub struct GroupMsgPayload {
    pub group_id: [u8; 16],
    pub epoch: u64,
    pub sender: [u8; 32],
    pub n: u32,
    pub nonce: [u8; 24],
    pub ct: Vec<u8>,
}

/// Inner plaintext of a pairwise envelope carrying group key material.
#[derive(Serialize, Deserialize)]
pub struct InviteInner {
    pub kind: u8, // 0x10 invite, 0x12 rotate
    pub group_id: [u8; 16],
    pub epoch: u64,
    pub group_key: [u8; 32],
    pub admin: [u8; 32],
    pub members: Vec<[u8; 32]>,
}

/// Frame a typed envelope.
pub fn frame<S: Serialize>(t: EnvType, payload: &S) -> Result<Vec<u8>> {
    let body = postcard::to_allocvec(payload).map_err(|_| Error::Serde)?;
    let mut out = Vec::with_capacity(3 + body.len());
    out.push(MAGIC);
    out.push(VERSION);
    out.push(t as u8);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Split an envelope into (type, payload). Also returns the 3-byte framing
/// header slice for AEAD associated-data purposes via `framing_bytes`.
pub fn unframe(env: &[u8]) -> Result<(EnvType, &[u8])> {
    if env.len() < 4 || env[0] != MAGIC || env[1] != VERSION {
        return Err(Error::BadEnvelope);
    }
    let t = EnvType::from_u8(env[2]).ok_or(Error::BadEnvelope)?;
    Ok((t, &env[3..]))
}

/// The bytes used as AEAD associated data prefix (magic+version+type).
pub fn framing_of(env: &[u8]) -> Result<&[u8]> {
    if env.len() < 3 || env[0] != MAGIC || env[1] != VERSION {
        return Err(Error::BadEnvelope);
    }
    Ok(&env[..3])
}
