//! Message layer: envelopes in/out, session dispatch, group invite plumbing.

use crate::card::{CardBundle, ContactCard};
use crate::error::{Error, Result};
use crate::group::GroupState;
use crate::handshake;
use crate::identity::Identity;
use crate::ratchet::SessionState;
use crate::wire::{
    self, EnvType, GroupInvitePayload, GroupMsgPayload, GroupRotatePayload, InviteInner,
    MemberWrap, PairInitPayload, PairMsgPayload,
};

/// What an inbound envelope turned out to be.
pub enum Inbound {
    /// A bare contact card (pairing material) — show/save it.
    Card(ContactCard),
    /// A PairInit created a new session with `peer_id` and carried plaintext.
    NewSession {
        session: SessionState,
        plaintext: Vec<u8>,
    },
    /// Pairwise plaintext on an existing session (index into `sessions`).
    PairText {
        session_index: usize,
        plaintext: Vec<u8>,
    },
    /// We were invited to / re-invited into a group.
    GroupJoined(GroupState),
    /// Group key rotated; index into `groups` updated in place.
    GroupRotated { group_index: usize },
    /// Group plaintext; index into `groups`.
    GroupText {
        group_index: usize,
        sender: [u8; 32],
        plaintext: Vec<u8>,
    },
}

fn ad_of(t: EnvType) -> [u8; 3] {
    [wire::MAGIC, wire::VERSION, t as u8]
}

/// Encrypt `plaintext` to the peer of `session`. First call on an initiator
/// session emits a `PairInit` envelope embedding the handshake data.
pub fn encrypt_pair(session: &mut SessionState, plaintext: &[u8]) -> Result<Vec<u8>> {
    if let Some(pending) = session.pending_init.take() {
        let ad = ad_of(EnvType::PairInit);
        let (header, nonce, ct) = session.encrypt(&ad, plaintext)?;
        wire::frame(
            EnvType::PairInit,
            &PairInitPayload {
                init: pending,
                header,
                nonce,
                ct,
            },
        )
    } else {
        let ad = ad_of(EnvType::PairMsg);
        let (header, nonce, ct) = session.encrypt(&ad, plaintext)?;
        wire::frame(
            EnvType::PairMsg,
            &PairMsgPayload { header, nonce, ct },
        )
    }
}

/// Encode a bare contact card envelope for sharing.
pub fn encode_card(card: &ContactCard) -> Result<Vec<u8>> {
    wire::frame(EnvType::Card, card)
}

/// Decrypt a pairwise envelope on an existing session (used for inner wraps
/// too — `env` is a complete framed envelope).
pub fn decrypt_pair_env(session: &mut SessionState, env: &[u8]) -> Result<Vec<u8>> {
    let (t, body) = wire::unframe(env)?;
    match t {
        EnvType::PairMsg => {
            let p: PairMsgPayload = postcard::from_bytes(body).map_err(|_| Error::Serde)?;
            session.decrypt(&ad_of(t), &p.header, &p.nonce, &p.ct)
        }
        EnvType::PairInit => {
            let p: PairInitPayload = postcard::from_bytes(body).map_err(|_| Error::Serde)?;
            // receiving PairInit on an existing session = peer reinstalled;
            // caller should re-pair, but try anyway in case keys match.
            session.decrypt(&ad_of(t), &p.header, &p.nonce, &p.ct)
        }
        _ => Err(Error::BadEnvelope),
    }
}

/// Full inbound dispatch. `sessions` and `groups` are owned collections; the
/// returned `Inbound` tells the caller what happened and what to persist.
pub fn decrypt_any(
    me: &Identity,
    bundles: &[CardBundle],
    sessions: &mut Vec<SessionState>,
    groups: &mut Vec<GroupState>,
    env: &[u8],
) -> Result<Inbound> {
    let (t, body) = wire::unframe(env)?;
    match t {
        EnvType::Card => {
            let card: ContactCard = postcard::from_bytes(body).map_err(|_| Error::Serde)?;
            card.verify()?;
            Ok(Inbound::Card(card))
        }
        EnvType::PairInit => {
            let p: PairInitPayload = postcard::from_bytes(body).map_err(|_| Error::Serde)?;
            let mut session = handshake::accept(me, bundles, &p.init)?;
            let pt = session.decrypt(&ad_of(t), &p.header, &p.nonce, &p.ct)?;
            session.confirmed = true;
            Ok(Inbound::NewSession {
                session,
                plaintext: pt,
            })
        }
        EnvType::PairMsg => {
            // Route by session_id embedded in the header.
            let p: PairMsgPayload = postcard::from_bytes(body).map_err(|_| Error::Serde)?;
            let idx = sessions
                .iter()
                .position(|s| s.session_id == p.header.session_id)
                .ok_or(Error::Ratchet("no session for id"))?;
            let s = &mut sessions[idx];
            let pt = s.decrypt(&ad_of(t), &p.header, &p.nonce, &p.ct)?;
            if !s.confirmed {
                s.confirmed = true;
            }
            Ok(Inbound::PairText {
                session_index: idx,
                plaintext: pt,
            })
        }
        EnvType::GroupMsg => {
            let p: GroupMsgPayload = postcard::from_bytes(body).map_err(|_| Error::Serde)?;
            let idx = groups
                .iter()
                .position(|g| g.group_id == p.group_id)
                .ok_or(Error::Group("unknown group"))?;
            let g = &mut groups[idx];
            let pt = g.decrypt(&ad_of(t), p.epoch, &p.sender, p.n, &p.nonce, &p.ct)?;
            Ok(Inbound::GroupText {
                group_index: idx,
                sender: p.sender,
                plaintext: pt,
            })
        }
        EnvType::GroupInvite | EnvType::GroupRotate => {
            let (group_id, _epoch, items) = if t == EnvType::GroupInvite {
                let p: GroupInvitePayload =
                    postcard::from_bytes(body).map_err(|_| Error::Serde)?;
                (p.group_id, p.epoch, p.items)
            } else {
                let p: GroupRotatePayload =
                    postcard::from_bytes(body).map_err(|_| Error::Serde)?;
                (p.group_id, p.epoch, p.items)
            };
            let my = me.public_id();
            let wrap = items
                .iter()
                .find(|w| w.member == my)
                .ok_or(Error::Group("not a recipient"))?;
            // inner env is a pairwise envelope to us; find its session by
            // peeking the session_id in the inner header. PairInit inner
            // wraps are not supported: pair with the admin first.
            let (inner_t, inner_body) = wire::unframe(&wrap.env)?;
            if inner_t != EnvType::PairMsg {
                return Err(Error::Group("invite needs an established pairwise session"));
            }
            let inner_hdr: PairMsgPayload =
                postcard::from_bytes(inner_body).map_err(|_| Error::Serde)?;
            let sidx = sessions
                .iter()
                .position(|s| s.session_id == inner_hdr.header.session_id)
                .ok_or(Error::Ratchet("no session for invite"))?;
            let inner_pt = decrypt_pair_env(&mut sessions[sidx], &wrap.env)?;
            let inner: InviteInner =
                postcard::from_bytes(&inner_pt).map_err(|_| Error::Serde)?;

            if t == EnvType::GroupInvite {
                if let Some(gi) = groups.iter().position(|g| g.group_id == group_id) {
                    // re-invite on same group id: treat as rotation
                    groups[gi].apply_rotate(inner.epoch, inner.group_key, inner.members)?;
                    return Ok(Inbound::GroupRotated { group_index: gi });
                }
                let g = GroupState::from_invite(
                    inner.group_id,
                    inner.epoch,
                    inner.group_key,
                    inner.admin,
                    inner.members,
                    "",
                    me.public_id(),
                );
                Ok(Inbound::GroupJoined(g))
            } else {
                let gi = groups
                    .iter()
                    .position(|g| g.group_id == group_id)
                    .ok_or(Error::Group("rotate for unknown group"))?;
                groups[gi].apply_rotate(inner.epoch, inner.group_key, inner.members)?;
                Ok(Inbound::GroupRotated { group_index: gi })
            }
        }
    }
}

/// Admin: create group and produce the invite envelope for `members`
/// (peer ids, each needing an established session in `sessions`).
pub fn group_create(
    me: &Identity,
    sessions: &mut [SessionState],
    member_ids: &[[u8; 32]],
    name: &str,
) -> Result<(GroupState, Vec<u8>)> {
    let mut g = GroupState::create(me.public_id(), name);
    let mut members = vec![me.public_id()];
    members.extend_from_slice(member_ids);
    g.members = members.clone();

    let inner = InviteInner {
        kind: EnvType::GroupInvite as u8,
        group_id: g.group_id,
        epoch: g.epoch,
        group_key: g.k_g,
        admin: me.public_id(),
        members,
    };
    let inner_bytes = postcard::to_allocvec(&inner).map_err(|_| Error::Serde)?;

    let mut items = Vec::new();
    for mid in member_ids {
        let s = sessions
            .iter_mut()
            .find(|s| &s.peer_id == mid)
            .ok_or(Error::Group("no session for member"))?;
        let env = encrypt_pair(s, &inner_bytes)?;
        items.push(MemberWrap { member: *mid, env });
    }
    let env = wire::frame(
        EnvType::GroupInvite,
        &GroupInvitePayload {
            group_id: g.group_id,
            epoch: g.epoch,
            items,
        },
    )?;
    Ok((g, env))
}

/// Admin: rotate after removing `removed` (and/or adding nothing). Produces a
/// rotate envelope wrapped for every remaining non-admin member.
pub fn group_rotate(
    me: &Identity,
    group: &mut GroupState,
    sessions: &mut [SessionState],
    new_members: Vec<[u8; 32]>,
) -> Result<Vec<u8>> {
    if group.admin != me.public_id() {
        return Err(Error::Group("only admin can rotate"));
    }
    let new_key = group.rotate(new_members.clone());
    let inner = InviteInner {
        kind: EnvType::GroupRotate as u8,
        group_id: group.group_id,
        epoch: group.epoch,
        group_key: new_key,
        admin: me.public_id(),
        members: new_members.clone(),
    };
    let inner_bytes = postcard::to_allocvec(&inner).map_err(|_| Error::Serde)?;

    let mut items = Vec::new();
    for mid in new_members.iter().filter(|m| **m != me.public_id()) {
        let s = sessions
            .iter_mut()
            .find(|s| &s.peer_id == mid)
            .ok_or(Error::Group("no session for member"))?;
        let env = encrypt_pair(s, &inner_bytes)?;
        items.push(MemberWrap { member: *mid, env });
    }
    wire::frame(
        EnvType::GroupRotate,
        &GroupRotatePayload {
            group_id: group.group_id,
            epoch: group.epoch,
            items,
        },
    )
}

/// Encrypt a group message envelope.
pub fn encrypt_group(group: &mut GroupState, plaintext: &[u8]) -> Result<Vec<u8>> {
    let ad = ad_of(EnvType::GroupMsg);
    let (n, nonce, ct) = group.encrypt(&ad, plaintext);
    wire::frame(
        EnvType::GroupMsg,
        &GroupMsgPayload {
            group_id: group.group_id,
            epoch: group.epoch,
            sender: group.my_id,
            n,
            nonce,
            ct,
        },
    )
}
