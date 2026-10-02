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

/// A pairwise session established while unwrapping a group invite/rotate:
/// the admin's inner wrap was a `PairInit` because no direct message had
/// been exchanged yet. The session is already pushed into `sessions`.
pub struct InnerSession {
    /// Index into `sessions` where the new session was appended.
    pub session_index: usize,
    /// Initiator's contact card (authenticates identity + prekeys).
    pub peer_card: ContactCard,
    /// Index into `bundles` of the one-time prekey bundle consumed.
    pub bundle_index: usize,
}

/// What an inbound envelope turned out to be.
pub enum Inbound {
    /// A bare contact card (pairing material) — show/save it.
    Card(ContactCard),
    /// A PairInit created a new session with `peer_id` and carried plaintext.
    NewSession {
        session: Box<SessionState>,
        plaintext: Vec<u8>,
        /// The initiator's contact card (authenticates identity + prekeys);
        /// lets the callee display/verify the peer without a second exchange.
        peer_card: ContactCard,
        /// Index into `bundles` of the one-time prekey bundle consumed by the
        /// handshake — the caller may securely drop it.
        bundle_index: usize,
    },
    /// Pairwise plaintext on an existing session (index into `sessions`).
    PairText {
        session_index: usize,
        plaintext: Vec<u8>,
    },
    /// We were invited to / re-invited into a group.
    GroupJoined {
        group: GroupState,
        /// Set when the invite also established a pairwise session.
        inner_session: Option<InnerSession>,
    },
    /// Group key rotated; index into `groups` updated in place.
    /// (Also produced for a rotate addressed to a group we didn't have yet —
    /// an invite by another name.)
    GroupRotated {
        group_index: usize,
        inner_session: Option<InnerSession>,
    },
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
        wire::frame(EnvType::PairMsg, &PairMsgPayload { header, nonce, ct })
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
            let (mut session, bundle_index) = handshake::accept(me, bundles, &p.init)?;
            // Replay of an already-accepted PairInit: route to the existing
            // session instead of creating a duplicate — the ratchet's replay
            // protection then rejects the re-delivered first message.
            if let Some(idx) = sessions
                .iter()
                .position(|s| s.session_id == session.session_id)
            {
                let pt = sessions[idx].decrypt(&ad_of(t), &p.header, &p.nonce, &p.ct)?;
                return Ok(Inbound::PairText {
                    session_index: idx,
                    plaintext: pt,
                });
            }
            let pt = session.decrypt(&ad_of(t), &p.header, &p.nonce, &p.ct)?;
            session.confirmed = true;
            Ok(Inbound::NewSession {
                session: Box::new(session),
                plaintext: pt,
                peer_card: p.init.card,
                bundle_index,
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
            let proof = crate::group::SenderProof {
                ed: p.sender_ed,
                x: p.sender_x,
                sig: p.signature,
            };
            let msg = crate::group::InboundMsg {
                epoch: p.epoch,
                sender: &p.sender,
                proof: &proof,
                n: p.n,
                nonce: &p.nonce,
                ct: &p.ct,
            };
            let pt = g.decrypt(&ad_of(t), &msg)?;
            Ok(Inbound::GroupText {
                group_index: idx,
                sender: p.sender,
                plaintext: pt,
            })
        }
        EnvType::GroupInvite | EnvType::GroupRotate => {
            let (group_id, epoch, items) = if t == EnvType::GroupInvite {
                let p: GroupInvitePayload = postcard::from_bytes(body).map_err(|_| Error::Serde)?;
                (p.group_id, p.epoch, p.items)
            } else {
                let p: GroupRotatePayload = postcard::from_bytes(body).map_err(|_| Error::Serde)?;
                (p.group_id, p.epoch, p.items)
            };
            let my = me.public_id();
            let wrap = items
                .iter()
                .find(|w| w.member == my)
                .ok_or(Error::Group("not a recipient"))?;
            // The inner env is a pairwise envelope addressed to us. It may be
            // a PairMsg on an established session *or* a PairInit: the admin's
            // first pairwise send is always a PairInit, so a group invite is
            // a perfectly valid first message between two peers.
            let (inner_t, inner_body) = wire::unframe(&wrap.env)?;
            let mut inner_session: Option<InnerSession> = None;
            let (sidx, inner_pt) = match inner_t {
                EnvType::PairInit => {
                    let p: PairInitPayload =
                        postcard::from_bytes(inner_body).map_err(|_| Error::Serde)?;
                    // Same PairInit already consumed as a direct message:
                    // the ratchet header carries session_id, so we can route
                    // to the existing session even if the one-time bundle was
                    // already dropped (a verbatim replay is then rejected by
                    // the ratchet itself).
                    match sessions
                        .iter()
                        .position(|s| s.session_id == p.header.session_id)
                    {
                        Some(i) => (
                            i,
                            sessions[i].decrypt(&ad_of(inner_t), &p.header, &p.nonce, &p.ct)?,
                        ),
                        None => {
                            let (mut session, bundle_index) =
                                handshake::accept(me, bundles, &p.init)?;
                            let pt =
                                session.decrypt(&ad_of(inner_t), &p.header, &p.nonce, &p.ct)?;
                            session.confirmed = true;
                            sessions.push(session);
                            inner_session = Some(InnerSession {
                                session_index: sessions.len() - 1,
                                peer_card: p.init.card,
                                bundle_index,
                            });
                            (sessions.len() - 1, pt)
                        }
                    }
                }
                EnvType::PairMsg => {
                    let inner_hdr: PairMsgPayload =
                        postcard::from_bytes(inner_body).map_err(|_| Error::Serde)?;
                    let i = sessions
                        .iter()
                        .position(|s| s.session_id == inner_hdr.header.session_id)
                        .ok_or(Error::Ratchet("no session for invite"))?;
                    (
                        i,
                        sessions[i].decrypt(&ad_of(inner_t), &inner_hdr.header, &inner_hdr.nonce, &inner_hdr.ct)?,
                    )
                }
                _ => return Err(Error::Group("invite wrap is not a pairwise envelope")),
            };
            let sender_id = sessions[sidx].peer_id;
            let inner: InviteInner = postcard::from_bytes(&inner_pt).map_err(|_| Error::Serde)?;

            // Authorization: the wrap must be consistent with the outer
            // envelope and must come from the *group admin's* pairwise
            // session — otherwise any contact (or non-admin member) could
            // force-rotate the group to a key they control.
            if inner.kind != t as u8 || inner.group_id != group_id || inner.epoch != epoch {
                return Err(Error::Group("invite/rotate inner mismatch"));
            }
            if sender_id != inner.admin {
                return Err(Error::Group("sender is not the claimed admin"));
            }
            if !inner.members.contains(&my) {
                return Err(Error::Group("we are not in the member list"));
            }

            if let Some(gi) = groups.iter().position(|g| g.group_id == group_id) {
                // Re-invite or rotation on an existing group: only the current
                // admin may change the epoch.
                if groups[gi].admin != sender_id {
                    return Err(Error::Group("only admin can rotate"));
                }
                groups[gi].apply_rotate(
                    inner.epoch,
                    inner.group_key,
                    inner.members,
                    &inner.name,
                )?;
                return Ok(Inbound::GroupRotated {
                    group_index: gi,
                    inner_session,
                });
            }
            // A rotate for an unknown group is just an invite: create state.
            let g = GroupState::from_invite(
                inner.group_id,
                inner.epoch,
                inner.group_key,
                inner.admin,
                inner.members,
                &inner.name,
                me.public_id(),
            );
            Ok(Inbound::GroupJoined {
                group: g,
                inner_session,
            })
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
    for mid in member_ids {
        // dedup + never invite ourselves (no self-session exists to wrap for)
        if *mid != me.public_id() && !members.contains(mid) {
            members.push(*mid);
        }
    }
    g.members = members.clone();

    let inner = InviteInner {
        kind: EnvType::GroupInvite as u8,
        group_id: g.group_id,
        epoch: g.epoch,
        group_key: g.k_g,
        admin: me.public_id(),
        members: members.clone(),
        name: name.to_string(),
    };
    let inner_bytes = postcard::to_allocvec(&inner).map_err(|_| Error::Serde)?;

    // Every member needs an established session: check all of them *before*
    // producing any wrap, so a missing session fails cleanly instead of
    // consuming ratchet keys on a subset of sessions for messages that will
    // never be sent.
    for mid in members.iter().filter(|m| **m != me.public_id()) {
        if !sessions.iter().any(|s| &s.peer_id == mid) {
            return Err(Error::Group("no session for member"));
        }
    }

    let mut items = Vec::new();
    for mid in members.iter().filter(|m| **m != me.public_id()) {
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
    if !new_members.contains(&me.public_id()) {
        return Err(Error::Group("admin must remain a member"));
    }
    // dedup while preserving order
    let mut dedup: Vec<[u8; 32]> = Vec::with_capacity(new_members.len());
    for m in new_members {
        if !dedup.contains(&m) {
            dedup.push(m);
        }
    }
    // Every member needs a session — check before rotating, and rotate a
    // scratch copy: a mid-wrap failure must not leave our local group on an
    // epoch whose key nobody else received.
    for mid in dedup.iter().filter(|m| **m != me.public_id()) {
        if !sessions.iter().any(|s| &s.peer_id == mid) {
            return Err(Error::Group("no session for member"));
        }
    }
    let mut next = group.clone();
    let new_key = next.rotate(dedup.clone());
    let inner = InviteInner {
        kind: EnvType::GroupRotate as u8,
        group_id: next.group_id,
        epoch: next.epoch,
        group_key: new_key,
        admin: me.public_id(),
        members: dedup.clone(),
        name: next.name.clone(),
    };
    let inner_bytes = postcard::to_allocvec(&inner).map_err(|_| Error::Serde)?;

    let mut items = Vec::new();
    for mid in dedup.iter().filter(|m| **m != me.public_id()) {
        let s = sessions
            .iter_mut()
            .find(|s| &s.peer_id == mid)
            .ok_or(Error::Group("no session for member"))?;
        let env = encrypt_pair(s, &inner_bytes)?;
        items.push(MemberWrap { member: *mid, env });
    }
    let env = wire::frame(
        EnvType::GroupRotate,
        &GroupRotatePayload {
            group_id: next.group_id,
            epoch: next.epoch,
            items,
        },
    )?;
    *group = next;
    Ok(env)
}

/// Encrypt a group message envelope, signed by our identity key.
pub fn encrypt_group(me: &Identity, group: &mut GroupState, plaintext: &[u8]) -> Result<Vec<u8>> {
    if group.my_id != me.public_id() {
        return Err(Error::Group("group state does not belong to this identity"));
    }
    let ad = ad_of(EnvType::GroupMsg);
    let (n, nonce, ct, signature) = group.encrypt(me, &ad, plaintext);
    wire::frame(
        EnvType::GroupMsg,
        &GroupMsgPayload {
            group_id: group.group_id,
            epoch: group.epoch,
            sender: group.my_id,
            sender_ed: me.ed_public(),
            sender_x: me.x_public(),
            n,
            nonce,
            ct,
            signature,
        },
    )
}
