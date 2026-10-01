use alien_core::card::{create_card, CardBundle, ContactCard};
use alien_core::handshake;
use alien_core::identity::Identity;
use alien_core::message::{self, Inbound};
use alien_core::ratchet::SessionState;
use alien_core::recovery;
use alien_core::wire::{self, EnvType};

struct Party {
    identity: Identity,
    bundles: Vec<CardBundle>,
    sessions: Vec<SessionState>,
    groups: Vec<alien_core::group::GroupState>,
}

impl Party {
    fn new(seed: &[u8; 32]) -> Party {
        Party {
            identity: Identity::from_seed(seed).unwrap(),
            bundles: vec![],
            sessions: vec![],
            groups: vec![],
        }
    }
    fn new_card(&mut self) -> ContactCard {
        let b = create_card(&self.identity);
        let c = b.card.clone();
        self.bundles.push(b);
        c
    }
    fn try_recv(&mut self, env: &[u8]) -> alien_core::Result<Inbound> {
        message::decrypt_any(
            &self.identity,
            &self.bundles,
            &mut self.sessions,
            &mut self.groups,
            env,
        )
    }
    fn recv(&mut self, env: &[u8]) -> Inbound {
        self.try_recv(env).unwrap()
    }
}

#[test]
fn mnemonic_recovery_is_deterministic() {
    let m = recovery::generate_mnemonic().unwrap();
    assert!(recovery::validate_mnemonic(&m));
    let s1 = recovery::seed_from_mnemonic(&m, "").unwrap();
    let s2 = recovery::seed_from_mnemonic(&m, "").unwrap();
    assert_eq!(s1, s2);
    let id1 = Identity::from_seed(&s1).unwrap();
    let id2 = Identity::from_seed(&s2).unwrap();
    assert_eq!(id1.public_id(), id2.public_id());
}

#[test]
fn mnemonic_rejects_garbage() {
    assert!(!recovery::validate_mnemonic("foo bar baz"));
    assert!(recovery::seed_from_mnemonic("foo bar baz", "").is_err());
}

#[test]
fn card_signs_and_verifies() {
    let id = Identity::from_seed(&[7u8; 32]).unwrap();
    let b = create_card(&id);
    b.card.verify().unwrap();
    let mut bad = b.card.clone();
    bad.spk_x[0] ^= 1;
    assert!(bad.verify().is_err());
}

#[test]
fn pairwise_roundtrip_both_directions() {
    let mut a = Party::new(&[1u8; 32]);
    let mut b = Party::new(&[2u8; 32]);

    let card_a = a.new_card();
    let card_b = b.new_card();

    // A initiates a session toward B.
    let mut sa = handshake::initiate(&a.identity, &card_a, &card_b).unwrap();
    let env1 = message::encrypt_pair(&mut sa, b"ciao bob").unwrap();
    a.sessions.push(sa);

    // B accepts: PairInit creates the session and decrypts.
    match b.recv(&env1) {
        Inbound::NewSession {
            session, plaintext, ..
        } => {
            assert_eq!(plaintext, b"ciao bob");
            b.sessions.push(*session);
        }
        _ => panic!("expected NewSession"),
    }

    // B replies; A decrypts (Alice's session gets confirmed).
    let env2 = message::encrypt_pair(&mut b.sessions[0], b"ciao alice").unwrap();
    match a.recv(&env2) {
        Inbound::PairText { plaintext, .. } => assert_eq!(plaintext, b"ciao alice"),
        _ => panic!("expected PairText"),
    }

    // Several more rounds.
    for i in 0..10u8 {
        let msg = format!("msg-{i}");
        let env = message::encrypt_pair(&mut a.sessions[0], msg.as_bytes()).unwrap();
        match b.recv(&env) {
            Inbound::PairText { plaintext, .. } => assert_eq!(plaintext, msg.as_bytes()),
            _ => panic!(),
        }
        let env = message::encrypt_pair(&mut b.sessions[0], msg.as_bytes()).unwrap();
        match a.recv(&env) {
            Inbound::PairText { plaintext, .. } => assert_eq!(plaintext, msg.as_bytes()),
            _ => panic!(),
        }
    }
}

#[test]
fn out_of_order_and_loss() {
    let mut a = Party::new(&[3u8; 32]);
    let mut b = Party::new(&[4u8; 32]);
    let card_a = a.new_card();
    let card_b = b.new_card();
    let mut sa = handshake::initiate(&a.identity, &card_a, &card_b).unwrap();
    let env0 = message::encrypt_pair(&mut sa, b"zero").unwrap();
    a.sessions.push(sa);
    match b.recv(&env0) {
        Inbound::NewSession { session, .. } => b.sessions.push(*session),
        _ => panic!(),
    }

    // A sends 3 messages; B receives them out of order.
    let e1 = message::encrypt_pair(&mut a.sessions[0], b"one").unwrap();
    let e2 = message::encrypt_pair(&mut a.sessions[0], b"two").unwrap();
    let e3 = message::encrypt_pair(&mut a.sessions[0], b"three").unwrap();
    for (env, want) in [(e3, "three"), (e1, "one"), (e2, "two")] {
        match b.recv(&env) {
            Inbound::PairText { plaintext, .. } => {
                assert_eq!(String::from_utf8(plaintext).unwrap(), want)
            }
            _ => panic!(),
        }
    }

    // Duplicate delivery is rejected as replay.
    let dup = message::encrypt_pair(&mut a.sessions[0], b"again").unwrap();
    let keep = dup.clone();
    match b.recv(&dup) {
        Inbound::PairText { .. } => {}
        _ => panic!(),
    }
    assert!(b.try_recv(&keep).is_err());
}

#[test]
fn tampered_ciphertext_fails() {
    let mut a = Party::new(&[5u8; 32]);
    let mut b = Party::new(&[6u8; 32]);
    let card_a = a.new_card();
    let card_b = b.new_card();
    let mut sa = handshake::initiate(&a.identity, &card_a, &card_b).unwrap();
    let mut env = message::encrypt_pair(&mut sa, b"hello").unwrap();
    a.sessions.push(sa);
    let n = env.len();
    env[n - 1] ^= 1; // flip a ciphertext bit
    assert!(b.try_recv(&env).is_err());
}

#[test]
fn group_full_lifecycle() {
    let mut admin = Party::new(&[10u8; 32]);
    let mut m1 = Party::new(&[11u8; 32]);
    let mut m2 = Party::new(&[12u8; 32]);

    // pair admin<->m1, admin<->m2
    for member in [&mut m1, &mut m2] {
        let ca = admin.new_card();
        let cm = member.new_card();
        let mut s = handshake::initiate(&admin.identity, &ca, &cm).unwrap();
        let env = message::encrypt_pair(&mut s, b"hi").unwrap();
        admin.sessions.push(s);
        match member.recv(&env) {
            Inbound::NewSession { session, .. } => member.sessions.push(*session),
            _ => panic!(),
        }
        // member replies so admin's session is confirmed
        let e = message::encrypt_pair(&mut member.sessions[0], b"hi back").unwrap();
        admin.try_recv(&e).ok();
    }

    let m1_id = m1.identity.public_id();
    let m2_id = m2.identity.public_id();

    // admin creates group with m1 and m2
    let (g, invite_env) = message::group_create(
        &admin.identity,
        &mut admin.sessions,
        &[m1_id, m2_id],
        "test",
    )
    .unwrap();
    admin.groups.push(g);
    let group_id = admin.groups[0].group_id;

    match m1.recv(&invite_env) {
        Inbound::GroupJoined(g) => {
            assert_eq!(g.group_id, group_id);
            m1.groups.push(g);
        }
        _ => panic!("m1 expected GroupJoined"),
    }
    match m2.recv(&invite_env) {
        Inbound::GroupJoined(g) => m2.groups.push(g),
        _ => panic!("m2 expected GroupJoined"),
    }

    // everyone can send and read
    let e = message::encrypt_group(&m1.identity, &mut m1.groups[0], b"group hello").unwrap();
    match admin.recv(&e) {
        Inbound::GroupText {
            plaintext, sender, ..
        } => {
            assert_eq!(plaintext, b"group hello");
            assert_eq!(sender, m1_id);
        }
        _ => panic!(),
    }
    match m2.recv(&e) {
        Inbound::GroupText { plaintext, .. } => assert_eq!(plaintext, b"group hello"),
        _ => panic!(),
    }

    // admin removes m2 -> rotation; m1 gets new epoch, m2 doesn't.
    let remaining = vec![admin.identity.public_id(), m1_id];
    let rot_env = message::group_rotate(
        &admin.identity,
        &mut admin.groups[0],
        &mut admin.sessions,
        remaining,
    )
    .unwrap();
    match m1.recv(&rot_env) {
        Inbound::GroupRotated { .. } => {}
        _ => panic!("expected GroupRotated"),
    }

    // m1 posts on the new epoch; m2 cannot decrypt it (dropped/unknown).
    let e_new =
        message::encrypt_group(&m1.identity, &mut m1.groups[0], b"secret post-kick").unwrap();
    match admin.recv(&e_new) {
        Inbound::GroupText { plaintext, .. } => assert_eq!(plaintext, b"secret post-kick"),
        _ => panic!(),
    }
    let res = m2.try_recv(&e_new);
    assert!(res.is_err());
}

#[test]
fn wire_rejects_garbage() {
    assert!(wire::unframe(b"hello").is_err());
    assert!(wire::unframe(&[0xA1, 0x01, 0x99]).is_err());
}

#[test]
fn pairinit_replay_does_not_duplicate_session() {
    let mut a = Party::new(&[20u8; 32]);
    let mut b = Party::new(&[21u8; 32]);
    let card_a = a.new_card();
    let card_b = b.new_card();
    let mut sa = handshake::initiate(&a.identity, &card_a, &card_b).unwrap();
    let env = message::encrypt_pair(&mut sa, b"first").unwrap();
    a.sessions.push(sa);

    match b.recv(&env) {
        Inbound::NewSession { session, .. } => b.sessions.push(*session),
        _ => panic!(),
    }
    // A verbatim replay must not create a second session nor re-deliver text.
    assert!(b.try_recv(&env).is_err());
    assert_eq!(b.sessions.len(), 1);
}

#[test]
fn tampered_delivery_does_not_burn_keys() {
    let mut a = Party::new(&[22u8; 32]);
    let mut b = Party::new(&[23u8; 32]);
    let card_a = a.new_card();
    let card_b = b.new_card();
    let mut sa = handshake::initiate(&a.identity, &card_a, &card_b).unwrap();
    let env0 = message::encrypt_pair(&mut sa, b"zero").unwrap();
    a.sessions.push(sa);
    match b.recv(&env0) {
        Inbound::NewSession { session, .. } => b.sessions.push(*session),
        _ => panic!(),
    }

    // In-order message corrupted in transit: decrypt fails, but an intact
    // re-delivery must still succeed (the chain step is committed only after
    // a successful AEAD open).
    let good = message::encrypt_pair(&mut a.sessions[0], b"one").unwrap();
    let mut bad = good.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    assert!(b.try_recv(&bad).is_err());
    match b.recv(&good) {
        Inbound::PairText { plaintext, .. } => assert_eq!(plaintext, b"one"),
        _ => panic!(),
    }

    // Out-of-order: corrupt a skipped message first, then deliver the intact
    // copy — the stored skipped key must survive the tampered attempt.
    let m2 = message::encrypt_pair(&mut a.sessions[0], b"two").unwrap();
    let m3 = message::encrypt_pair(&mut a.sessions[0], b"three").unwrap();
    let mut bad3 = m3.clone();
    let k = bad3.len();
    bad3[k - 1] ^= 1;
    assert!(b.try_recv(&bad3).is_err()); // n=2 becomes skipped, n=3 fails
    match b.recv(&m3) {
        Inbound::PairText { plaintext, .. } => assert_eq!(plaintext, b"three"),
        _ => panic!(),
    }
    match b.recv(&m2) {
        Inbound::PairText { plaintext, .. } => assert_eq!(plaintext, b"two"),
        _ => panic!(),
    }
}

/// Build a three-member group (admin + m1 + m2), everyone joined.
fn setup_group() -> (Party, Party, Party) {
    let mut admin = Party::new(&[30u8; 32]);
    let mut m1 = Party::new(&[31u8; 32]);
    let mut m2 = Party::new(&[32u8; 32]);
    for member in [&mut m1, &mut m2] {
        let ca = admin.new_card();
        let cm = member.new_card();
        let mut s = handshake::initiate(&admin.identity, &ca, &cm).unwrap();
        let env = message::encrypt_pair(&mut s, b"hi").unwrap();
        admin.sessions.push(s);
        match member.recv(&env) {
            Inbound::NewSession { session, .. } => member.sessions.push(*session),
            _ => panic!(),
        }
    }
    let ids = [m1.identity.public_id(), m2.identity.public_id()];
    let (g, invite) =
        message::group_create(&admin.identity, &mut admin.sessions, &ids, "g").unwrap();
    admin.groups.push(g);
    for member in [&mut m1, &mut m2] {
        match member.recv(&invite) {
            Inbound::GroupJoined(g) => member.groups.push(g),
            _ => panic!(),
        }
    }
    (admin, m1, m2)
}

#[test]
fn non_admin_cannot_rotate_or_invite() {
    let (mut admin, mut m1, _m2) = setup_group();
    let group_id = admin.groups[0].group_id;

    // m1 crafts a rotate envelope claiming to be admin: the wrap is encrypted
    // on m1's pairwise session to admin, so the admin check must reject it.
    let inner = wire::InviteInner {
        kind: EnvType::GroupRotate as u8,
        group_id,
        epoch: 99,
        group_key: [9u8; 32],
        admin: m1.identity.public_id(),
        members: vec![admin.identity.public_id(), m1.identity.public_id()],
        name: "hijack".into(),
    };
    let inner_bytes = postcard::to_allocvec(&inner).unwrap();
    // m1's session to admin is sessions[0] (admin initiated, m1 accepted).
    let wrap_env = message::encrypt_pair(&mut m1.sessions[0], &inner_bytes).unwrap();
    let outer = wire::frame(
        EnvType::GroupRotate,
        &wire::GroupRotatePayload {
            group_id,
            epoch: 99,
            items: vec![wire::MemberWrap {
                member: admin.identity.public_id(),
                env: wrap_env,
            }],
        },
    )
    .unwrap();
    assert!(admin.try_recv(&outer).is_err());
    // Group state untouched: still epoch 1.
    assert_eq!(admin.groups[0].epoch, 1);
}

#[test]
fn group_sender_impersonation_is_rejected() {
    let (mut admin, mut m1, m2) = setup_group();
    let m2_id = m2.identity.public_id();

    // m1 encrypts a legit message, then rewrites the claimed sender to m2.
    // The signature no longer matches the (ed, x) pair -> must be rejected.
    let env = message::encrypt_group(&m1.identity, &mut m1.groups[0], b"fake").unwrap();
    let (t, body) = wire::unframe(&env).unwrap();
    assert_eq!(t, EnvType::GroupMsg);
    let mut p: wire::GroupMsgPayload = postcard::from_bytes(body).unwrap();
    p.sender = m2_id;
    let forged = wire::frame(t, &p).unwrap();
    assert!(admin.try_recv(&forged).is_err());

    // Also: claim m2's id AND m2's real keys, but keep m1's signature — the
    // hash check passes, the Ed25519 verification must fail.
    let env = message::encrypt_group(&m1.identity, &mut m1.groups[0], b"fake2").unwrap();
    let (t, body) = wire::unframe(&env).unwrap();
    let mut p: wire::GroupMsgPayload = postcard::from_bytes(body).unwrap();
    p.sender = m2_id;
    p.sender_ed = m2.identity.ed_public();
    p.sender_x = m2.identity.x_public();
    let forged = wire::frame(t, &p).unwrap();
    assert!(admin.try_recv(&forged).is_err());
}

#[test]
fn removed_member_cannot_post_on_old_epoch() {
    let (mut admin, mut m1, mut m2) = setup_group();
    let admin_id = admin.identity.public_id();
    let m1_id = m1.identity.public_id();

    // admin removes m2 -> m1 rotates to epoch 2, m2 keeps epoch-1 state.
    let rot = message::group_rotate(
        &admin.identity,
        &mut admin.groups[0],
        &mut admin.sessions,
        vec![admin_id, m1_id],
    )
    .unwrap();
    match m1.recv(&rot) {
        Inbound::GroupRotated { .. } => {}
        _ => panic!(),
    }

    // m2 posts on the old epoch: members must reject it (sender excluded).
    let e_old = message::encrypt_group(&m2.identity, &mut m2.groups[0], b"stale").unwrap();
    assert!(admin.try_recv(&e_old).is_err());
    assert!(m1.try_recv(&e_old).is_err());

    // A non-member id that was never in the group is rejected outright on the
    // current epoch too (signature is valid but sender not in members).
    let outsider = Party::new(&[33u8; 32]);
    let e = message::encrypt_group(&m1.identity, &mut m1.groups[0], b"hi").unwrap();
    let (t, body) = wire::unframe(&e).unwrap();
    let mut p: wire::GroupMsgPayload = postcard::from_bytes(body).unwrap();
    p.sender = outsider.identity.public_id();
    p.sender_ed = outsider.identity.ed_public();
    p.sender_x = outsider.identity.x_public();
    p.signature = outsider.identity.sign(&sig_msg_for_test(&p, &ad_group()));
    let forged = wire::frame(t, &p).unwrap();
    assert!(admin.try_recv(&forged).is_err());
}

#[test]
fn initiate_rejects_foreign_card() {
    // `my_card` must belong to the initiating identity: passing someone
    // else's card must fail instead of silently mis-binding the session.
    let mut a = Party::new(&[1u8; 32]);
    let mut b = Party::new(&[2u8; 32]);
    let _card_a = a.new_card();
    let card_b = b.new_card();
    // honest use works
    assert!(handshake::initiate(&a.identity, &_card_a, &card_b).is_ok());
    // presenting Bob's card as ours is rejected
    assert!(handshake::initiate(&a.identity, &card_b, &card_b).is_err());
}

#[test]
fn forged_ratchet_header_does_not_poison_session() {
    // A header advertising an attacker-chosen ratchet key must not desync
    // the session: the DH step is committed only after AEAD success.
    // Otherwise one forged packet permanently diverges rk and kills the
    // session (both directions, forever).
    let mut a = Party::new(&[30u8; 32]);
    let mut b = Party::new(&[31u8; 32]);
    let card_a = a.new_card();
    let card_b = b.new_card();
    let mut sa = handshake::initiate(&a.identity, &card_a, &card_b).unwrap();
    let env0 = message::encrypt_pair(&mut sa, b"zero").unwrap();
    a.sessions.push(sa);
    match b.recv(&env0) {
        Inbound::NewSession { session, .. } => b.sessions.push(*session),
        _ => panic!(),
    }
    // confirm the session so b's ratchet is live in both directions
    let r = message::encrypt_pair(&mut b.sessions[0], b"ok").unwrap();
    a.recv(&r);

    // Forged PairMsg: attacker-chosen ratchet key + garbage ciphertext,
    // but the *real* session_id (it's readable in the header).
    let forged = wire::frame(
        EnvType::PairMsg,
        &wire::PairMsgPayload {
            header: alien_core::ratchet::MsgHeader {
                dh: rand::random(),
                n: 0,
                pn: 0,
                session_id: b.sessions[0].session_id,
            },
            nonce: rand::random(),
            ct: vec![0u8; 32],
        },
    )
    .unwrap();
    assert!(b.try_recv(&forged).is_err());

    // The honest channel must survive in both directions.
    let m = message::encrypt_pair(&mut a.sessions[0], b"still alive").unwrap();
    match b.recv(&m) {
        Inbound::PairText { plaintext, .. } => assert_eq!(plaintext, b"still alive"),
        _ => panic!("session killed by forged header"),
    }
    let m2 = message::encrypt_pair(&mut b.sessions[0], b"ack").unwrap();
    match a.recv(&m2) {
        Inbound::PairText { plaintext, .. } => assert_eq!(plaintext, b"ack"),
        _ => panic!("reverse direction killed by forged header"),
    }
}

#[test]
fn pairinit_replay_after_bundle_pruned_fails() {
    // Once the consumed one-time prekey bundle has been dropped, a replay of
    // the same PairInit must fail outright — no second session, no plaintext.
    let mut a = Party::new(&[24u8; 32]);
    let mut b = Party::new(&[25u8; 32]);
    let card_a = a.new_card();
    let card_b = b.new_card();
    let mut sa = handshake::initiate(&a.identity, &card_a, &card_b).unwrap();
    let env = message::encrypt_pair(&mut sa, b"first").unwrap();
    a.sessions.push(sa);

    match b.recv(&env) {
        Inbound::NewSession { session, .. } => b.sessions.push(*session),
        _ => panic!(),
    }
    // Simulate the FFI/app dropping the consumed bundle, then replay.
    b.bundles.clear();
    assert!(b.try_recv(&env).is_err());
    assert_eq!(b.sessions.len(), 1);
}

// helpers mirroring production framing for forgery tests
fn ad_group() -> [u8; 3] {
    [wire::MAGIC, wire::VERSION, EnvType::GroupMsg as u8]
}

fn sig_msg_for_test(p: &wire::GroupMsgPayload, ad: &[u8; 3]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"AlienMsg/GroupSig/v1");
    v.extend_from_slice(ad);
    v.extend_from_slice(&p.group_id);
    v.extend_from_slice(&p.epoch.to_be_bytes());
    v.extend_from_slice(&p.sender);
    v.extend_from_slice(&p.n.to_be_bytes());
    v.extend_from_slice(&p.nonce);
    v.extend_from_slice(&p.ct);
    v
}
