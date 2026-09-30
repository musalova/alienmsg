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
        Inbound::NewSession { session, plaintext } => {
            assert_eq!(plaintext, b"ciao bob");
            b.sessions.push(session);
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
        Inbound::NewSession { session, .. } => b.sessions.push(session),
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
            Inbound::NewSession { session, .. } => member.sessions.push(session),
            _ => panic!(),
        }
        // member replies so admin's session is confirmed
        let e = message::encrypt_pair(&mut member.sessions[0], b"hi back").unwrap();
        admin.try_recv(&e).ok();
    }

    let m1_id = m1.identity.public_id();
    let m2_id = m2.identity.public_id();

    // admin creates group with m1 and m2
    let (g, invite_env) =
        message::group_create(&admin.identity, &mut admin.sessions, &[m1_id, m2_id], "test")
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
    let e = message::encrypt_group(&mut m1.groups[0], b"group hello").unwrap();
    match admin.recv(&e) {
        Inbound::GroupText { plaintext, sender, .. } => {
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
    let e_new = message::encrypt_group(&mut m1.groups[0], b"secret post-kick").unwrap();
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
