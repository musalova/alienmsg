//! End-to-end test of the JSON FFI surface: two virtual devices pairing,
//! exchanging messages and running a group — entirely through `alien_invoke`.

use alien_ffi::alien_invoke;
use serde_json::{json, Value};

fn invoke(req: Value) -> Value {
    let s = req.to_string();
    let buf = alien_invoke(s.as_ptr(), s.len());
    assert!(!buf.is_null());
    unsafe {
        let b = &*buf;
        let bytes = std::slice::from_raw_parts(b.ptr, b.len);
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        alien_ffi::alien_free_buf(buf);
        serde_json::from_str(&text).unwrap()
    }
}

fn ok(req: Value) -> Value {
    let r = invoke(req);
    assert_eq!(r["ok"], json!(true), "call failed: {r}");
    r
}

struct Device {
    identity: String,
    bundles: Vec<String>,
    sessions: Vec<String>,
    groups: Vec<String>,
}

impl Device {
    fn new(seed_phrase: &str) -> Device {
        let r = ok(json!({"op":"identity_create","mnemonic":seed_phrase}));
        Device {
            identity: r["identity"].as_str().unwrap().to_string(),
            bundles: vec![],
            sessions: vec![],
            groups: vec![],
        }
    }
    fn make_card(&mut self) -> (String, String) {
        let r = ok(json!({"op":"card_create","identity":self.identity}));
        self.bundles.push(r["bundle"].as_str().unwrap().to_string());
        (r["card_envelope"].as_str().unwrap().to_string(),
         r["card"].as_str().unwrap().to_string())
    }
    fn recv(&mut self, env_b64: &str) -> Value {
        let r = ok(json!({
            "op":"decrypt","identity":self.identity,
            "bundles":self.bundles,"sessions":self.sessions,
            "groups":self.groups,"envelope":env_b64}));
        // write back any state updates
        if let Some(s) = r.get("sessions").and_then(|x| x.as_array()) {
            self.sessions = s.iter().map(|v| v.as_str().unwrap().to_string()).collect();
        }
        if let Some(g) = r.get("groups").and_then(|x| x.as_array()) {
            self.groups = g.iter().map(|v| v.as_str().unwrap().to_string()).collect();
        }
        r
    }
}

#[test]
fn ffi_full_flow() {
    // --- setup two devices
    let m1 = ok(json!({"op":"mnemonic_generate"}))["mnemonic"]
        .as_str().unwrap().to_string();
    let m2 = ok(json!({"op":"mnemonic_generate"}))["mnemonic"]
        .as_str().unwrap().to_string();
    assert!(ok(json!({"op":"mnemonic_validate","phrase":m1}))["valid"].as_bool().unwrap());

    let mut alice = Device::new(&m1);
    let mut bob = Device::new(&m2);

    // --- exchange cards
    let (card_a_env, card_a) = alice.make_card();
    let (_card_b_env, card_b) = bob.make_card();

    // render card as blob text -> unrender back to envelope
    let txt_a = ok(json!({"op":"render","bytes":card_a_env,"format":"blob"}))["text"]
        .as_str().unwrap().to_string();
    assert!(txt_a.starts_with("AYA1:"));
    let env_a = ok(json!({"op":"unrender","text":txt_a}))["bytes"].as_str().unwrap().to_string();
    assert_eq!(env_a, card_a_env);

    let card_a_parsed = bob.recv(&env_a);
    assert_eq!(card_a_parsed["kind"], "card");

    // --- alice starts session toward bob
    let s = ok(json!({
        "op":"session_start","identity":alice.identity,
        "my_card":card_a,"peer_card":card_b}));
    alice.sessions.push(s["session"].as_str().unwrap().to_string());

    // --- alice encrypts first message (PairInit), renders as emoji
    let e = ok(json!({
        "op":"encrypt","session":alice.sessions[0],"plaintext":"ciao bob"}));
    alice.sessions[0] = e["session"].as_str().unwrap().to_string();
    let env_b64 = e["envelope"].as_str().unwrap().to_string();
    let txt = ok(json!({"op":"render","bytes":env_b64,"format":"emoji"}))["text"]
        .as_str().unwrap().to_string();
    assert!(txt.starts_with('👽'));

    // bob unrenders + decrypts
    let env2 = ok(json!({"op":"unrender","text":txt}))["bytes"].as_str().unwrap().to_string();
    let d = bob.recv(&env2);
    assert_eq!(d["kind"], "new_session");
    assert_eq!(d["plaintext"], "ciao bob");
    bob.sessions.push(d["session"].as_str().unwrap().to_string());

    // bob replies
    let e2 = ok(json!({
        "op":"encrypt","session":bob.sessions[0],"plaintext":"ciao alice"}));
    bob.sessions[0] = e2["session"].as_str().unwrap().to_string();
    let d2 = alice.recv(e2["envelope"].as_str().unwrap());
    assert_eq!(d2["kind"], "pair");
    assert_eq!(d2["plaintext"], "ciao alice");

    // --- group: admin alice, member bob
    let bob_id = d2["peer_id"].as_str().unwrap().to_string(); // alice sees bob's peer id
    let gc = ok(json!({
        "op":"group_create","identity":alice.identity,
        "sessions":alice.sessions,"member_ids":[bob_id],"name":"nucleo"}));
    alice.sessions = gc["sessions"].as_array().unwrap()
        .iter().map(|v| v.as_str().unwrap().to_string()).collect();
    alice.groups.push(gc["group"].as_str().unwrap().to_string());
    let invite = gc["envelope"].as_str().unwrap().to_string();

    let dj = bob.recv(&invite);
    assert_eq!(dj["kind"], "group_joined");
    bob.groups.push(dj["group"].as_str().unwrap().to_string());

    // bob sends group message
    let ge = ok(json!({
        "op":"group_encrypt","group":bob.groups[0],"plaintext":"segreto di gruppo"}));
    bob.groups[0] = ge["group"].as_str().unwrap().to_string();
    let dg = alice.recv(ge["envelope"].as_str().unwrap());
    assert_eq!(dg["kind"], "group_text");
    assert_eq!(dg["plaintext"], "segreto di gruppo");
}
