//! C ABI for the Flutter app. One entry point:
//!
//! ```c
//! AlienBuf* alien_invoke(const uint8_t* req, uintptr_t req_len);
//! void      alien_free_buf(AlienBuf* buf);
//! ```
//!
//! `req` is UTF-8 JSON: `{"op": "...", ...}`. Response is UTF-8 JSON:
//! `{"ok": true, ...}` or `{"ok": false, "error": "..."}`.
//! Binary values are base64 strings. Sessions/groups/bundles/identity are
//! opaque blobs passed back and forth — the library is stateless except for
//! open vault handles.

use alien_core::card::{CardBundle, ContactCard};
use alien_core::group::GroupState;
use alien_core::identity::Identity;
use alien_core::message::{self, Inbound};
use alien_core::ratchet::SessionState;
use alien_core::{handshake, recovery};
use alien_store::Vault;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

#[repr(C)]
pub struct AlienBuf {
    pub ptr: *mut u8,
    pub len: usize,
}

static VAULTS: OnceLock<Mutex<HashMap<u64, Vault>>> = OnceLock::new();
static NEXT_HANDLE: OnceLock<Mutex<u64>> = OnceLock::new();

fn vaults() -> &'static Mutex<HashMap<u64, Vault>> {
    VAULTS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[no_mangle]
pub extern "C" fn alien_invoke(req: *const u8, req_len: usize) -> *mut AlienBuf {
    let out = if req.is_null() || req_len == 0 {
        r#"{"ok":false,"error":"empty request"}"#.to_string()
    } else {
        let slice = unsafe { std::slice::from_raw_parts(req, req_len) };
        match catch_unwind(AssertUnwindSafe(|| dispatch(slice))) {
            Ok(s) => s,
            Err(_) => r#"{"ok":false,"error":"internal panic"}"#.to_string(),
        }
    };
    let bytes = out.into_bytes();
    let b = Box::new(AlienBuf {
        len: bytes.len(),
        ptr: Box::into_raw(bytes.into_boxed_slice()) as *mut u8,
    });
    Box::into_raw(b)
}

#[no_mangle]
pub extern "C" fn alien_free_buf(buf: *mut AlienBuf) {
    if buf.is_null() {
        return;
    }
    unsafe {
        let b = Box::from_raw(buf);
        if !b.ptr.is_null() && b.len > 0 {
            drop(Box::from_raw(std::slice::from_raw_parts_mut(b.ptr, b.len)));
        }
    }
}

fn dispatch(raw: &[u8]) -> String {
    let req: Value = match serde_json::from_slice(raw) {
        Ok(v) => v,
        Err(_) => return r#"{"ok":false,"error":"bad json"}"#.to_string(),
    };
    match run(&req) {
        Ok(v) => {
            let mut o = v;
            o["ok"] = json!(true);
            o.to_string()
        }
        Err(e) => json!({"ok": false, "error": e}).to_string(),
    }
}

fn err<T>(m: impl std::fmt::Display) -> Result<T, String> {
    Err(m.to_string())
}

fn get_str<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v.get(k).and_then(|x| x.as_str()).ok_or_else(|| format!("missing '{k}'"))
}

fn get_b64(v: &Value, k: &str) -> Result<Vec<u8>, String> {
    let s = get_str(v, k)?;
    B64.decode(s).map_err(|_| "bad base64".to_string())
}

fn b64(d: &[u8]) -> Value {
    json!(B64.encode(d))
}

fn hex(d: &[u8]) -> Value {
    json!(d.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn parse_identity(v: &Value, k: &str) -> Result<Identity, String> {
    // The identity blob IS the 32-byte recovery seed (from `identity_create`).
    let raw = get_b64(v, k)?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| "bad identity blob".to_string())?;
    Identity::from_seed(&arr).map_err(|e| e.to_string())
}

fn parse_sessions(v: &Value, k: &str) -> Result<Vec<SessionState>, String> {
    let arr = v.get(k).and_then(|x| x.as_array()).cloned().unwrap_or_default();
    let mut out = Vec::with_capacity(arr.len());
    for s in arr {
        let raw = B64
            .decode(s.as_str().unwrap_or(""))
            .map_err(|_| "bad session b64")?;
        out.push(SessionState::from_bytes(&raw).map_err(|e| e.to_string())?);
    }
    Ok(out)
}

fn parse_groups(v: &Value, k: &str) -> Result<Vec<GroupState>, String> {
    let arr = v.get(k).and_then(|x| x.as_array()).cloned().unwrap_or_default();
    let mut out = Vec::with_capacity(arr.len());
    for s in arr {
        let raw = B64
            .decode(s.as_str().unwrap_or(""))
            .map_err(|_| "bad group b64")?;
        out.push(GroupState::from_bytes(&raw).map_err(|e| e.to_string())?);
    }
    Ok(out)
}

fn sessions_json(v: &[SessionState]) -> Result<Value, String> {
    let mut arr = Vec::with_capacity(v.len());
    for s in v {
        arr.push(json!(B64.encode(s.to_bytes().map_err(|e| e.to_string())?)));
    }
    Ok(json!(arr))
}

fn groups_json(v: &[GroupState]) -> Result<Value, String> {
    let mut arr = Vec::with_capacity(v.len());
    for g in v {
        arr.push(json!(B64.encode(g.to_bytes().map_err(|e| e.to_string())?)));
    }
    Ok(json!(arr))
}

fn run(v: &Value) -> Result<Value, String> {
    let op = get_str(v, "op")?;
    match op {
        "mnemonic_generate" => {
            let m = recovery::generate_mnemonic().map_err(|e| e.to_string())?;
            Ok(json!({"mnemonic": m}))
        }
        "mnemonic_validate" => {
            let phrase = get_str(v, "phrase")?;
            Ok(json!({"valid": recovery::validate_mnemonic(phrase)}))
        }
        "identity_create" => {
            let phrase = get_str(v, "mnemonic")?;
            let pass = v.get("passphrase").and_then(|x| x.as_str()).unwrap_or("");
            let seed = recovery::seed_from_mnemonic(phrase, pass).map_err(|e| e.to_string())?;
            let id = Identity::from_seed(&seed).map_err(|e| e.to_string())?;
            Ok(json!({
                "identity": b64(&seed),
                "pub_id": hex(&id.public_id()),
                "ed_pub": hex(&id.ed_public()),
                "x_pub": hex(&id.x_public()),
            }))
        }
        "card_create" => {
            let id = parse_identity(v, "identity")?;
            let bundle = alien_core::card::create_card(&id);
            let card_env = message::encode_card(&bundle.card).map_err(|e| e.to_string())?;
            Ok(json!({
                "card_envelope": b64(&card_env),
                "card": b64(&bundle.card.to_bytes().map_err(|e| e.to_string())?),
                "bundle": b64(&bundle.to_bytes().map_err(|e| e.to_string())?),
                "card_id": hex(&bundle.card.card_id),
                "owner_id": hex(&bundle.card.owner_id()),
            }))
        }
        "fingerprint" => {
            let id = parse_identity(v, "identity")?;
            let card_raw = get_b64(v, "peer_card")?;
            let card = ContactCard::from_bytes(&card_raw).map_err(|e| e.to_string())?;
            card.verify().map_err(|e| e.to_string())?;
            let sas = handshake::safety_fingerprint(
                &id.public_id(),
                &id.ed_public(),
                &card.owner_id(),
                &card.identity_ed,
            );
            Ok(json!({"sas": sas}))
        }
        "session_start" => {
            let id = parse_identity(v, "identity")?;
            let my_card_raw = get_b64(v, "my_card")?;
            let my_card = ContactCard::from_bytes(&my_card_raw).map_err(|e| e.to_string())?;
            let peer_raw = get_b64(v, "peer_card")?;
            let peer = ContactCard::from_bytes(&peer_raw).map_err(|e| e.to_string())?;
            let s = handshake::initiate(&id, &my_card, &peer).map_err(|e| e.to_string())?;
            Ok(json!({
                "session": b64(&s.to_bytes().map_err(|e| e.to_string())?),
                "session_id": hex(&s.session_id),
                "peer_id": hex(&s.peer_id),
            }))
        }
        "encrypt" => {
            let mut s = SessionState::from_bytes(&get_b64(v, "session")?)
                .map_err(|e| e.to_string())?;
            let pt = get_str(v, "plaintext")?.as_bytes().to_vec();
            let env = message::encrypt_pair(&mut s, &pt).map_err(|e| e.to_string())?;
            Ok(json!({
                "session": b64(&s.to_bytes().map_err(|e| e.to_string())?),
                "envelope": b64(&env),
            }))
        }
        "decrypt" => {
            let id = parse_identity(v, "identity")?;
            let bundle_arr = v.get("bundles").and_then(|x| x.as_array()).cloned().unwrap_or_default();
            let mut bundles = Vec::new();
            for b in bundle_arr {
                let raw = B64.decode(b.as_str().unwrap_or("")).map_err(|_| "bad bundle b64")?;
                bundles.push(CardBundle::from_bytes(&raw).map_err(|e| e.to_string())?);
            }
            let mut sessions = parse_sessions(v, "sessions")?;
            let mut groups = parse_groups(v, "groups")?;
            let env = get_b64(v, "envelope")?;

            match message::decrypt_any(&id, &bundles, &mut sessions, &mut groups, &env)
                .map_err(|e| e.to_string())?
            {
                Inbound::Card(card) => Ok(json!({
                    "kind": "card",
                    "card": b64(&card.to_bytes().map_err(|e| e.to_string())?),
                    "owner_id": hex(&card.owner_id()),
                    "card_id": hex(&card.card_id),
                })),
                Inbound::NewSession { session, plaintext } => Ok(json!({
                    "kind": "new_session",
                    "session": b64(&session.to_bytes().map_err(|e| e.to_string())?),
                    "peer_id": hex(&session.peer_id),
                    "peer_ed": hex(&session.peer_ed),
                    "plaintext": String::from_utf8_lossy(&plaintext),
                })),
                Inbound::PairText { session_index, plaintext } => {
                    let s = sessions[session_index].to_bytes().map_err(|e| e.to_string())?;
                    let peer = sessions[session_index].peer_id;
                    Ok(json!({
                        "kind": "pair",
                        "session_index": session_index,
                        "peer_id": hex(&peer),
                        "session": b64(&s),
                        "sessions": sessions_json(&sessions)?,
                        "plaintext": String::from_utf8_lossy(&plaintext),
                    }))
                }
                Inbound::GroupJoined(g) => Ok(json!({
                    "kind": "group_joined",
                    "group": b64(&g.to_bytes().map_err(|e| e.to_string())?),
                    "group_id": hex(&g.group_id),
                    "sessions": sessions_json(&sessions)?,
                })),
                Inbound::GroupRotated { group_index } => Ok(json!({
                    "kind": "group_rotated",
                    "group_index": group_index,
                    "groups": groups_json(&groups)?,
                    "sessions": sessions_json(&sessions)?,
                })),
                Inbound::GroupText { group_index, sender, plaintext } => Ok(json!({
                    "kind": "group_text",
                    "group_index": group_index,
                    "sender": hex(&sender),
                    "groups": groups_json(&groups)?,
                    "plaintext": String::from_utf8_lossy(&plaintext),
                })),
            }
        }
        "group_create" => {
            let id = parse_identity(v, "identity")?;
            let mut sessions = parse_sessions(v, "sessions")?;
            let members: Vec<[u8; 32]> = v
                .get("member_ids")
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default()
                .iter()
                .filter_map(|h| {
                    let h = h.as_str()?;
                    let raw = hex_decode(h)?;
                    <[u8; 32]>::try_from(raw.as_slice()).ok()
                })
                .collect();
            let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("");
            let (g, env) = message::group_create(&id, &mut sessions, &members, name)
                .map_err(|e| e.to_string())?;
            Ok(json!({
                "group": b64(&g.to_bytes().map_err(|e| e.to_string())?),
                "group_id": hex(&g.group_id),
                "envelope": b64(&env),
                "sessions": sessions_json(&sessions)?,
            }))
        }
        "group_rotate" => {
            let id = parse_identity(v, "identity")?;
            let mut g = GroupState::from_bytes(&get_b64(v, "group")?).map_err(|e| e.to_string())?;
            let mut sessions = parse_sessions(v, "sessions")?;
            let members: Vec<[u8; 32]> = v
                .get("new_members")
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default()
                .iter()
                .filter_map(|h| {
                    let h = h.as_str()?;
                    let raw = hex_decode(h)?;
                    <[u8; 32]>::try_from(raw.as_slice()).ok()
                })
                .collect();
            let env =
                message::group_rotate(&id, &mut g, &mut sessions, members).map_err(|e| e.to_string())?;
            Ok(json!({
                "group": b64(&g.to_bytes().map_err(|e| e.to_string())?),
                "envelope": b64(&env),
                "sessions": sessions_json(&sessions)?,
            }))
        }
        "group_encrypt" => {
            let mut g = GroupState::from_bytes(&get_b64(v, "group")?).map_err(|e| e.to_string())?;
            let pt = get_str(v, "plaintext")?.as_bytes().to_vec();
            let env = message::encrypt_group(&mut g, &pt).map_err(|e| e.to_string())?;
            Ok(json!({
                "group": b64(&g.to_bytes().map_err(|e| e.to_string())?),
                "envelope": b64(&env),
            }))
        }
        "group_info" => {
            let g = GroupState::from_bytes(&get_b64(v, "group")?).map_err(|e| e.to_string())?;
            let members: Vec<Value> = g
                .members
                .iter()
                .map(|m| json!({"id": hex(m), "is_me": *m == g.my_id, "is_admin": *m == g.admin}))
                .collect();
            Ok(json!({
                "group_id": hex(&g.group_id),
                "epoch": g.epoch,
                "name": g.name,
                "members": members,
            }))
        }
        "render" => {
            let raw = get_b64(v, "bytes")?;
            let fmt = match get_str(v, "format")? {
                "emoji" => alien_codec::Format::Emoji,
                "words" => alien_codec::Format::Words,
                _ => alien_codec::Format::Blob,
            };
            Ok(json!({"text": alien_codec::encode(&raw, fmt)}))
        }
        "unrender" => {
            let text = get_str(v, "text")?;
            let raw = alien_codec::decode(text).map_err(|e| e.to_string())?;
            Ok(json!({"bytes": b64(&raw)}))
        }
        "vault_open" => {
            let path = PathBuf::from(get_str(v, "path")?);
            let pass = v.get("password").and_then(|x| x.as_str()).unwrap_or("");
            let vault = Vault::open(&path, pass).map_err(|e| e.to_string())?;
            let mut nh = NEXT_HANDLE.get_or_init(|| Mutex::new(1)).lock().unwrap();
            let h = *nh;
            *nh += 1;
            vaults().lock().unwrap().insert(h, vault);
            Ok(json!({"handle": h}))
        }
        "vault_set" => {
            let h = v.get("handle").and_then(|x| x.as_u64()).ok_or("missing handle")?;
            let key = get_str(v, "key")?;
            let val = get_b64(v, "value")?;
            let mut m = vaults().lock().unwrap();
            let vault = m.get_mut(&h).ok_or("bad vault handle")?;
            vault.set(key, &val);
            Ok(json!({}))
        }
        "vault_get" => {
            let h = v.get("handle").and_then(|x| x.as_u64()).ok_or("missing handle")?;
            let key = get_str(v, "key")?;
            let m = vaults().lock().unwrap();
            let vault = m.get(&h).ok_or("bad vault handle")?;
            match vault.get(key) {
                Some(d) => Ok(json!({"value": b64(d)})),
                None => Ok(json!({"value": Value::Null})),
            }
        }
        "vault_list" => {
            let h = v.get("handle").and_then(|x| x.as_u64()).ok_or("missing handle")?;
            let prefix = v.get("prefix").and_then(|x| x.as_str()).unwrap_or("");
            let m = vaults().lock().unwrap();
            let vault = m.get(&h).ok_or("bad vault handle")?;
            Ok(json!({"keys": vault.keys_with_prefix(prefix)}))
        }
        "vault_remove" => {
            let h = v.get("handle").and_then(|x| x.as_u64()).ok_or("missing handle")?;
            let key = get_str(v, "key")?;
            let mut m = vaults().lock().unwrap();
            let vault = m.get_mut(&h).ok_or("bad vault handle")?;
            vault.remove(key);
            Ok(json!({}))
        }
        "vault_save" => {
            let h = v.get("handle").and_then(|x| x.as_u64()).ok_or("missing handle")?;
            let path = PathBuf::from(get_str(v, "path")?);
            let m = vaults().lock().unwrap();
            let vault = m.get(&h).ok_or("bad vault handle")?;
            vault.save(&path).map_err(|e| e.to_string())?;
            Ok(json!({}))
        }
        "vault_close" => {
            let h = v.get("handle").and_then(|x| x.as_u64()).ok_or("missing handle")?;
            vaults().lock().unwrap().remove(&h);
            Ok(json!({}))
        }
        _ => err(format!("unknown op '{op}'")),
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
