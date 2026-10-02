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
use zeroize::Zeroize;

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

/// # Safety
/// `req` must point to `req_len` readable bytes for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn alien_invoke(req: *const u8, req_len: usize) -> *mut AlienBuf {
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

/// # Safety
/// `buf` must be a pointer previously returned by [`alien_invoke`], at most once.
#[no_mangle]
pub unsafe extern "C" fn alien_free_buf(buf: *mut AlienBuf) {
    if buf.is_null() {
        return;
    }
    let b = Box::from_raw(buf);
    if !b.ptr.is_null() && b.len > 0 {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            b.ptr, b.len,
        )));
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
    v.get(k)
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("missing '{k}'"))
}

/// Plaintext may arrive as UTF-8 (`plaintext`) or raw bytes (`plaintext_b64`)
/// so binary payloads survive the JSON boundary untouched.
fn get_plaintext(v: &Value) -> Result<Vec<u8>, String> {
    if let Some(b) = v.get("plaintext_b64").and_then(|x| x.as_str()) {
        B64.decode(b).map_err(|_| "bad plaintext_b64".to_string())
    } else {
        Ok(get_str(v, "plaintext")?.as_bytes().to_vec())
    }
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
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| "bad identity blob".to_string())?;
    Identity::from_seed(&arr).map_err(|e| e.to_string())
}

fn parse_sessions(v: &Value, k: &str) -> Result<Vec<SessionState>, String> {
    let arr = v
        .get(k)
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::with_capacity(arr.len());
    for s in arr {
        let raw = B64
            .decode(s.as_str().unwrap_or(""))
            .map_err(|_| "bad session b64")?;
        out.push(SessionState::from_bytes(&raw).map_err(|e| e.to_string())?);
    }
    Ok(out)
}

/// Parse a JSON array of 64-hex pub_ids. Strict: a malformed entry is an
/// error, not silently dropped — a silently-missing member would otherwise
/// be excluded from the group without the admin noticing.
fn parse_hex32_array(v: &Value, k: &str) -> Result<Vec<[u8; 32]>, String> {
    let arr = v
        .get(k)
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let h = item
            .as_str()
            .ok_or_else(|| format!("'{k}' item not a string"))?;
        let raw = hex_decode(h).ok_or_else(|| format!("'{k}' bad hex"))?;
        out.push(<[u8; 32]>::try_from(raw.as_slice()).map_err(|_| format!("'{k}' wrong length"))?);
    }
    Ok(out)
}

fn parse_groups(v: &Value, k: &str) -> Result<Vec<GroupState>, String> {
    let arr = v
        .get(k)
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
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

/// Serialize info about a session created inside a group invite/rotate wrap
/// (inner `PairInit`): the Dart side uses it to attach the session to the
/// admin's contact (or create that contact) and drop the consumed bundle.
fn inner_session_json(
    s: &alien_core::message::InnerSession,
    sessions: &[SessionState],
) -> Result<Value, String> {
    let sess = &sessions[s.session_index];
    Ok(json!({
        "session_index": s.session_index,
        "session": b64(&sess.to_bytes().map_err(|e| e.to_string())?),
        "session_id": hex(&sess.session_id),
        "peer_id": hex(&sess.peer_id),
        "peer_ed": hex(&sess.peer_ed),
        "peer_card": b64(&s.peer_card.to_bytes().map_err(|e| e.to_string())?),
        "consumed_bundle": s.bundle_index,
    }))
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
        "random_bytes" => {
            let n = v.get("n").and_then(|x| x.as_u64()).unwrap_or(32) as usize;
            if n == 0 || n > 4096 {
                return err("bad n");
            }
            let mut buf = vec![0u8; n];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut buf);
            Ok(json!({"bytes": b64(&buf)}))
        }
        "dpapi_wrap" => {
            let raw = get_b64(v, "data")?;
            Ok(json!({"wrapped": b64(&dpapi_wrap(&raw)?)}))
        }
        "dpapi_unwrap" => {
            let raw = get_b64(v, "data")?;
            Ok(json!({"bytes": b64(&dpapi_unwrap(&raw)?)}))
        }
        "pin_wrap" => {
            let pin = get_str(v, "pin")?;
            let raw = get_b64(v, "data")?;
            let blob = alien_store::pin_wrap(pin, &raw).map_err(|e| e.to_string())?;
            Ok(json!({"wrapped": b64(&blob)}))
        }
        "pin_unwrap" => {
            let pin = get_str(v, "pin")?;
            let raw = get_b64(v, "data")?;
            let pt = alien_store::pin_unwrap(pin, &raw).map_err(|e| e.to_string())?;
            Ok(json!({"bytes": b64(&pt)}))
        }
        "identity_create" => {
            // Two ways to create an identity:
            //  - mnemonic + optional passphrase (recovery-friendly)
            //  - seed_b64: caller-supplied 32-byte seed (device-bound profile,
            //    no words to remember)
            let mut seed = if let Some(s) = v.get("seed_b64").and_then(|x| x.as_str()) {
                let raw = B64.decode(s).map_err(|_| "bad seed_b64")?;
                <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| "seed_b64 must be 32 bytes")?
            } else {
                let phrase = get_str(v, "mnemonic")?;
                let pass = v.get("passphrase").and_then(|x| x.as_str()).unwrap_or("");
                recovery::seed_from_mnemonic(phrase, pass).map_err(|e| e.to_string())?
            };
            let id = Identity::from_seed(&seed).map_err(|e| e.to_string())?;
            let resp = json!({
                "identity": b64(&seed),
                "pub_id": hex(&id.public_id()),
                "ed_pub": hex(&id.ed_public()),
                "x_pub": hex(&id.x_public()),
            });
            seed.zeroize();
            Ok(resp)
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
            let mut s =
                SessionState::from_bytes(&get_b64(v, "session")?).map_err(|e| e.to_string())?;
            let pt = get_plaintext(v)?;
            let env = message::encrypt_pair(&mut s, &pt).map_err(|e| e.to_string())?;
            Ok(json!({
                "session": b64(&s.to_bytes().map_err(|e| e.to_string())?),
                "envelope": b64(&env),
            }))
        }
        "decrypt" => {
            let id = parse_identity(v, "identity")?;
            let bundle_arr = v
                .get("bundles")
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default();
            let mut bundles = Vec::new();
            for b in bundle_arr {
                let raw = B64
                    .decode(b.as_str().unwrap_or(""))
                    .map_err(|_| "bad bundle b64")?;
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
                Inbound::NewSession {
                    session,
                    plaintext,
                    peer_card,
                    bundle_index,
                } => Ok(json!({
                    "kind": "new_session",
                    "session": b64(&session.to_bytes().map_err(|e| e.to_string())?),
                    "session_id": hex(&session.session_id),
                    "peer_id": hex(&session.peer_id),
                    "peer_ed": hex(&session.peer_ed),
                    "peer_card": b64(&peer_card.to_bytes().map_err(|e| e.to_string())?),
                    "consumed_bundle": bundle_index,
                    "plaintext": String::from_utf8_lossy(&plaintext),
                    "plaintext_b64": b64(&plaintext),
                })),
                Inbound::PairText {
                    session_index,
                    plaintext,
                } => {
                    let s = sessions[session_index]
                        .to_bytes()
                        .map_err(|e| e.to_string())?;
                    let peer = sessions[session_index].peer_id;
                    Ok(json!({
                        "kind": "pair",
                        "session_index": session_index,
                        "peer_id": hex(&peer),
                        "session": b64(&s),
                        "sessions": sessions_json(&sessions)?,
                        "plaintext": String::from_utf8_lossy(&plaintext),
                        "plaintext_b64": b64(&plaintext),
                    }))
                }
                Inbound::GroupJoined {
                    group,
                    inner_session,
                } => {
                    let mut o = json!({
                        "kind": "group_joined",
                        "group": b64(&group.to_bytes().map_err(|e| e.to_string())?),
                        "group_id": hex(&group.group_id),
                        "name": group.name,
                        "sessions": sessions_json(&sessions)?,
                    });
                    if let Some(s) = inner_session {
                        o["inner_session"] = inner_session_json(&s, &sessions)?;
                    }
                    Ok(o)
                }
                Inbound::GroupRotated {
                    group_index,
                    inner_session,
                } => {
                    let mut o = json!({
                        "kind": "group_rotated",
                        "group_index": group_index,
                        "groups": groups_json(&groups)?,
                        "sessions": sessions_json(&sessions)?,
                    });
                    if let Some(s) = inner_session {
                        o["inner_session"] = inner_session_json(&s, &sessions)?;
                    }
                    Ok(o)
                }
                Inbound::GroupText {
                    group_index,
                    sender,
                    plaintext,
                } => Ok(json!({
                    "kind": "group_text",
                    "group_index": group_index,
                    "sender": hex(&sender),
                    "groups": groups_json(&groups)?,
                    "plaintext": String::from_utf8_lossy(&plaintext),
                    "plaintext_b64": b64(&plaintext),
                })),
            }
        }
        "group_create" => {
            let id = parse_identity(v, "identity")?;
            let mut sessions = parse_sessions(v, "sessions")?;
            let members = parse_hex32_array(v, "member_ids")?;
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
            let members = parse_hex32_array(v, "new_members")?;
            let env = message::group_rotate(&id, &mut g, &mut sessions, members)
                .map_err(|e| e.to_string())?;
            Ok(json!({
                "group": b64(&g.to_bytes().map_err(|e| e.to_string())?),
                "envelope": b64(&env),
                "sessions": sessions_json(&sessions)?,
            }))
        }
        "group_encrypt" => {
            let id = parse_identity(v, "identity")?;
            let mut g = GroupState::from_bytes(&get_b64(v, "group")?).map_err(|e| e.to_string())?;
            let pt = get_plaintext(v)?;
            let env = message::encrypt_group(&id, &mut g, &pt).map_err(|e| e.to_string())?;
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
                "frasi" => alien_codec::Format::Frasi,
                _ => alien_codec::Format::Blob,
            };
            Ok(json!({"text": alien_codec::encode(&raw, fmt)}))
        }
        "unrender" => {
            let text = get_str(v, "text")?;
            let raw = alien_codec::decode(text).map_err(|e| e.to_string())?;
            // Everything we render is a framed wire envelope: reject anything
            // else up front so callers get "not an AlienMsg code" instead of
            // an opaque deserialize/decrypt error on prose that happened to
            // decode (every-Italian-word text is legal `frasi` input).
            alien_core::wire::unframe(&raw).map_err(|_| "not an AlienMsg code")?;
            Ok(json!({"bytes": b64(&raw)}))
        }
        "vault_open" => {
            let path = PathBuf::from(get_str(v, "path")?);
            let pass = v.get("password").and_then(|x| x.as_str()).unwrap_or("");
            let vault = Vault::open(&path, pass).map_err(|e| e.to_string())?;
            let protected = vault.is_protected();
            let mut nh = NEXT_HANDLE.get_or_init(|| Mutex::new(1)).lock().unwrap();
            let h = *nh;
            *nh += 1;
            vaults().lock().unwrap().insert(h, vault);
            Ok(json!({"handle": h, "protected": protected}))
        }
        "vault_probe" => {
            let path = PathBuf::from(get_str(v, "path")?);
            let p = alien_store::probe(&path).map_err(|e| e.to_string())?;
            Ok(json!({
                "exists": p.exists,
                "needs_password": p.needs_password,
            }))
        }
        "vault_set" => {
            let h = v
                .get("handle")
                .and_then(|x| x.as_u64())
                .ok_or("missing handle")?;
            let key = get_str(v, "key")?;
            let val = get_b64(v, "value")?;
            let mut m = vaults().lock().unwrap();
            let vault = m.get_mut(&h).ok_or("bad vault handle")?;
            vault.set(key, &val);
            Ok(json!({}))
        }
        "vault_get" => {
            let h = v
                .get("handle")
                .and_then(|x| x.as_u64())
                .ok_or("missing handle")?;
            let key = get_str(v, "key")?;
            let m = vaults().lock().unwrap();
            let vault = m.get(&h).ok_or("bad vault handle")?;
            match vault.get(key) {
                Some(d) => Ok(json!({"value": b64(d)})),
                None => Ok(json!({"value": Value::Null})),
            }
        }
        "vault_list" => {
            let h = v
                .get("handle")
                .and_then(|x| x.as_u64())
                .ok_or("missing handle")?;
            let prefix = v.get("prefix").and_then(|x| x.as_str()).unwrap_or("");
            let m = vaults().lock().unwrap();
            let vault = m.get(&h).ok_or("bad vault handle")?;
            Ok(json!({"keys": vault.keys_with_prefix(prefix)}))
        }
        "vault_remove" => {
            let h = v
                .get("handle")
                .and_then(|x| x.as_u64())
                .ok_or("missing handle")?;
            let key = get_str(v, "key")?;
            let mut m = vaults().lock().unwrap();
            let vault = m.get_mut(&h).ok_or("bad vault handle")?;
            vault.remove(key);
            Ok(json!({}))
        }
        "vault_save" => {
            let h = v
                .get("handle")
                .and_then(|x| x.as_u64())
                .ok_or("missing handle")?;
            let path = PathBuf::from(get_str(v, "path")?);
            let m = vaults().lock().unwrap();
            let vault = m.get(&h).ok_or("bad vault handle")?;
            vault.save(&path).map_err(|e| e.to_string())?;
            Ok(json!({}))
        }
        "vault_set_password" => {
            let h = v
                .get("handle")
                .and_then(|x| x.as_u64())
                .ok_or("missing handle")?;
            let pass = v.get("password").and_then(|x| x.as_str()).unwrap_or("");
            let path = PathBuf::from(get_str(v, "path")?);
            let mut m = vaults().lock().unwrap();
            let vault = m.get_mut(&h).ok_or("bad vault handle")?;
            vault.set_password(pass).map_err(|e| e.to_string())?;
            vault.save(&path).map_err(|e| e.to_string())?;
            Ok(json!({"protected": !pass.is_empty()}))
        }
        "vault_close" => {
            let h = v
                .get("handle")
                .and_then(|x| x.as_u64())
                .ok_or("missing handle")?;
            vaults().lock().unwrap().remove(&h);
            Ok(json!({}))
        }
        "vault_delete" => {
            let path = PathBuf::from(get_str(v, "path")?);
            alien_store::delete(&path).map_err(|e| e.to_string())?;
            Ok(json!({}))
        }
        "vault_rename" => {
            let from = PathBuf::from(get_str(v, "path")?);
            let to = PathBuf::from(get_str(v, "to")?);
            alien_store::rename(&from, &to).map_err(|e| e.to_string())?;
            Ok(json!({}))
        }
        _ => err(format!("unknown op '{op}'")),
    }
}

/// Wrap secret bytes with Windows DPAPI (CryptProtectData, current-user
/// scope): the output can only be unwrapped by the same Windows user account.
/// This is what binds the vault to the device — a copied file is useless
/// elsewhere.
#[cfg(windows)]
fn dpapi_wrap(data: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        if CryptProtectData(
            &mut input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        ) == 0
        {
            return Err("CryptProtectData failed".into());
        }
        let out = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData.cast());
        Ok(out)
    }
}

#[cfg(windows)]
fn dpapi_unwrap(data: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        if CryptUnprotectData(
            &mut input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        ) == 0
        {
            return Err("CryptUnprotectData failed".into());
        }
        let out = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData.cast());
        Ok(out)
    }
}

#[cfg(not(windows))]
fn dpapi_wrap(_data: &[u8]) -> Result<Vec<u8>, String> {
    Err("dpapi_wrap is only available on Windows".into())
}

#[cfg(not(windows))]
fn dpapi_unwrap(_data: &[u8]) -> Result<Vec<u8>, String> {
    Err("dpapi_unwrap is only available on Windows".into())
}

/// WASM/JS entry point: same JSON contract as `alien_invoke`, but taking and
/// returning `String` so the browser can call it without pointer plumbing.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = alienInvokeJson)]
pub fn alien_invoke_json(req: &str) -> String {
    match catch_unwind(AssertUnwindSafe(|| dispatch(req.as_bytes()))) {
        Ok(s) => s,
        Err(_) => r#"{"ok":false,"error":"internal panic"}"#.to_string(),
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
