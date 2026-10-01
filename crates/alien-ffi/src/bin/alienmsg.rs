//! alienmsg — CLI companion that exercises the exact JSON API used by the app.
//!
//!   alienmsg demo                     # end-to-end demo transcript (2 devices)
//!   alienmsg invoke '<json>'          # raw JSON op, e.g. {"op":"mnemonic_generate"}
//!
//! For interactive use, `demo` prints a full simulated conversation.

use alien_ffi::{alien_free_buf, alien_invoke};
use serde_json::{json, Value};
use std::io::Read;

fn invoke(req: Value) -> Value {
    let s = req.to_string();
    // SAFETY: `s` outlives the call; returned buf is freed below.
    let buf = unsafe { alien_invoke(s.as_ptr(), s.len()) };
    if buf.is_null() {
        return json!({"ok": false, "error": "null buf"});
    }
    unsafe {
        let b = &*buf;
        let bytes = std::slice::from_raw_parts(b.ptr, b.len);
        let text = String::from_utf8_lossy(bytes).to_string();
        alien_free_buf(buf);
        serde_json::from_str(&text).unwrap_or(json!({"ok":false,"error":"bad resp"}))
    }
}

fn ok(req: Value) -> Value {
    let r = invoke(req);
    if r["ok"] != json!(true) {
        eprintln!("ERRORE: {}", r["error"]);
        std::process::exit(1);
    }
    r
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("demo") => demo(),
        Some("invoke") => {
            let payload = if let Some(j) = args.get(2) {
                j.clone()
            } else {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s).unwrap();
                s
            };
            let req: Value = serde_json::from_str(&payload).unwrap_or_else(|_| {
                eprintln!("json non valido");
                std::process::exit(2);
            });
            println!("{}", invoke(req));
        }
        _ => {
            eprintln!(
                "alienmsg — CLI\n\n  demo              demo end-to-end\n  invoke '<json>'   op JSON grezza (o da stdin)\n"
            );
            std::process::exit(2);
        }
    }
}

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

fn demo() {
    println!("=== AlienMsg demo — due dispositivi virtuali ===\n");

    let ma = ok(json!({"op":"mnemonic_generate"}))["mnemonic"]
        .as_str()
        .unwrap()
        .to_string();
    let mb = ok(json!({"op":"mnemonic_generate"}))["mnemonic"]
        .as_str()
        .unwrap()
        .to_string();
    println!("Alice frase: {}", trunc(&ma, 60));
    println!("Bob   frase: {}\n", trunc(&mb, 60));

    let ida = ok(json!({"op":"identity_create","mnemonic":ma}));
    let idb = ok(json!({"op":"identity_create","mnemonic":mb}));
    let (sa, sb) = (
        ida["identity"].as_str().unwrap(),
        idb["identity"].as_str().unwrap(),
    );
    let (pa, pb) = (
        ida["pub_id"].as_str().unwrap(),
        idb["pub_id"].as_str().unwrap(),
    );
    println!("Alice pub_id: {}", trunc(pa, 32));
    println!("Bob   pub_id: {}\n", trunc(pb, 32));

    let ca = ok(json!({"op":"card_create","identity":sa}));
    let cb = ok(json!({"op":"card_create","identity":sb}));
    let (card_a, card_b) = (ca["card"].as_str().unwrap(), cb["card"].as_str().unwrap());
    let (bundle_a, bundle_b) = (
        ca["bundle"].as_str().unwrap(),
        cb["bundle"].as_str().unwrap(),
    );
    println!("Carte generate (con prekey ML-KEM-1024 firmate).");
    println!(
        "Fingerprint SAS: {}",
        ok(json!({"op":"fingerprint","identity":sa,"peer_card":card_b}))["sas"]
            .as_str()
            .unwrap()
    );

    let sess = ok(json!({
        "op":"session_start","identity":sa,"my_card":card_a,"peer_card":card_b}));
    let mut session_a = sess["session"].as_str().unwrap().to_string();
    println!("\nSessione ibrida PQ stabilita (X25519+ML-KEM-1024 → Double Ratchet).\n");

    // Alice → Bob
    let e = ok(
        json!({"op":"encrypt","session":session_a,"plaintext":"Ciao Bob, messaggio segretissimo!"}),
    );
    session_a = e["session"].as_str().unwrap().to_string();
    let env = e["envelope"].as_str().unwrap().to_string();
    for fmt in ["blob", "emoji", "words"] {
        let t = ok(json!({"op":"render","bytes":env,"format":fmt}))["text"]
            .as_str()
            .unwrap()
            .to_string();
        println!("--- formato {fmt} ---\n{}\n", trunc(&t, 240));
    }
    let txt = ok(json!({"op":"render","bytes":env,"format":"blob"}))["text"]
        .as_str()
        .unwrap()
        .to_string();
    let env2 = ok(json!({"op":"unrender","text":txt}))["bytes"]
        .as_str()
        .unwrap()
        .to_string();
    let d = ok(json!({"op":"decrypt","identity":sb,"bundles":[bundle_b],
        "sessions":[],"groups":[],"envelope":env2}));
    println!(
        "Bob decifra (nuova sessione): \"{}\"\n",
        d["plaintext"].as_str().unwrap()
    );
    let mut session_b = d["session"].as_str().unwrap().to_string();

    // Bob → Alice
    let e2 = ok(
        json!({"op":"encrypt","session":session_b,"plaintext":"Ricevuto, Alice. Canale sicuro."}),
    );
    session_b = e2["session"].as_str().unwrap().to_string();
    let d2 = ok(json!({"op":"decrypt","identity":sa,"bundles":[bundle_a],
        "sessions":[session_a],"groups":[],"envelope":e2["envelope"].as_str().unwrap()}));
    println!("Alice decifra: \"{}\"\n", d2["plaintext"].as_str().unwrap());
    let sessions_a: Vec<String> = d2["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    // Gruppo
    let gc = ok(
        json!({"op":"group_create","identity":sa,"sessions":sessions_a,
        "member_ids":[pb],"name":"nucleo"}),
    );
    println!(
        "Gruppo creato: {}",
        trunc(gc["group_id"].as_str().unwrap(), 16)
    );
    let dj = ok(json!({"op":"decrypt","identity":sb,"bundles":[bundle_b],
        "sessions":[session_b],"groups":[],"envelope":gc["envelope"].as_str().unwrap()}));
    println!(
        "Bob entrato nel gruppo (kind={})",
        dj["kind"].as_str().unwrap()
    );
    let group_b = dj["group"].as_str().unwrap().to_string();

    let ge = ok(
        json!({"op":"group_encrypt","identity":sb,"group":group_b,"plaintext":"messaggio al gruppo"}),
    );
    let dg = ok(json!({"op":"decrypt","identity":sa,"bundles":[bundle_a],
        "sessions":gc["sessions"].as_array().unwrap(),
        "groups":[gc["group"].as_str().unwrap()],
        "envelope":ge["envelope"].as_str().unwrap()}));
    println!(
        "Alice legge dal gruppo: \"{}\"",
        dg["plaintext"].as_str().unwrap()
    );

    println!("\n=== demo completata: handshake PQ ✓ ratchet ✓ gruppo ✓ stealth ✓ ===");
}
