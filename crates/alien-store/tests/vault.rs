use alien_store::{probe, Vault};

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("alien-store-test-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_file(&d);
    d
}

#[test]
fn plain_vault_roundtrip() {
    let p = tmp("plain.vault");
    {
        let mut v = Vault::open(&p, "").unwrap();
        v.set("k", b"secret");
        v.save(&p).unwrap();
    }
    assert!(!probe(&p).unwrap().needs_password);
    // still opens with empty password
    let v = Vault::open(&p, "").unwrap();
    assert_eq!(v.get("k"), Some(&b"secret"[..]));
    assert!(!v.is_protected());
    let _ = std::fs::remove_file(&p);
}

#[test]
fn protected_vault_requires_password() {
    let p = tmp("prot.vault");
    {
        let mut v = Vault::open(&p, "hunter2").unwrap();
        v.set("k", b"secret");
        v.save(&p).unwrap();
        assert!(v.is_protected());
    }
    assert!(probe(&p).unwrap().needs_password);
    // empty and wrong passwords both fail
    assert!(Vault::open(&p, "").is_err());
    assert!(Vault::open(&p, "wrong").is_err());
    // correct password opens
    let v = Vault::open(&p, "hunter2").unwrap();
    assert_eq!(v.get("k"), Some(&b"secret"[..]));
    let _ = std::fs::remove_file(&p);
}

#[test]
fn set_password_rekeys_vault() {
    let p = tmp("rekey.vault");
    {
        let mut v = Vault::open(&p, "").unwrap();
        v.set("k", b"data");
        v.set_password("pw").unwrap();
        v.save(&p).unwrap();
    }
    assert!(probe(&p).unwrap().needs_password);
    assert!(Vault::open(&p, "").is_err());
    let mut v = Vault::open(&p, "pw").unwrap();
    assert_eq!(v.get("k"), Some(&b"data"[..]));
    // removing the password goes back to a plain v1 vault
    v.set_password("").unwrap();
    v.save(&p).unwrap();
    drop(v);
    assert!(!probe(&p).unwrap().needs_password);
    let v = Vault::open(&p, "").unwrap();
    assert_eq!(v.get("k"), Some(&b"data"[..]));
    let _ = std::fs::remove_file(&p);
}

#[test]
fn corrupt_file_is_not_protected() {
    let p = tmp("corrupt.vault");
    std::fs::write(&p, b"not a vault").unwrap();
    let pr = probe(&p).unwrap();
    assert!(pr.exists);
    assert!(!pr.needs_password);
    assert!(Vault::open(&p, "").is_err());
    let _ = std::fs::remove_file(&p);
}
