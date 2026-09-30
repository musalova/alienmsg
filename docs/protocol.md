# AlienMsg — specifica del protocollo e threat model

## Primitive

| Scopo | Algoritmo |
|---|---|
| Firma identità / prekey | Ed25519 (`ed25519-dalek`) |
| DH classico | X25519 (`x25519-dalek`, StaticSecret) |
| KEM post-quantum | ML-KEM-1024 (`ml-kem` RustCrypto) |
| AEAD messaggi/vault | XChaCha20-Poly1305 (`chacha20poly1305`) |
| KDF ratchet | HKDF-SHA256 + HMAC-SHA256 |
| Stretching mnemonic/vault | Argon2id (m=64MiB, t=3, p=1) |
| Mnemonic | BIP-39, wordlist italiana (inglese accettata) |

## Identità

`mnemonic (24 parole) → Argon2id → seed 32B → HKDF(domain-separated) → Ed25519 sk + X25519 sk`

`pub_id = SHA256("alienmsg/pubid/v1" ‖ ed_pub ‖ x_pub)`

Le prekey (signed X25519, one-time PQ ML-KEM-1024) sono **casuali e per-device**:
non derivano dal mnemonic. Ripristinare la frase rigenera l'identità ma non lo
stato ratchet → i messaggi passati restano protetti (forward secrecy reale
anche in caso di furto della frase).

## Contact card

```
ContactCard {
  version=1, card_id[16], identity_ed[32], identity_x[32],
  spk_x[32], pq_ek[1568], signature[64]
}
signature = Ed25519(identity_ed).sign("AlienMsg/ContactCard/v1" ‖ identity_x ‖ spk_x ‖ pq_ek)
```

Scambiata come envelope `Card` (paste o QR). Una carta per pairing → prekey
effettivamente one-time. Anti-MITM: confronto SAS/fingerprint out-of-band.

## Handshake (PQXDH-like, asincrono)

Initiator A verso B:
```
DH1 = DH(x_A, spk_B)     DH2 = DH(eph_A, x_B)     DH3 = DH(eph_A, spk_B)
(ss, pq_ct) = ML-KEM-1024.encaps(pq_ek_B)
root = HKDF("AlienMsg/PQXDH/v1", DH1‖DH2‖DH3‖ss,
            "AlienMsg/root/v1" ‖ min(pubid_A,pubid_B) ‖ max(...))
```
`pq_ct` viaggia nel primo messaggio (PairInit) insieme alla carta di A.
`session_id = SHA256("alienmsg/session-id/v1" ‖ root)[:16]`.

## Double Ratchet

- `KDF_RK(rk, dh) = HKDF(salt=rk, ikm=dh, "AlienMsg/RatchetRoot/v1") → (rk', ck)`
- `KDF_CK(ck)`: `mk = HMAC(ck, 0x01)`, `ck' = HMAC(ck, 0x02)`
- Header messaggio: `{dh_pub, n, pn, session_id}` — incluso come AEAD AD
  insieme ai 3 byte di framing `[0xA1, ver, type]`.
- Skipped-key store per out-of-order: max 400 per batch, 2000 totali.
- Alice inizia con `remote_dh = spk_B`; Bob fa il primo DH-step alla ricezione.

## Envelope

```
[0xA1][ver=1][type][postcard payload]
type: 0x01 Card | 0x02 PairInit | 0x03 PairMsg
      0x10 GroupInvite | 0x11 GroupMsg | 0x12 GroupRotate
```

PairInit payload: `{init: {eph, pq_ct, recipient_card_id, card}, header, nonce[24], ct}`.
PairMsg payload: `{header, nonce[24], ct}`.

## Gruppi (sender-key)

- `K_g` casuale per epoch; chain di invio per membro:
  `send_ck = HKDF(K_g, "gsend" ‖ sender_pubid)`.
- mk per messaggio: `HMAC(ck,"gmk")`; chain: `HMAC(ck,"gck")`.
- Invito/rotazione: `InviteInner{group_id, epoch, k_g, admin, members}`
  wrappato per-membro dentro envelope PairMsg (consuma il ratchet pairwise —
  autenticità ereditata dalla sessione E2E).
- Rimozione membro → `K_g'` + epoch+1, wrappata ai soli rimasti. Vecchie epoch
  (≤8) conservate per messaggi in ritardo; l'espulso non riceve la nuova chiave.

## Codec di output (`alien-codec`)

- **Blob**: `AYA1:` + base64url.
- **Emoji**: `👽` + 1 emoji/byte (alfabeto U+1F300..U+1F3FF).
- **Parole**: sillabe CV (16 consonanti × 16 vocali = 256 → 1 byte).

Lo stealth è *opacità*, non sicurezza aggiuntiva: il ciphertext AEAD è già
indistinguibile da rumore.

## Vault (`alien-store`)

`ALNV ‖ ver ‖ salt(16) ‖ nonce(24) ‖ XChaCha20-Poly1305(postcard map)`,
chiave = Argon2id(password, salt) — o chiave casuale se password vuota.

## Threat model (onesto)

**Protetto contro**: intercettazione sul canale di trasporto, analisi del
ciphertext (computazionalmente infattibile, PQ-safe), furto futuro della chiave
identità (PFS sui messaggi passati), tampering (AEAD + firme).

**NON protetto contro**: compromesso endpoint (malware/screenshot/keylogger),
MITM sullo scambio carte *senza* verifica fingerprint, metadati dell'app
trasportatrice (WhatsApp vede che scrivi a Tizio), passphrase mnemonic rubata
*prima* che le sessioni avanzino, coercizione fisica.

**Limiti noti**: contact card riusabile finché non rigenerata (no server per
one-time enforcement); iOS richiede macOS per build/distribuzione.
