# AlienMsg

Cifratura messaggi end-to-end **post-quantum** per PC, Android e iOS — nessun
server: il testo cifrato si incolla in qualsiasi canale (WhatsApp, email, SMS,
file). Ogni contatto ha la propria sessione crittografica; i gruppi condividono
una chiave con rotazione automatica quando un membro esce.

## Stack

- **Core crypto in Rust** (`crates/`): handshake ibrido X25519 + ML-KEM-1024
  (stile PQXDH di Signal), Double Ratchet con forward secrecy,
  XChaCha20-Poly1305, Ed25519, Argon2id, mnemonic BIP-39 italiano.
- **UI Flutter** (`app/`): un'unica codebase per Windows, Android, iOS **e
  Web/PWA**; parla con Rust via un solo entry point JSON (`alien_invoke`) —
  `dart:ffi` su nativo, WASM su web.
- **CLI** (`alienmsg`): wrapper Windows che espone la stessa API.

Specifica completa e threat model: [`docs/protocol.md`](docs/protocol.md).

## Build rapida (PC / CLI)

```powershell
cargo build --release
.\target\release\alienmsg.exe demo      # demo end-to-end a due dispositivi
.\target\release\alienmsg.exe invoke '{"op":"mnemonic_generate"}'
```

## App Flutter

Prerequisiti: Flutter SDK 3.4+, toolchain Rust.

```powershell
cargo build --release -p alien-ffi      # produce target\release\alien_ffi.dll
cd app
flutter pub get
flutter test                          # smoke test FFI sulla DLL reale
flutter run -d windows                # richiede Visual Studio Build Tools
flutter run -d <android-device>       # richiede Android SDK + device
```

- **Windows**: `windows/runner/CMakeLists.txt` copia `alien_ffi.dll` accanto
  all'exe automaticamente (build MSVC consigliata: installa VS Build Tools,
  poi `rustup default stable-x86_64-pc-windows-msvc`). Le chiavi del vault
  sono legate al dispositivo via **DPAPI** (`CryptProtectData`).
- **Android**: `cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o
  app/android/app/src/main/jniLibs build --release -p alien-ffi` produce i
  `.so`. Le chiavi sono legate al dispositivo via **Android Keystore**
  (`flutter_secure_storage`); il blocco con impronta usa `local_auth` +
  `FlutterFragmentActivity`.
- **Web / PWA** (iPhone gratis, senza scadenza, senza Apple ID): il core Rust
  è compilato in WASM (`bash scripts/build_wasm.sh` → `app/web/pkg/`), il
  resto è Flutter web. Su GitHub Pages il job `web` del workflow builda e
  pubblica automaticamente a ogni push — poi su iPhone: Safari → Condividi →
  **"Aggiungi a Home"**. Funziona offline dopo il primo caricamento (service
  worker), gli aggiornamenti arrivano da soli al reload. Vault e devkey
  restano in localStorage/IndexedDB (cifrati); il blocco PIN è disponibile,
  l'impronta no (i browser non espongono un'API di sblocco biometrico alle
  PWA).
- **iOS nativa**: Apple impone macOS/Xcode per la build — **non serve
  possedere un Mac**: il job `ios` del workflow lo fa su runner macOS hosted
  e produce `alienmsg.ipa` non firmato. Per installarlo: **AltServer**/
  **SideStore** su Windows (Apple ID gratuito, rinnovo ogni 7 giorni) oppure
  account sviluppatore Apple ($99/anno). Con un Mac: `bash
  scripts/build_ios.sh` produce `app/ios/Frameworks/AlienFfi.xcframework`
  da trascinare in Xcode (Runner → Frameworks). Le chiavi vanno nel
  **Keychain** iOS, Face ID/Touch ID via `local_auth` (permessi già in
  `Info.plist`).

## Aggiornamenti

L'app nativa controlla un manifest JSON all'avvio (`UpdateChecker.manifestUrl`
in `app/lib/update.dart` — punta a un URL HTTPS che ospiti
`{"version","url","notes","mandatory"}`). Se la versione remota è più nuova,
propone il download. Vuoto = funzione disattivata, zero traffico di rete.
Sulla PWA il controllo è saltato: il service worker serve sempre la build
più recente al reload.

## Uso

1. **Onboarding**: genera la frase di recupero (24 parole italiane) → identità.
2. **Pairing**: ogni peer genera una *carta contatto* fresca e la invia
   (incolla/QR). Incolla la carta del peer → "Abbina". Verifica il codice di
   sicurezza (SAS) di persona per escludere MITM.
3. **Messaggi**: scrivi → scegli formato (Frasi italiane — predefinito,
   Blob `AYA1:…`, Emoji `👽…`, Parole inventate) → copia e incolla dove
   vuoi. Per leggere: incolla e "Decifra" — il formato è riconosciuto
   automaticamente.
4. **Gruppi**: crea → incolla il blob di invito nel canale. Rimozione membro →
   blob di rotazione: chi esce non legge più i messaggi futuri.

## Sicurezza — limiti onesti

- La cifratura è computazionalmente inviolabile (anche post-quantum), ma
  **nessun software protegge da un dispositivo compromesso** (malware,
  screenshot, accesso fisico).
- Senza verifica del fingerprint, un MITM attivo sul canale di scambio carte
  potrebbe sostituirle — verifica sempre il SAS con i contatti importanti.
- Il formato stealth rende i messaggi irriconoscibili (opacità), non aumenta la
  sicurezza matematica — che è già al massimo.
- I metadati dell'app di trasporto (chi scrive a chi, quando) non sono coperti.
- Il vault locale contiene il seed dell'identità: senza password è AEAD ma
  decifrabile da chiunque copi il file. Attiva la protezione da
  Impostazioni → Password del vault (v2, Argon2id).
- **Web/PWA**: il "device binding" è IndexedDB/localStorage per origine, non
  un keystore hardware — più esposto di DPAPI/Keystore/Keychain. Attiva il
  PIN ad ogni avvio; su iOS considera che cancellare i dati del sito cancella
  il profilo (tieni la frase di recupero).

## Test

```powershell
cargo test --workspace    # 27 test: ratchet, out-of-order, gruppi, codec, tamper,
                          # replay PairInit, header forgiati, impersonificazione,
                          # autorizzazione admin, vault protetto da password
cd app; flutter test      # FFI smoke test end-to-end sulla DLL
```
