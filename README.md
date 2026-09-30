# AlienMsg

Cifratura messaggi end-to-end **post-quantum** per PC, Android e iOS — nessun
server: il testo cifrato si incolla in qualsiasi canale (WhatsApp, email, SMS,
file). Ogni contatto ha la propria sessione crittografica; i gruppi condividono
una chiave con rotazione automatica quando un membro esce.

## Stack

- **Core crypto in Rust** (`crates/`): handshake ibrido X25519 + ML-KEM-1024
  (stile PQXDH di Signal), Double Ratchet con forward secrecy,
  XChaCha20-Poly1305, Ed25519, Argon2id, mnemonic BIP-39 italiano.
- **UI Flutter** (`app/`): un'unica codebase per Windows, Android, iOS; parla
  con Rust via `dart:ffi` (un solo entry point JSON, `alien_invoke`).
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
  poi `rustup default stable-x86_64-pc-windows-msvc`).
- **Android**: cross-compila per `aarch64-linux-android`, `armv7-linux-androideabi`,
  `x86_64-android` e posiziona `libalien_ffi.so` in `app/android/app/src/main/jniLibs/<abi>/`.
- **iOS**: richiede macOS/Xcode; compila `aarch64-apple-ios` (cdylib/staticlib)
  e linka in Xcode.

## Uso

1. **Onboarding**: genera la frase di recupero (24 parole italiane) → identità.
2. **Pairing**: ogni peer genera una *carta contatto* fresca e la invia
   (incolla/QR). Incolla la carta del peer → "Abbina". Verifica il codice di
   sicurezza (SAS) di persona per escludere MITM.
3. **Messaggi**: scrivi → scegli formato (Blob `AYA1:…`, Emoji `👽…`, Parole)
   → copia e incolla dove vuoi. Per leggere: incolla e "Decifra".
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

## Test

```powershell
cargo test --workspace    # 12 test: ratchet, out-of-order, gruppi, codec, tamper
cd app; flutter test      # FFI smoke test end-to-end sulla DLL
```
