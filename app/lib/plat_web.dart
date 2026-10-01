// Web platform services.
//
// Vault "path" is a logical name — the wasm store backend persists it under
// the localStorage key `alienmsg.fs:<path>`.
//
// Secrets (device key, hello marker) are AES-256-GCM encrypted with a
// NON-EXTRACTABLE CryptoKey persisted in IndexedDB by `web/secure.js`:
// JavaScript can use the key but `exportKey` refuses, so a localStorage
// dump alone cannot decrypt the values. Honest limit: the key material
// still lives inside the browser profile — a full profile copy can carry
// it. Weaker than a hardware keystore; the documented PWA tradeoff.
//
// When the user sets a PIN, the device key is additionally wrapped by an
// Argon2id-derived key in Rust (ops pin_wrap/pin_unwrap), so unlocking then
// cryptographically requires the PIN — not just the UI gate.

import 'dart:js_interop';
import 'dart:js_interop_unsafe';

@JS('alienSecure.ready')
external JSPromise<JSAny?> get _secureReady;

@JS('alienSecure.get')
external JSPromise<JSString?> _secureGet(JSString name);

@JS('alienSecure.set')
external JSPromise<JSAny?> _secureSet(JSString name, JSString value);

@JS('alienSecure.del')
external JSPromise<JSAny?> _secureDel(JSString name);

@JS('window.addEventListener')
external void _addListener(JSString type, JSFunction fn);

Future<String> defaultVaultPath() async => 'alienmsg.vault';

/// Wait for the IndexedDB key to be loadable and for the legacy
/// flutter_secure_storage_web migration to complete. Must run before any
/// secureRead/secureWrite at boot.
Future<void> secureReady() async {
  await _secureReady.toDart;
}

Future<String?> secureRead(String vaultPath, String name) async {
  final v = await _secureGet(name.toJS).toDart;
  return v?.toDart;
}

Future<void> secureWrite(String vaultPath, String name, String value) =>
    _secureSet(name.toJS, value.toJS).toDart;

Future<void> secureDelete(String vaultPath, String name) =>
    _secureDel(name.toJS).toDart;

/// Fires when ANOTHER tab writes the vault (storage events never fire in
/// the writing tab). Used to reload vault state instead of silently
/// diverging — the last writer would otherwise clobber this tab's data.
void onVaultChanged(void Function() cb) {
  _addListener(
      'storage'.toJS,
      ((JSAny? event) {
        final key = (event as JSObject?)
            ?.getProperty<JSString?>('key'.toJS);
        if (key != null && key.toDart.startsWith('alienmsg.fs:')) cb();
      }).toJS);
}
