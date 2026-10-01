// Web platform services: the vault "path" is just a logical name — the wasm
// store backend persists it as a localStorage key. Secrets go through
// flutter_secure_storage's web implementation (WebCrypto AES-GCM over
// localStorage). A copied localStorage dump on another origin is useless,
// which is the web analogue of device binding — weaker than a hardware
// keystore, honest tradeoff of the PWA path.

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

const _secure = FlutterSecureStorage();

Future<String> defaultVaultPath() async => 'alienmsg.vault';

Future<String?> secureRead(String vaultPath, String name) =>
    _secure.read(key: 'alienmsg.$name');

Future<void> secureWrite(String vaultPath, String name, String value) =>
    _secure.write(key: 'alienmsg.$name', value: value);

Future<void> secureDelete(String vaultPath, String name) =>
    _secure.delete(key: 'alienmsg.$name');
