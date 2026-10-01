// Native platform services: vault path under the app-support dir; secrets in
// a DPAPI-wrapped sidecar file on Windows, Keystore/Keychain elsewhere via
// flutter_secure_storage.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path_provider/path_provider.dart';

import 'api.dart';

const _secure = FlutterSecureStorage();

Future<String> defaultVaultPath() async {
  final dir = await getApplicationSupportDirectory();
  return '${dir.path}${Platform.pathSeparator}alienmsg.vault';
}

/// Platform-protected secret store.
/// Windows: DPAPI-wrapped sidecar file next to the vault.
/// Android/iOS: Keystore / Keychain via flutter_secure_storage.
/// Both scopes bind the secret to this device+account.
Future<String?> secureRead(String vaultPath, String name) async {
  if (Platform.isWindows) {
    final f = File('$vaultPath.$name');
    if (!await f.exists()) return null;
    final raw = AlienApi.dpapiUnwrap((await f.readAsString()).trim());
    return utf8.decode(base64Decode(raw));
  }
  return _secure.read(key: 'alienmsg.$name');
}

Future<void> secureWrite(String vaultPath, String name, String value) async {
  if (Platform.isWindows) {
    await File('$vaultPath.$name').writeAsString(
        AlienApi.dpapiWrap(base64Encode(utf8.encode(value))));
    return;
  }
  await _secure.write(key: 'alienmsg.$name', value: value);
}

Future<void> secureDelete(String vaultPath, String name) async {
  if (Platform.isWindows) {
    final f = File('$vaultPath.$name');
    if (await f.exists()) await f.delete();
    return;
  }
  await _secure.delete(key: 'alienmsg.$name');
}
