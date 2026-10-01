// Conditional platform services: real files + DPAPI/Keystore/Keychain on
// native, browser storage (WebCrypto-encrypted via flutter_secure_storage)
// on the web build.
export 'plat_web.dart' if (dart.library.io) 'plat_io.dart';
