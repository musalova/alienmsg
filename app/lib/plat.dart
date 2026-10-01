// Conditional platform services: real files + DPAPI/Keystore/Keychain on
// native, browser storage (WebCrypto with a non-extractable IndexedDB key,
// see web/secure.js) on the web build.
export 'plat_web.dart' if (dart.library.io) 'plat_io.dart';
