import 'dart:convert';

// Conditional transport: dart:ffi on native platforms, the wasm-bindgen JS
// bridge on the web (dart.library.io is absent when compiling for web).
import 'ffi_transport_web.dart'
    if (dart.library.io) 'ffi_transport_native.dart' as transport;

/// Low-level bridge to the Rust `alien-ffi` library. Single JSON entry point
/// (`alienInvoke`) on every platform: native dynamic library, or the WASM
/// module loaded by `web/index.html` in the browser build.
class AlienFfi {
  AlienFfi._();

  /// Load the backend. On web this awaits the WASM module fetch+instantiate
  /// promised as `window.alienReady` by index.html; natively it opens the
  /// dynamic library (optionally from [libraryPath]).
  static Future<void> init({String? libraryPath}) =>
      transport.init(libraryPath: libraryPath);

  /// Call `alien_invoke` with a JSON request map; returns decoded JSON map.
  /// Throws [AlienException] on `{ok:false}`.
  static Map<String, dynamic> call(Map<String, dynamic> request) {
    final text = transport.invoke(jsonEncode(request));
    final decoded = jsonDecode(text);
    if (decoded is! Map<String, dynamic>) {
      throw const AlienException('malformed native response');
    }
    if (decoded['ok'] != true) {
      throw AlienException('${decoded['error'] ?? 'native error'}');
    }
    return decoded;
  }

  /// Like [call] but returns null instead of throwing on error.
  static Map<String, dynamic>? tryCall(Map<String, dynamic> request) {
    try {
      return call(request);
    } on AlienException {
      return null;
    }
  }
}

class AlienException implements Exception {
  final String message;
  const AlienException(this.message);
  @override
  String toString() => 'AlienException: $message';
}
