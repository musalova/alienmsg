import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

final class AlienBuf extends Struct {
  external Pointer<Uint8> ptr;
  @UintPtr()
  external int len;
}

typedef _InvokeNativeSig = Pointer<AlienBuf> Function(Pointer<Uint8>, IntPtr);
typedef _InvokeDart = Pointer<AlienBuf> Function(Pointer<Uint8>, int);
typedef _FreeNativeSig = Void Function(Pointer<AlienBuf>);
typedef _FreeDart = void Function(Pointer<AlienBuf>);

/// Low-level bridge to the Rust `alien-ffi` library. Single JSON entry point.
class AlienFfi {
  AlienFfi._();

  static DynamicLibrary? _lib;
  static _InvokeDart? _invoke;
  static _FreeDart? _free;

  static void init({String? libraryPath}) {
    if (_lib != null) return;
    if (libraryPath != null) {
      _lib = DynamicLibrary.open(libraryPath);
    } else if (Platform.isWindows) {
      _lib = DynamicLibrary.open('alien_ffi.dll');
    } else if (Platform.isAndroid) {
      _lib = DynamicLibrary.open('libalien_ffi.so');
    } else if (Platform.isIOS || Platform.isMacOS) {
      _lib = DynamicLibrary.process();
    } else {
      _lib = DynamicLibrary.open('libalien_ffi.so');
    }
    _invoke =
        _lib!.lookupFunction<_InvokeNativeSig, _InvokeDart>('alien_invoke');
    _free =
        _lib!.lookupFunction<_FreeNativeSig, _FreeDart>('alien_free_buf');
  }

  /// Call `alien_invoke` with a JSON request map; returns decoded JSON map.
  /// Throws [AlienException] on `{ok:false}`.
  static Map<String, dynamic> call(Map<String, dynamic> request) {
    init();
    final reqBytes = utf8.encode(jsonEncode(request));
    final arena = Arena();
    try {
      final reqPtr = arena.allocate<Uint8>(reqBytes.length);
      reqPtr.asTypedList(reqBytes.length).setAll(0, reqBytes);
      final bufPtr = _invoke!(reqPtr, reqBytes.length);
      if (bufPtr == nullptr) {
        throw const AlienException('null response from native library');
      }
      final buf = bufPtr.ref;
      final outBytes = buf.ptr.asTypedList(buf.len);
      final text = utf8.decode(outBytes);
      _free!(bufPtr);
      final decoded = jsonDecode(text);
      if (decoded is! Map<String, dynamic>) {
        throw const AlienException('malformed native response');
      }
      if (decoded['ok'] != true) {
        throw AlienException('${decoded['error'] ?? 'native error'}');
      }
      return decoded;
    } finally {
      arena.releaseAll();
    }
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
