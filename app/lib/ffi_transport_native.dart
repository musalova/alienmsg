// Native transport: dart:ffi against the alien_ffi dynamic library.

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

DynamicLibrary? _lib;
_InvokeDart? _invoke;
_FreeDart? _free;

Future<void> init({String? libraryPath}) async {
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
  _free = _lib!.lookupFunction<_FreeNativeSig, _FreeDart>('alien_free_buf');
}

String invoke(String requestJson) {
  final reqBytes = utf8.encode(requestJson);
  final arena = Arena();
  try {
    final reqPtr = arena.allocate<Uint8>(reqBytes.length);
    reqPtr.asTypedList(reqBytes.length).setAll(0, reqBytes);
    final bufPtr = _invoke!(reqPtr, reqBytes.length);
    if (bufPtr == nullptr) {
      throw StateError('null response from native library');
    }
    final buf = bufPtr.ref;
    final outBytes =
        buf.len > 0 ? buf.ptr.asTypedList(buf.len) : const <int>[];
    final text = utf8.decode(outBytes);
    _free!(bufPtr);
    return text;
  } finally {
    arena.releaseAll();
  }
}
