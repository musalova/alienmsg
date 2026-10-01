// Web transport: the Rust core compiled to WASM, exposed by index.html as
// `window.alienInvoke(json) -> json` once `window.alienReady` resolves.
// The JS call is synchronous, matching the native dart:ffi signature.

import 'dart:js_interop';

@JS('alienReady')
external JSPromise<JSAny?> get _alienReady;

@JS('alienInvoke')
external JSString _alienInvoke(JSString req);

Future<void> init({String? libraryPath}) async {
  await _alienReady.toDart;
}

String invoke(String requestJson) =>
    _alienInvoke(requestJson.toJS).toDart;
