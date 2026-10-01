#!/usr/bin/env bash
# Build the alien-ffi Rust core to WASM and generate the JS bindings the web
# app loads (app/web/pkg/). Works on Linux/macOS/Windows-git-bash.
#
# Requires: rustup target wasm32-unknown-unknown; the wasm-bindgen CLI binary
# matching the wasm-bindgen crate version (auto-downloaded if missing).
set -euo pipefail
cd "$(dirname "$0")/.."

rustup target add wasm32-unknown-unknown

# Resolve the wasm-bindgen CLI version from Cargo.lock so the generated glue
# matches the linked library.
WBG_VER=$(grep -A1 'name = "wasm-bindgen"' Cargo.lock | grep '^version' | head -1 | cut -d'"' -f2)
WBG="tools/wasm-bindgen/wasm-bindgen"
[ "$(uname -s)" = "Linux" ] || [ "$(uname -s)" = "Darwin" ] || WBG="$WBG.exe"

if [ ! -x "$WBG" ]; then
  echo "Downloading wasm-bindgen-cli $WBG_VER…"
  case "$(uname -s)" in
    Linux)  TGT=x86_64-unknown-linux-musl ;;
    Darwin) TGT=aarch64-apple-darwin ;;
    *)      TGT=x86_64-pc-windows-msvc ;;
  esac
  mkdir -p tools/wasm-bindgen
  curl -sL "https://github.com/rustwasm/wasm-bindgen/releases/download/$WBG_VER/wasm-bindgen-$WBG_VER-$TGT.tar.gz" \
    | tar xz -C tools/wasm-bindgen --strip-components=1
fi

cargo build --release --lib -p alien-ffi --target wasm32-unknown-unknown
"$WBG" --target web --out-dir app/web/pkg --out-name alien_ffi \
  target/wasm32-unknown-unknown/release/alien_ffi.wasm

echo "WASM bundle → app/web/pkg/"
