#!/usr/bin/env bash
# Build libalien_ffi.a as an XCFramework for iOS (device + simulator).
# Requires: macOS with Xcode, rustup targets:
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=app/ios/Frameworks
mkdir -p "$OUT"

cargo build --release --target aarch64-apple-ios -p alien-ffi
cargo build --release --target aarch64-apple-ios-sim -p alien-ffi
cargo build --release --target x86_64-apple-ios -p alien-ffi  # Intel sims

lipo -create \
  target/aarch64-apple-ios-sim/release/libalien_ffi.a \
  target/x86_64-apple-ios/release/libalien_ffi.a \
  -output target/ios-sim-libalien_ffi.a

xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libalien_ffi.a \
  -library target/ios-sim-libalien_ffi.a \
  -output "$OUT/AlienFfi.xcframework"

echo "Done → $OUT/AlienFfi.xcframework"
echo "Drag it into Xcode → Runner → Frameworks, Libraries and Embedded Content."
