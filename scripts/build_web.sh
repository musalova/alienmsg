#!/usr/bin/env bash
# Build the AlienMsg PWA (WASM core + Flutter web) ready for static hosting.
#
# Usage: bash scripts/build_web.sh [base-href]
#   base-href defaults to "/" (root hosting); pass "/<repo>/" for GitHub
#   Pages project sites.
set -euo pipefail
cd "$(dirname "$0")/.."

BASE_HREF="${1:-/}"

# 1. Rust crypto core → WASM + JS bindings
bash scripts/build_wasm.sh

# 2. Flutter web, canvaskit self-hosted (privacy + real offline support)
(cd app && flutter build web --release --no-web-resources-cdn \
    --base-href "$BASE_HREF")

# 3. Flutter generates flutter_service_worker.js as a self-unregistering
#    stub (the upstream feature is deprecated). Overwrite it with our real
#    cache-aside worker so the bootstrap's own registration gives offline
#    support. Registering a SECOND worker alongside the stub caused a
#    navigate/reload loop — do not do that.
cp app/web/sw.js app/build/web/flutter_service_worker.js

echo "PWA build ready in app/build/web"
