#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for f in "$ROOT/build/fullscreen.vert.spv" "$ROOT/build/solid.frag.spv"; do
  [[ -s "$f" ]] || { echo "missing: $f" >&2; exit 2; }
done
if command -v spirv-val >/dev/null 2>&1; then
  spirv-val "$ROOT/build/fullscreen.vert.spv"
  spirv-val "$ROOT/build/solid.frag.spv"
else
  echo "spirv-val unavailable; structural existence check only"
fi
sha256sum "$ROOT/build"/*.spv
