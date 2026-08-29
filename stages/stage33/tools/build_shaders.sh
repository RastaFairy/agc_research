#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GLSLANG_BIN="${GLSLANG_BIN:-$ROOT/.toolchain/glslang-16.5.0/bin/glslang}"
if [[ ! -x "$GLSLANG_BIN" ]]; then
  echo "glslang not found: $GLSLANG_BIN" >&2
  echo "Run tools/bootstrap_glslang.sh or set GLSLANG_BIN" >&2
  exit 2
fi
mkdir -p "$ROOT/build"
"$GLSLANG_BIN" -V "$ROOT/shaders/fullscreen.vert" -o "$ROOT/build/fullscreen.vert.spv"
"$GLSLANG_BIN" -V "$ROOT/shaders/solid.frag" -o "$ROOT/build/solid.frag.spv"
