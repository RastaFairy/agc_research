#!/usr/bin/env bash
set -euo pipefail
BASE_URL='https://github.com/KhronosGroup/glslang/releases/download/16.5.0'
ARCHIVE='glslang-16.5.0-linux-x86_64-release.tar.gz'
OUT_DIR="${1:-$PWD/.toolchain/glslang-16.5.0}"
mkdir -p "$OUT_DIR"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fL --retry 3 -o "$TMP/$ARCHIVE" "$BASE_URL/$ARCHIVE"
tar -xzf "$TMP/$ARCHIVE" -C "$OUT_DIR" --strip-components=1
"$OUT_DIR/bin/glslang" --version | head -1 || "$OUT_DIR/bin/glslangValidator" --version | head -1
