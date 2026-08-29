#!/usr/bin/env bash
set -euo pipefail

: "${PS5_PAYLOAD_SDK:?PS5_PAYLOAD_SDK must point to the installed PS5 payload SDK}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$ROOT/stage36_results"
rm -rf "$OUT"
mkdir -p "$OUT"

{
  echo "PS5_PAYLOAD_SDK=$PS5_PAYLOAD_SDK"
  echo "date=$(date -Is)"
  echo
  echo "== toolchain =="
  test -f "$PS5_PAYLOAD_SDK/toolchain/prospero.mk" && echo "prospero.mk=PASS" || echo "prospero.mk=FAIL"
  command -v make || true
  command -v clang || true
  command -v ld.lld || true
  echo
  echo "== candidate AGC artifacts =="
  find "$PS5_PAYLOAD_SDK" \( \
      -iname 'libSceAgcDriver.a' -o \
      -iname 'libSceAgcDriver.c' -o \
      -iname 'libSceAgcDriver.sprx' -o \
      -iname '*AgcDriver*' \
    \) -print 2>/dev/null | sort
  echo
  echo "== submit symbol references in local SDK =="
  grep -R -n --binary-files=without-match 'sceAgcDriverSubmitDcb' "$PS5_PAYLOAD_SDK" 2>/dev/null | head -50 || true
} | tee "$OUT/discovery.txt"

STUB_LIB=""
while IFS= read -r p; do
  if [[ -f "$p" ]]; then
    STUB_LIB="$p"
    break
  fi
done < <(find "$PS5_PAYLOAD_SDK" -type f -name 'libSceAgcDriver.a' 2>/dev/null | sort)

if [[ -z "$STUB_LIB" ]]; then
  echo "STATUS=STUB_UNAVAILABLE" | tee "$OUT/status.txt"
  exit 0
fi

echo "STATUS=STUB_FOUND" | tee "$OUT/status.txt"
echo "STUB_LIB=$STUB_LIB" | tee -a "$OUT/status.txt"

BUILD="$OUT/build"
mkdir -p "$BUILD"

cp "$ROOT/agc_ps5_submit_boundary.c" "$BUILD/"
cp "$ROOT/agc_ps5_submit_boundary.h" "$BUILD/"
cp "$ROOT/ABI_CHECK.c" "$BUILD/"

cat > "$BUILD/Makefile" <<'MK'
ifndef PS5_PAYLOAD_SDK
$(error PS5_PAYLOAD_SDK is undefined)
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

CFLAGS += -I.
LDFLAGS +=
LDADD += -lSceAgcDriver

BIN := stage36_probe.elf
SRCS := agc_ps5_submit_boundary.c ABI_CHECK.c

all: $(BIN)

$(BIN): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS) $(LDADD)

clean:
	rm -f $(BIN)
MK

make -C "$BUILD" clean all 2>&1 | tee "$OUT/build.log"
file "$BUILD/stage36_probe.elf" | tee "$OUT/elf.txt"

if command -v llvm-readelf >/dev/null 2>&1; then
  llvm-readelf -Ws "$BUILD/stage36_probe.elf" | grep -E 'sceAgcDriverSubmitDcb' | tee "$OUT/symbol.txt" || true
fi
