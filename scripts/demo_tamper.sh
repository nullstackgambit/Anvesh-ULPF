#!/usr/bin/env bash
# Scenario 5 - tamper evidence, run against a COPY of the sealed archive.
#   seal -> verify (PASS) -> modify ONE byte of ONE record -> verify (FAIL)
# The real archive under runtime/data is never modified.
set -euo pipefail
cd "$(dirname "$0")/.."
ULPF=${ULPF:-.venv/bin/ulpf}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ulpf-tamper-XXXXXX")
trap 'rm -rf "$WORK"' EXIT

echo "== sealing closed files of the live archive"
$ULPF seal --grace 60 >/dev/null || true
cp -a runtime/data/archive "$WORK/archive"
export ULPF_DATA="$WORK"            # every ulpf path now points at the copy

echo "== 1) verify the untouched copy"
$ULPF verify

FILE=$(ls "$WORK"/archive/raw/*/raw-*.ndjson | head -1)
echo "== 2) flip one byte inside the first record's raw_b64 in $(basename "$FILE")"
python3 - "$FILE" <<'EOF'
import sys
p = sys.argv[1]
data = bytearray(open(p, "rb").read())
i = data.index(b'"raw_b64":"') + 12
before = chr(data[i])
data[i] = ord("B") if data[i] != ord("B") else ord("C")
open(p, "wb").write(bytes(data))
print(f"   byte {i}: {before!r} -> {chr(data[i])!r}")
EOF

echo "== 3) verify again (must FAIL)"
if $ULPF verify; then
  echo "DEMO FAILED: tampering was not detected" >&2
  exit 1
fi
echo "== tampering detected, as required"
