#!/usr/bin/env bash
# ULPF air-gapped installer. Verifies the bundle, installs into DEST and
# generates this installation's secrets. It never uses the network: Python
# packages come from wheelhouse/ (hash-pinned), Vector/OpenSearch from dist/
# (SHA-256-pinned in deploy/airgap/ARTIFACTS.json).
#
# usage: ./install.sh DEST [--pubkey FILE] [--no-secure]
#   --pubkey FILE   verify BUNDLE.json.sig with this Ed25519 public key (openssl)
#   --no-secure     leave the OpenSearch security plugin off (plain http, no auth)
set -euo pipefail
B="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${1:?usage: install.sh DEST [--pubkey FILE] [--no-secure]}"
shift
PUBKEY="" SECURE=1
while [ $# -gt 0 ]; do
  case "$1" in
    --pubkey) PUBKEY="$2"; shift 2 ;;
    --no-secure) SECURE=0; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
PY="${PYTHON:-python3}"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else "Python >= 3.12 required")'

echo "== 1/6 verify bundle"
"$PY" "$B/verify_bundle.py" "$B"
if [ -n "$PUBKEY" ]; then
  openssl pkeyutl -verify -pubin -inkey "$PUBKEY" -rawin -in "$B/BUNDLE.json" -sigfile "$B/BUNDLE.json.sig"
else
  echo "   (no --pubkey: compare the BUNDLE.json sha256 above with the published value)"
fi

echo "== 2/6 copy source tree to $DEST"
mkdir -p "$DEST"
cp -a "$B/src/." "$DEST/"
DEST="$(cd "$DEST" && pwd)"

echo "== 3/6 Python environment (offline, hash-pinned wheels)"
"$PY" -m venv "$DEST/.venv"
"$DEST/.venv/bin/pip" install --quiet --no-index --find-links "$B/wheelhouse" --require-hashes \
  --only-binary=:all: -r "$B/requirements.lock"
# ulpf itself: a .pth entry + launcher instead of a build (no build backend needed offline)
SP="$("$DEST/.venv/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
echo "$DEST" > "$SP/ulpf-src.pth"
cat > "$DEST/.venv/bin/ulpf" <<EOF
#!$DEST/.venv/bin/python
import sys
from ulpf.cli import main
sys.exit(main())
EOF
chmod 0755 "$DEST/.venv/bin/ulpf"
U="$DEST/.venv/bin/ulpf"

echo "== 4/6 runtime (Vector, OpenSearch, security plugin) from pinned artifacts"
mkdir -p "$DEST/runtime/dist"
# hard links when bundle and DEST share a filesystem (saves ~350 MB), else copy
cp -al "$B/dist/." "$DEST/runtime/dist/" 2>/dev/null || cp -a "$B/dist/." "$DEST/runtime/dist/"
"$U" runtime install --with-security

echo "== 5/6 secrets, keys, certificates (generated here, never shipped)"
"$U" keygen
"$U" secrets init
"$U" certs init
if [ "$SECURE" = 1 ]; then "$U" os secure; fi
"$U" spec compile > "$DEST/runtime/BUILD-install.json"

echo "== 6/6 checks"
"$U" doctor
echo
echo "installed in $DEST. Start:  $U stack up"
