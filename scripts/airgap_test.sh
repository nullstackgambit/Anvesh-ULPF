#!/usr/bin/env bash
# Scenario 9: install and run ULPF from the offline bundle with NO network.
#
# The inner part runs in `bwrap --unshare-net` as the invoking (non-root)
# user: a fresh network namespace with only loopback (no route, no DNS).
# It installs from the bundle into an empty directory and runs: signature +
# hash verification, offline venv, runtime install, secrets/certs, secured
# OpenSearch, Vector, golden tests, live traffic + accounting, Sigma, seal +
# verify. The repository's own stack is stopped meanwhile (ports, memory,
# disk) and restarted afterwards.
#
# usage: scripts/airgap_test.sh [BUNDLE_DIR] [WORK_DIR]
#   KEEP=1 keeps the sandbox installation (~1.4 GB: venv, OpenSearch, Vector)
#   for inspection; by default it is deleted when the test ends.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE="${1:-$REPO/runtime/bundle/ulpf-bundle-0.1.0}"
WORK="${2:-$REPO/runtime/airgap-test}"
U="$REPO/.venv/bin/ulpf"

if [ "${1:-}" = "--inner" ]; then
  BUNDLE="$2"; WORK="$3"
  DEST="$WORK/ulpf"; I="$DEST/.venv/bin/ulpf"
  t0=$(date +%s)
  step() { echo; echo "[$(( $(date +%s) - t0 ))s] == $*"; }
  cleanup() { [ -x "$I" ] && "$I" stack down >/dev/null 2>&1 || true; }
  trap cleanup EXIT
  step "network check inside the sandbox"
  ip -brief addr
  python3 - <<'EOF'
import socket
s = socket.socket(); s.settimeout(3)
print("connect 1.1.1.1:443 ->", s.connect_ex(("1.1.1.1", 443)), "(101 = network unreachable)")
try:
    socket.getaddrinfo("pypi.org", 443); print("DNS: RESOLVED (not air-gapped!)"); raise SystemExit(1)
except socket.gaierror as e:
    print("DNS pypi.org ->", type(e).__name__)
EOF
  step "install from bundle (signature + hashes, offline venv, runtime, secrets, certs, security)"
  "$BUNDLE/install.sh" "$DEST" --pubkey "$BUNDLE/release.pub"
  step "golden/schema/completeness/round-trip tests through Vector"
  "$I" test | tail -3
  step "start secured OpenSearch + Vector"
  "$I" stack up opensearch
  "$I" stack up vector
  step "live traffic (SYNTHETIC TEST DATA) and accounting"
  "$I" gen --vendor fortigate --vendor panos --vendor suricata --count 300 --transport tcp --seed 91 --sendlog "$WORK/sendlog.ndjson"
  "$I" account --sendlog "$WORK/sendlog.ndjson"
  step "Sigma detections against the sandbox index"
  "$I" detect sigma
  step "seal + verify the raw archive"
  sleep 61
  "$I" seal --grace 1 | grep -E '"sealed"|"records"|"seq"' || true
  "$I" verify | tail -3
  step "AIR-GAP TEST: PASS"
  exit 0
fi

mkdir -p "$WORK"
rm -rf -- "${WORK:?}/ulpf" "${WORK:?}/home"
mkdir -p "$WORK/home"
echo "stopping the repository stack (restarted afterwards)"
"$U" stack down vector opensearch ui || true
set +e
bwrap --dev-bind / / --unshare-net --die-with-parent \
      --setenv HOME "$WORK/home" --setenv PIP_NO_CACHE_DIR 1 --setenv PIP_NO_INDEX 1 \
      bash "$REPO/scripts/airgap_test.sh" --inner "$BUNDLE" "$WORK"
rc=$?
set -e
echo "sandbox Vector/OpenSearch ERROR lines (evidence):"
grep -h -E " ERROR |\]\[ERROR" "$WORK"/ulpf/runtime/logs/*.log 2>/dev/null | tail -20 || true
if [ "${KEEP:-0}" != 1 ]; then
  echo "removing the sandbox installation ($(du -sh "$WORK" 2>/dev/null | cut -f1)); KEEP=1 keeps it"
  rm -rf -- "${WORK:?}/ulpf" "${WORK:?}/home"
fi
echo "restarting the repository stack"
"$U" stack up opensearch || true
"$U" stack up vector || true
"$U" stack up ui || true
exit $rc
