#!/usr/bin/env bash
# Finding P6-4, reproduced with the real Vector binary and a minimal config
# (no ULPF components): what happens to events a file sink has already
# buffered when a configuration change switches its codec (json -> text)?
#
#   A: socket -> remap (structured record) -> file sink, codec json
#   B: socket -> remap ({"message": encode_json(record)}) -> file sink, codec text
#
# Cases (each: burst of N events, change A -> B while the sink still has a
# backlog, then 1000 more events, wait until the output stops growing):
#   1. hot reload (--watch-config), same sink key
#   2. hot reload, sink renamed (new key)
#   3. graceful stop (Vector drains), then start with B
# Output: per case lines / empty lines / distinct events / missing events.
# Work files: runtime/tmp/reload-exp-<time>/ (removed by `make clean`).
#
# The sink must still have a backlog when the reload takes effect: with a
# small burst it may have drained already and nothing happens (seen with
# N=6000 on the reference VM), hence the large default.
#
# usage: scripts/reload_codec_experiment.sh [N]   (default 60000)
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
V="$REPO/runtime/vector/bin/vector"
N="${1:-60000}"
PORT=59901
BASE="$REPO/runtime/tmp/reload-exp-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BASE"
echo "# $(date -u +%FT%TZ) $("$V" --version) | burst N=$N | work dir ${BASE#"$REPO"/}"

config() {  # $1 dir, $2 A|B, $3 sink key
  local codec=json src='. = {"uid": .message, "shape": "A", "timestamp": now()}'
  if [ "$2" = B ]; then
    codec=text
    src='r = {"uid": .message, "shape": "B"}
      . = {"message": encode_json(r), "shape": "B", "timestamp": now()}'
  fi
  cat <<EOF
data_dir: $1/data
api: {enabled: false}
sources:
  in: {type: socket, mode: tcp, address: 127.0.0.1:$PORT, decoding: {codec: bytes}}
transforms:
  rec:
    type: remap
    inputs: [in]
    source: |
      $src
sinks:
  $3:
    type: file
    inputs: [rec]
    path: $1/out-{{ shape }}.ndjson
    encoding: {codec: $codec}
EOF
}

py() { "$REPO/.venv/bin/python" - "$@"; }

wait_port() { py "$PORT" <<'EOF'
import socket, sys, time
for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1).close(); sys.exit(0)  # no bytes sent
    except OSError:
        time.sleep(0.2)
sys.exit(1)
EOF
}

send() { py "$PORT" "$1" "$2" <<'EOF'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
s.sendall(b"".join(b"%s%06d\n" % (sys.argv[2].encode(), i) for i in range(int(sys.argv[3]))))
s.close()
EOF
}

wait_stable() {  # until the output files stop growing for 6 s
  local prev=-1 cur
  while :; do
    cur=$(cat "$1"/out-*.ndjson 2>/dev/null | wc -l)
    [ "$cur" = "$prev" ] && break
    prev=$cur
    sleep 6
  done
}

count() { py "$1" "$N" "$2" <<'EOF'
import glob, json, sys
d, n, label = sys.argv[1], int(sys.argv[2]), sys.argv[3]
want = {"e%06d" % i for i in range(n)} | {"f%06d" % i for i in range(1000)}
seen, lines, blank = {}, 0, 0
for f in glob.glob(d + "/out-*.ndjson"):
    for ln in open(f):
        lines += 1
        if not ln.strip():
            blank += 1
            continue
        r = json.loads(ln)
        u = json.loads(r["message"])["uid"] if "message" in r else r["uid"]
        seen[u] = seen.get(u, 0) + 1
print(f"{label}: lines={lines} empty_lines={blank} distinct={len(seen)} missing={len(want - set(seen))} "
      f"duplicated={sum(1 for v in seen.values() if v > 1)}")
EOF
}

run() {  # $1 label, $2 mode: reload | rename | restart
  local D="$BASE/$2" VP
  mkdir -p "$D/data"
  config "$D" A out > "$D/live.yaml"
  "$V" --config "$D/live.yaml" --watch-config --color never > "$D/vector.log" 2>&1 & VP=$!
  wait_port
  send e "$N"
  case "$2" in
    reload)  config "$D" B out > "$D/new.yaml"; mv "$D/new.yaml" "$D/live.yaml" ;;
    rename)  config "$D" B out_v2 > "$D/new.yaml"; mv "$D/new.yaml" "$D/live.yaml" ;;
    restart) kill -TERM "$VP"; wait "$VP" 2>/dev/null || true
             config "$D" B out > "$D/live.yaml"
             "$V" --config "$D/live.yaml" --watch-config --color never >> "$D/vector.log" 2>&1 & VP=$!
             wait_port ;;
  esac
  if [ "$2" != restart ]; then
    for _ in $(seq 1 120); do grep -q "Vector has reloaded" "$D/vector.log" && break; sleep 0.5; done
  fi
  send f 1000
  wait_stable "$D"
  kill -TERM "$VP"; wait "$VP" 2>/dev/null || true
  count "$D" "$1"
  grep -E " (WARN|ERROR) " "$D/vector.log" | cut -c29-200 | sort | uniq -c | sed 's/^/    vector: /' || true
}

run "1. hot reload, same sink key, json -> text" reload
run "2. hot reload, sink renamed out -> out_v2  " rename
run "3. graceful stop, then start with config B " restart
