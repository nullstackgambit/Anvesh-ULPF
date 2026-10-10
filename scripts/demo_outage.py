#!/usr/bin/env python3
"""OpenSearch outage: the raw archive keeps up, the index catches up after.

1. stop OpenSearch while Vector keeps receiving (SYNTHETIC TEST DATA)
2. check: every sent event is archived + normalized while the index is down
3. start OpenSearch: Vector's disk buffer drains into the index
4. `ulpf account` must PASS (sent = archived = normalized = indexed)
Run against the live stack: .venv/bin/python scripts/demo_outage.py [N]
"""
import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
U = str(REPO / ".venv" / "bin" / "ulpf")
N = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
T0 = time.time()


def say(m):
    print(f"[{time.time() - T0:6.1f}s] {m}", flush=True)


def run(*a, check=True):
    say("$ ulpf " + " ".join(a))
    p = subprocess.run([U, *a], capture_output=True, text=True, cwd=REPO)
    out = (p.stdout + p.stderr).strip()
    if out:
        print("\n".join("    " + x for x in out.splitlines()[-25:]), flush=True)
    if check and p.returncode != 0:
        raise SystemExit(f"failed: {a}")
    return p


sl = REPO / "runtime" / "data" / f"sendlog-outage-{int(T0)}.ndjson"
run("stack", "down", "opensearch")
run("gen", "--vendor", "fortigate", "--vendor", "panos", "--count", str(N), "--transport", "tcp", "--eps", "200",
    "--seed", "81", "--sendlog", str(sl))
rep = json.loads(run("account", "--sendlog", str(sl), "--no-opensearch", "--json", check=False).stdout)
say(f"while OpenSearch is DOWN: sent={rep['sent']} sent_not_archived={rep['sent_not_archived']} "
    f"archived_not_normalized={rep['archived_not_normalized']} verdict(no index)={rep['verdict']}")
down_ok = rep["sent_not_archived"] == 0 and rep["archived_not_normalized"] == 0
run("stack", "up", "opensearch")
for _ in range(60):          # let Vector's retries drain the disk buffer
    rep = json.loads(run("account", "--sendlog", str(sl), "--json", "--settle", "5", check=False).stdout)
    if rep.get("verdict") == "PASS":
        break
    time.sleep(5)
say(f"after restart: indexed={rep.get('indexed')} archived_not_indexed={rep.get('archived_not_indexed')} verdict={rep.get('verdict')}")
ok = down_ok and rep.get("verdict") == "PASS"
say(f"OUTAGE TEST: {'PASS' if ok else 'FAIL'}")
sys.exit(0 if ok else 1)
