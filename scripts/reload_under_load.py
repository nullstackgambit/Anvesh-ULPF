#!/usr/bin/env python3
"""Configuration changes under load, with the real generated configuration
(VERIFICATION_REPORT finding P6-4). SYNTHETIC TEST DATA.

Runs in an ISOLATED home under runtime/demo/ (copied specs, own archive and
stores, Vector on test ports, own OpenSearch index ulpf-reload-*); the shared
OpenSearch is the stack's instance.

  A. Spec changes under continuous TCP traffic (7 vendors): retire the Zeek
     spec, then re-add it. Both are hot reloads (no reload hazards), while
     Zeek events are in flight through the transform being removed/re-added.
  B. Structural change (limits.max_parse_bytes -> the pre-parse program):
     `ulpf spec compile` must REFUSE it while Vector runs. Then a burst; once
     Vector has archived all of it (the index is still catching up),
     `ulpf spec compile --restart` applies it with a drained restart.
  C. A short batch through the restarted pipeline.

After A and after C: `ulpf account` (sent = archived = normalized = indexed by
SHA-256 and UID) and no empty line in any archive or normalized file.
The isolated home and its index are deleted at the end unless KEEP=1.

Usage: .venv/bin/python scripts/reload_under_load.py
"""
from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tests"))
import helpers  # noqa: E402

PORTS = {"syslog_udp": "127.0.0.1:25514", "syslog_tcp": "127.0.0.1:25514", "syslog_tls": "127.0.0.1:26514",
         "http_ndjson": "127.0.0.1:28088"}
VENDORS = ["fortigate", "panos", "zeek", "suricata", "asa", "squid", "pfsense"]
EPS_A, COUNT_A, COUNT_B, COUNT_C = 400, 48000, 15000, 1000
T0 = time.time()


def say(msg: str) -> None:
    print(f"[{time.time() - T0:7.1f}s] {msg}", flush=True)


def run(env, *args, check=True, quiet=False):
    say("$ ulpf " + " ".join(args))
    p = helpers.ulpf(env, *args, check=check)
    out = (p.stdout + p.stderr).rstrip()
    if out and not quiet:
        print("\n".join("    " + ln for ln in out.splitlines()[-30:]), flush=True)
    return p


def reloads(home: Path) -> int:
    log = home / "runtime" / "logs" / "vector.log"
    return log.read_text().count("Vector has reloaded") if log.exists() else 0


def wait_for(pred, what: str, timeout: float = 300) -> None:
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return
        time.sleep(1)
    raise SystemExit(f"timed out waiting for {what}")


def lines_in(home: Path, sub: str, pattern: str) -> tuple[int, int]:
    """(event lines, empty lines) over every file of a store."""
    ev = empty = 0
    for f in (home / "runtime" / "data" / sub).glob(pattern):
        for ln in f.read_bytes().split(b"\n")[:-1]:
            ev, empty = (ev, empty + 1) if ln == b"" else (ev + 1, empty)
    return ev, empty


def account(env, sendlogs: list[Path], home: Path, label: str) -> bool:
    both = home / f"sendlog-{label}.ndjson"
    both.write_text("".join(p.read_text() for p in sendlogs))
    rep = json.loads(run(env, "account", "--sendlog", str(both), "--settle", "90", "--json", check=False,
                         quiet=True).stdout)
    keys = ["sent", "archived", "normalized", "indexed", "sent_not_archived", "archived_not_normalized",
            "archived_not_indexed", "archive_uid_duplicates", "settled_after_s", "recorded_losses", "verdict"]
    print("    " + json.dumps({k: rep.get(k) for k in keys}), flush=True)
    a = lines_in(home, "archive/raw", "*/raw-*.ndjson")
    n = lines_in(home, "normalized", "*/events-*.ndjson")
    say(f"{label}: archive {a[0]} records / {a[1]} empty lines; normalized {n[0]} events / {n[1]} empty lines")
    return rep.get("verdict") == "PASS" and rep.get("sent") == rep.get("archived") and a[1] == 0 and n[1] == 0


def main() -> None:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    home = REPO / "runtime" / "demo" / f"reload-{stamp}"
    env = helpers.isolated_home(home)
    cfgp = home / "deploy" / "ulpf.yaml"
    cfg = yaml.safe_load(cfgp.read_text())
    cfg["collector_id"] = "ulpf-reload-collector"
    cfg["listen"].update(PORTS)
    cfg["vector"] = {"api_address": "127.0.0.1:28686", "metrics_address": "127.0.0.1:29598"}
    cfg["opensearch"].update({"index_prefix": "ulpf-reload", "read_alias": "ulpf-reload", "write_alias": "ulpf-reload-write"})
    cfgp.write_text("# test overrides (scripts/reload_under_load.py)\n" + yaml.safe_dump(cfg, sort_keys=False))
    say(f"isolated home: {home.relative_to(REPO)}")
    ok_a = ok_c = refused = False
    try:
        run(env, "spec", "compile", quiet=True)
        run(env, "os", "bootstrap", quiet=True)
        run(env, "stack", "up", "vector")

        say(f"A. {COUNT_A} events at {EPS_A}/s over TCP ({', '.join(VENDORS)}) while specs change")
        sl_a = home / "sendlog-A.ndjson"
        gen = subprocess.Popen([str(Path(sys.executable).with_name("ulpf")), "gen", *sum((["--vendor", v] for v in VENDORS), []),
                                "--count", str(COUNT_A), "--eps", str(EPS_A), "--transport", "tcp", "--seed", "31",
                                "--sendlog", str(sl_a)], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        time.sleep(10)
        if gen.poll() is not None:
            raise SystemExit("the sender exited early:\n" + gen.communicate()[0][-3000:])
        zeek = next(p for p in (home / "specs").rglob("*.yaml") if yaml.safe_load(p.read_text()).get("id", "").startswith("zeek."))
        held = home / "held" / zeek.name
        held.parent.mkdir()
        for step, (src, dst) in enumerate(((zeek, held), (held, zeek)), start=1):
            before = reloads(home)
            src.rename(dst)
            say(f"A{step}. {'retire' if step == 1 else 're-add'} {zeek.name} (traffic running: {gen.poll() is None})")
            rep = json.loads(run(env, "spec", "compile", quiet=True).stdout)
            say(f"    applied={rep['applied']!r} reload_hazards={rep['reload_hazards']} specs={len(rep['specs'])}")
            wait_for(lambda: reloads(home) > before, "the hot reload", timeout=300)
            say(f"    Vector reloaded (traffic still running: {gen.poll() is None})")
        out, _ = gen.communicate(timeout=600)
        say("    sender: " + out.strip().splitlines()[-1] if out.strip() else "    sender done")
        ok_a = account(env, [sl_a], home, "after A")

        say("B. structural change: limits.max_parse_bytes 65536 -> 65535 (pre-parse program)")
        cfg["limits"]["max_parse_bytes"] = int(cfg["limits"]["max_parse_bytes"]) - 1
        cfgp.write_text("# test overrides (scripts/reload_under_load.py)\n" + yaml.safe_dump(cfg, sort_keys=False))
        p = run(env, "spec", "compile", check=False)
        refused = p.returncode != 0 and "structural change" in (p.stdout + p.stderr)
        say(f"    plain compile refused while Vector runs: {refused}")
        sl_b = home / "sendlog-B.ndjson"
        run(env, "gen", *sum((["--vendor", v] for v in VENDORS), []), "--count", str(COUNT_B), "--transport", "tcp",
            "--seed", "32", "--sendlog", str(sl_b))
        total = COUNT_A + COUNT_B
        wait_for(lambda: lines_in(home, "archive/raw", "*/raw-*.ndjson")[0] >= total, "the burst to be archived")
        from ulpf.opensearch import Client

        c = Client.from_settings()
        c.refresh("ulpf-reload")
        say(f"    burst archived; index has {c.count('ulpf-reload')}/{total} -> restart while it drains")
        rep = json.loads(run(env, "spec", "compile", "--restart", quiet=True).stdout)
        say(f"    applied={rep['applied']!r} stop={rep.get('vector_stop')!r} start={rep.get('vector_start')!r}")

        say(f"C. {COUNT_C} events through the restarted pipeline")
        sl_c = home / "sendlog-C.ndjson"
        run(env, "gen", "--vendor", "fortigate", "--vendor", "zeek", "--count", str(COUNT_C), "--transport", "tcp",
            "--seed", "33", "--sendlog", str(sl_c))
        ok_c = account(env, [sl_a, sl_b, sl_c], home, "after B+C")
    finally:
        run(env, "stack", "down", "vector", check=False)
        if os.environ.get("KEEP") != "1":
            from ulpf.opensearch import Client, OpenSearchError

            try:
                c = Client.from_settings()
                for idx in c.alias_targets("ulpf-reload"):
                    c.request("DELETE", f"/{idx}")
                say("deleted the test index (KEEP=1 keeps it)")
            except (OSError, OpenSearchError) as e:
                say(f"could not delete the test index: {e}")
            shutil.rmtree(home, ignore_errors=True)
            say(f"removed {home.relative_to(REPO)} (KEEP=1 keeps it)")
    ok = ok_a and refused and ok_c
    say(f"RELOAD UNDER LOAD: {'PASS' if ok else 'FAIL'} (A hot reloads lossless: {ok_a}; structural change refused: "
        f"{refused}; drained restart + C lossless: {ok_c})")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
