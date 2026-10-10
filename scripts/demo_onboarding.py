#!/usr/bin/env python3
"""Scenario 3, LIVE: an unknown source is onboarded while the pipeline runs.

Runs in an ISOLATED home under runtime/demo/ (own specs, archive, Vector
instance on demo ports, own OpenSearch index) so the repository's specs and
data are untouched. OpenSearch itself is shared (the stack's instance).

  1. start Vector (13 approved specs) on demo ports
  2. send SYNTHETIC "Blackbox Gateway" events over TCP  -> fallback + DLQ
  3. ulpf fingerprint / onboard / (scripted review edit) / gate / promote
  4. Vector hot-reloads the promoted spec (--watch-config, atomic replace)
  5. send more events -> parsed by the new spec; accounting + OpenSearch query

The approval in step 3 is recorded as "Scripted Demo Reviewer" with a note
saying it is a scripted demo -- in production a named human runs promote.
Usage: .venv/bin/python scripts/demo_onboarding.py [N_EVENTS]
"""
from __future__ import annotations

import datetime as dt
import json
import sys
import time
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tests"))
import helpers  # noqa: E402

N = int(sys.argv[1]) if len(sys.argv) > 1 else 200
SPEC = "acme.blackbox.flow"
DEMO_PORTS = {"syslog_udp": "127.0.0.1:15514", "syslog_tcp": "127.0.0.1:15514", "syslog_tls": "127.0.0.1:16514",
              "http_ndjson": "127.0.0.1:18088"}
T0 = time.time()


def say(msg: str) -> None:
    print(f"[{time.time() - T0:7.1f}s] {msg}", flush=True)


def run(env, *args, check=True):
    say("$ ulpf " + " ".join(args))
    p = helpers.ulpf(env, *args, check=check)
    out = (p.stdout + p.stderr).rstrip()
    if out:
        print("\n".join("    " + ln for ln in out.splitlines()[-40:]), flush=True)
    return p


def _client():
    from ulpf.opensearch import Client   # https + CA + credentials when the stack is secured

    return Client.from_settings()


def os_count(index: str, query: dict) -> int:
    return _client().count(index, query)


def os_refresh(index: str) -> None:
    _client().refresh(index)


def wait_for(pred, what: str, timeout: float = 180) -> None:
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return
        time.sleep(2)
    raise SystemExit(f"timed out waiting for {what}")


def normalized_count(home: Path) -> int:
    return sum(sum(1 for _ in open(f)) for f in (home / "runtime" / "data" / "normalized").glob("*/events-*.ndjson"))


def main() -> None:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    home = REPO / "runtime" / "demo" / f"onboarding-{stamp}"
    env = helpers.isolated_home(home)
    cfg = yaml.safe_load((home / "deploy" / "ulpf.yaml").read_text())
    cfg["collector_id"] = "ulpf-demo-collector"
    cfg["listen"].update(DEMO_PORTS)
    cfg["vector"] = {"api_address": "127.0.0.1:18686", "metrics_address": "127.0.0.1:19598"}
    cfg["opensearch"].update({"index_prefix": "ulpf-demo", "read_alias": "ulpf-demo", "write_alias": "ulpf-demo-write"})
    (home / "deploy" / "ulpf.yaml").write_text("# demo overrides (scripts/demo_onboarding.py)\n" + yaml.safe_dump(cfg, sort_keys=False))
    say(f"isolated demo home: {home.relative_to(REPO)}")
    try:
        _client().info()
    except Exception:  # noqa: BLE001
        raise SystemExit("OpenSearch is not running: .venv/bin/ulpf stack up opensearch") from None

    run(env, "spec", "compile")
    run(env, "os", "bootstrap")
    run(env, "stack", "up", "vector")
    sl1 = home / "sendlog-unknown.ndjson"
    run(env, "gen", "--vendor", "blackbox", "--count", str(N), "--transport", "tcp", "--seed", "21", "--sendlog", str(sl1))
    wait_for(lambda: normalized_count(home) >= N, "unknown events to be normalized")
    run(env, "account", "--sendlog", str(sl1))
    fps = json.loads(helpers.ulpf(env, "fingerprint", "--json").stdout)
    run(env, "fingerprint")
    fp = fps[0]["fingerprint"]
    run(env, "onboard", fp, "--id", SPEC, "--vendor", "Blackbox (fictional)", "--product", "Blackbox Gateway",
        "--samples", "synthetic")
    draft = home / "specs" / "_drafts" / f"{SPEC}.yaml"
    run(env, "gate", str(draft))

    say("SCRIPTED REVIEW EDIT: map header field h2 (gateway name) to device.hostname (+host profile)")
    text = draft.read_text()
    text = text.replace("  profiles:\n  - security_control\n", "  profiles: [host, security_control]   # review: host profile for device.*\n", 1)
    text = text.replace("  # not mapped (kept in `unmapped` automatically): h0, h2, h3",
                        "  h2: {to: device.hostname, type: string}  # review: gateway name\n"
                        "  # not mapped (kept in `unmapped` automatically): h0, h3", 1)
    draft.write_text(text)
    run(env, "promote", str(draft), "--approver", "Scripted Demo Reviewer", check=False)   # refused: stale gate
    run(env, "gate", str(draft))
    vlog = home / "runtime" / "logs" / "vector.log"
    reloads_before = vlog.read_text().count("Vector has reloaded")
    run(env, "promote", str(draft), "--approver", "Scripted Demo Reviewer",
        "--note", "scripted demo (scripts/demo_onboarding.py) - not a human review")
    t_promoted = time.time()
    wait_for(lambda: vlog.read_text().count("Vector has reloaded") > reloads_before, "Vector hot reload", timeout=240)
    say(f"Vector reloaded the new configuration {time.time() - t_promoted:.1f}s after promote")

    sl2 = home / "sendlog-after.ndjson"
    run(env, "gen", "--vendor", "blackbox", "--count", str(N), "--transport", "tcp", "--seed", "22", "--sendlog", str(sl2))
    wait_for(lambda: normalized_count(home) >= 2 * N, "post-promotion events to be normalized")
    time.sleep(3)
    both = home / "sendlog-all.ndjson"
    both.write_text(sl1.read_text() + sl2.read_text())
    run(env, "account", "--sendlog", str(both))
    os_refresh("ulpf-demo")
    parsed = os_count("ulpf-demo", {"bool": {"filter": [{"term": {"ulpf.parser.id": SPEC}}, {"term": {"ulpf.status": "parsed"}}]}})
    fallback = os_count("ulpf-demo", {"term": {"ulpf.status": "fallback"}})
    q = {"bool": {"filter": [{"term": {"metadata.product.name": "Blackbox Gateway"}}, {"term": {"action_id": 2}}]}}
    denied = os_count("ulpf-demo", q)
    say(f"OpenSearch ulpf-demo: parsed by {SPEC} = {parsed}, fallback = {fallback}, denied Blackbox flows = {denied}")
    run(env, "drift", "check", "--all-time", check=False)
    say("BACKFILL: re-process the events that arrived while the source was unknown (same document ids)")
    run(env, "replay", "backfill", "--status", "fallback")
    os_refresh("ulpf-demo")
    parsed_after = os_count("ulpf-demo", {"bool": {"filter": [{"term": {"ulpf.parser.id": SPEC}}, {"term": {"ulpf.status": "parsed"}}]}})
    fallback_after = os_count("ulpf-demo", {"term": {"ulpf.status": "fallback"}})
    total_after = os_count("ulpf-demo", {"match_all": {}})
    say(f"after backfill: parsed by {SPEC} = {parsed_after}, fallback = {fallback_after}, documents = {total_after}")
    run(env, "account", "--sendlog", str(both))
    run(env, "scorecard")
    run(env, "stack", "down", "vector")
    ok = parsed == N and fallback == N and parsed_after == 2 * N and fallback_after == 0 and total_after == 2 * N
    say(f"SCENARIO 3 LIVE: {'PASS' if ok else 'FAIL'} ({N} fallback before onboarding, {N} parsed after promotion, "
        f"all {2 * N} parsed after backfill, no duplicates)")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
