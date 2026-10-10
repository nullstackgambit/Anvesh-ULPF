"""Test helpers: isolated ULPF homes and seeding of unknown-source traffic.

`isolated_home()` builds a throwaway ULPF_HOME (symlinked schema and static
VRL, copied specs/goldens/config) so control-plane commands that write specs,
goldens, baselines and the live config can be exercised end to end without
touching the repository. Because ulpf.paths is resolved at import time,
commands run in a subprocess with the returned environment.

`python tests/helpers.py seed-unknown N SEED TRUTH_FILE` (inside such an
environment) renders SYNTHETIC TEST DATA for the fictional "Blackbox
Gateway", writes it to the raw archive exactly as the live archive sink would,
pushes it through the real batch pipeline (approved specs) and writes the
resulting fallback events to the DLQ and normalized store -- i.e. the state
the live system is in after receiving traffic from an unknown source.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import random
import secrets
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def isolated_home(dst: Path, *, share_credentials: bool = True) -> dict[str, str]:
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "pipeline" / "vector").mkdir(parents=True, exist_ok=True)
    (dst / "tests").mkdir(exist_ok=True)
    (dst / "deploy").mkdir(exist_ok=True)
    os.symlink(REPO / "schema", dst / "schema")
    os.symlink(REPO / "pipeline" / "vector" / "static", dst / "pipeline" / "vector" / "static")
    shutil.copytree(REPO / "specs", dst / "specs", ignore=shutil.ignore_patterns("_drafts"))
    shutil.copytree(REPO / "tests" / "golden", dst / "tests" / "golden", ignore=shutil.ignore_patterns("*.py", "__pycache__"))
    shutil.copy2(REPO / "deploy" / "ulpf.yaml", dst / "deploy" / "ulpf.yaml")
    env = dict(os.environ)
    env.update({"ULPF_HOME": str(dst), "ULPF_RUNTIME": str(dst / "runtime"),
                "ULPF_VECTOR_BIN": str(REPO / "runtime" / "vector" / "bin" / "vector"),
                "ULPF_KEYS": str(dst / "deploy" / "keys"), "ULPF_SECRETS": str(dst / "runtime" / "secrets"),
                "ULPF_CERTS": str(dst / "deploy" / "certs")})
    if share_credentials:
        # same deployment: talk to the shared (possibly secured) OpenSearch with
        # the deployment's CA, users and security switch
        if (REPO / "runtime" / "secrets").exists():
            env["ULPF_SECRETS"] = str(REPO / "runtime" / "secrets")
        if (REPO / "deploy" / "certs").exists():
            env["ULPF_CERTS"] = str(REPO / "deploy" / "certs")
        local = REPO / "runtime" / "ulpf.local.yaml"
        if local.exists():
            (dst / "runtime").mkdir(parents=True, exist_ok=True)
            shutil.copy2(local, dst / "runtime" / "ulpf.local.yaml")
    env.pop("ULPF_CONFIG", None)
    env.pop("ULPF_DATA", None)
    return env


def ulpf(env: dict, *args: str, check: bool = True, timeout: float = 600) -> subprocess.CompletedProcess:
    exe = Path(sys.executable).with_name("ulpf")
    p = subprocess.run([str(exe), *args], env=env, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise AssertionError(f"ulpf {' '.join(args)} -> {p.returncode}\nSTDOUT:\n{p.stdout[-4000:]}\nSTDERR:\n{p.stderr[-4000:]}")
    return p


def uuid7(ms: int) -> str:
    b = bytearray(ms.to_bytes(6, "big") + secrets.token_bytes(10))
    b[6] = (b[6] & 0x0F) | 0x70
    b[8] = (b[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(b)))


def seed_unknown(n: int, seed: int, truth_file: Path, *, renderer: str = "blackbox") -> None:
    from ulpf import gen, paths
    from ulpf.spec import discover
    from ulpf.testing import archive_record, run_records

    rng = random.Random(seed)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(minutes=5)
    cid = "ulpf-collector-01"
    records, truth = [], []
    for i in range(n):
        f = gen.random_flow(rng, when=now + dt.timedelta(seconds=i, milliseconds=rng.randint(0, 999)),
                            action="allow" if i % 4 else "deny")
        raw = gen.RENDERERS[renderer](f)
        t = now + dt.timedelta(seconds=i, milliseconds=500)
        ms = int(t.timestamp() * 1000)
        uid = uuid7(ms)
        rec = archive_record(uid, raw, ingest_time=t.strftime("%Y-%m-%dT%H:%M:%S.%f000Z"), transport="tcp", collector=cid)
        rec["peer"] = {"ip": "127.0.0.1"}
        records.append(rec)
        truth.append({"event_uid": uid, "src_ip": f.src_ip, "src_port": f.src_port, "dst_ip": f.dst_ip,
                      "dst_port": f.dst_port, "proto": f.proto, "proto_num": f.proto_num, "bytes_out": f.bytes_out,
                      "bytes_in": f.bytes_in, "action": f.action, "time_ms": int(f.time.timestamp() * 1000)})
    day = now.strftime("%Y-%m-%d")
    bucket = now.strftime("%Y%m%dT%H%M")
    arch = paths.ARCHIVE_RAW / day / f"raw-{bucket}-{cid}.ndjson"
    arch.parent.mkdir(parents=True, exist_ok=True)
    with open(arch, "a", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    events = run_records(discover(), records, replay_run="seed")
    for root, name, keep in ((paths.NORMALIZED, "events", lambda e: True),
                             (paths.DLQ, "dlq", lambda e: e["ulpf"]["status"] in ("fallback", "failed"))):
        p = root / day / f"{name}-{bucket}-{cid}.ndjson"
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as fh:
            for e in events:
                if keep(e):
                    e.get("ulpf", {}).pop("replay", None)  # live events carry no replay marker
                    fh.write(json.dumps(e) + "\n")
    truth_file.write_text("".join(json.dumps(t) + "\n" for t in truth))


def replay_check(truth_file: Path, spec_id: str) -> dict:
    """Replay every archived record through the CURRENT approved specs and
    compare the normalized output with the generator's ground truth."""
    from ulpf import paths
    from ulpf.spec import discover
    from ulpf.testing import run_records

    truth = {t["event_uid"]: t for t in map(json.loads, truth_file.read_text().splitlines())}
    records = [json.loads(line) for f in sorted(paths.ARCHIVE_RAW.glob("*/raw-*.ndjson"))
               for line in f.read_text().splitlines() if line.strip()]
    records = [r for r in records if r["event_uid"] in truth]
    events = run_records(discover(), records, replay_run="check")
    bad = []
    status = {}
    for e in events:
        t = truth[e["metadata"]["uid"]]
        u = e["ulpf"]
        status[u["status"]] = status.get(u["status"], 0) + 1
        got = ((u.get("parser") or {}).get("id"), e.get("src_endpoint", {}).get("ip"), e.get("src_endpoint", {}).get("port"),
               e.get("dst_endpoint", {}).get("ip"), e.get("dst_endpoint", {}).get("port"),
               e.get("connection_info", {}).get("protocol_num"), e.get("traffic", {}).get("bytes_out"),
               e.get("traffic", {}).get("bytes_in"), e.get("action_id"), e.get("time"))
        want = (spec_id, t["src_ip"], t["src_port"], t["dst_ip"], t["dst_port"], t["proto_num"], t["bytes_out"],
                t["bytes_in"], {"allow": 1, "deny": 2}[t["action"]], t["time_ms"])
        if got != want or u["status"] != "parsed":
            bad.append({"uid": t["event_uid"], "got": got, "want": want, "status": u["status"]})
    return {"records": len(records), "events": len(events), "status": status, "mismatches": bad[:10], "n_bad": len(bad)}


if __name__ == "__main__":
    if sys.argv[1] == "seed-unknown":
        seed_unknown(int(sys.argv[2]), int(sys.argv[3]), Path(sys.argv[4]),
                     renderer=sys.argv[5] if len(sys.argv) > 5 else "blackbox")
    elif sys.argv[1] == "replay-check":
        print(json.dumps(replay_check(Path(sys.argv[2]), sys.argv[3])))
    else:
        raise SystemExit(f"unknown command {sys.argv[1]}")
