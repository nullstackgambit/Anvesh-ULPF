#!/usr/bin/env python3
"""ULPF benchmark against the RUNNING stack (SYNTHETIC TEST DATA).

For each target rate (and "max" = as fast as the generator can send) a burst
of mixed-vendor traffic is sent over TCP; then we wait until every event is
archived, normalized and indexed, and measure from the system itself:

  throughput   sent events/s (generator), end-to-end events/s and MB/s
               (first send -> last event indexed and on disk)
  latency      per event: sender timestamp -> metadata.processed_time (Vector
               finalize) for every event, p50/p95/p99/max
  resources    CPU seconds and peak RSS of the Vector and OpenSearch processes
               (/proc), sampled every 0.5 s
  quality      parsed / partial / fallback / failed rates, mean mapped-field ratio
  storage      raw bytes vs archive NDJSON vs normalized NDJSON vs OpenSearch
               primary store delta (index stats)

Results: verification/benchmark-<UTC>.json. Larger figures (events/day) are
EXTRAPOLATED from the measured rate and labelled as such.
Usage: .venv/bin/python scripts/benchmark.py [--rates 200,500,1000,max] [--seconds 20]
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import hashlib
import json
import os
import statistics
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from ulpf import paths  # noqa: E402
from ulpf.opensearch import Client  # noqa: E402
from ulpf.settings import load  # noqa: E402

VENDORS = ["fortigate", "panos", "suricata", "zeek", "asa", "pfsense"]
TICK = os.sysconf("SC_CLK_TCK")


def pid_of(name: str) -> int | None:
    p = paths.RUN / f"{name}.pid"
    try:
        pid = int(p.read_text().strip())
        os.kill(pid, 0)
        return pid
    except (OSError, ValueError):
        return None


def proc_stats(pid: int) -> tuple[float, int]:
    """(cpu seconds incl. children threads, rss bytes) of a process and its children."""
    cpu, rss = 0.0, 0
    pids = [pid]
    try:
        pids += [int(x) for x in Path(f"/proc/{pid}/task/{pid}/children").read_text().split()]
    except OSError:
        pass
    for p in pids:
        try:
            st = Path(f"/proc/{p}/stat").read_text().rsplit(")", 1)[1].split()
            cpu += (int(st[11]) + int(st[12])) / TICK
            for line in Path(f"/proc/{p}/status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    rss += int(line.split()[1]) * 1024
        except OSError:
            pass
    return cpu, rss


class Sampler(threading.Thread):
    def __init__(self, pids: dict[str, int]):
        super().__init__(daemon=True)
        self.pids, self.stop_ev = pids, threading.Event()
        self.start_cpu = {k: proc_stats(v)[0] for k, v in pids.items()}
        self.peak_rss = {k: 0 for k in pids}

    def run(self):
        while not self.stop_ev.is_set():
            for k, pid in self.pids.items():
                self.peak_rss[k] = max(self.peak_rss[k], proc_stats(pid)[1])
            time.sleep(0.5)

    def finish(self, wall: float) -> dict:
        self.stop_ev.set()
        self.join()
        out = {}
        for k, pid in self.pids.items():
            cpu = proc_stats(pid)[0] - self.start_cpu[k]
            out[k] = {"cpu_seconds": round(cpu, 2), "avg_cores": round(cpu / wall, 2) if wall else None,
                      "peak_rss_mb": round(self.peak_rss[k] / 2**20, 1)}
        return out


def store_bytes(c: Client) -> int:
    s = load()["opensearch"]
    res = c.request("GET", f"/{s['read_alias']}/_stats/store")
    return int(res["_all"]["primaries"]["store"]["size_in_bytes"])


def files_bytes(pattern: str) -> int:
    return sum(os.path.getsize(f) for f in glob.glob(pattern))


def percentile(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else None


def run_rate(rate: str, seconds: int, c: Client, seed: int) -> dict:
    s = load()
    n = 4000 if rate == "max" else int(float(rate) * seconds)
    sl = paths.DATA / f"bench-sendlog-{rate}-{int(time.time())}.ndjson"
    arch0, norm0 = files_bytes(str(paths.ARCHIVE_RAW / "*/raw-*.ndjson")), files_bytes(str(paths.NORMALIZED / "*/events-*.ndjson"))
    c.request("POST", f"/{s['read_alias']}/_flush")
    store0 = store_bytes(c)
    pids = {k: p for k in ("vector", "opensearch") if (p := pid_of(k))}
    sampler = Sampler(pids)
    sampler.start()
    t0 = time.time()
    cmd = [str(REPO / ".venv/bin/ulpf"), "gen", "--count", str(n), "--transport", "tcp", "--seed", str(seed), "--sendlog", str(sl)]
    for v in VENDORS:
        cmd += ["--vendor", v]
    if rate != "max":
        cmd += ["--eps", rate]
    subprocess.run(cmd, check=True, capture_output=True)
    t_sent = time.time()
    sent = [json.loads(x) for x in sl.read_text().splitlines()]
    shas = {r["sha256"]: r["sent_at"] for r in sent}
    raw_bytes = sum(r["len"] for r in sent)
    # wait until every event is searchable
    want = set(shas)
    deadline = time.time() + 600
    found: dict[str, dict] = {}
    while time.time() < deadline:
        c.refresh(s["opensearch"]["read_alias"])
        q = {"bool": {"filter": [{"range": {"ulpf.ingest.time": {"gte": dt.datetime.fromtimestamp(t0 - 5, dt.timezone.utc).isoformat()}}}]}}
        src = ["raw_data_hash.value", "metadata.processed_time", "ulpf.status", "ulpf.coverage"]
        found = {h["_source"]["raw_data_hash"]["value"]: h["_source"] for h in c.scroll_all(s["opensearch"]["read_alias"], q, source=src)}
        if want <= set(found):
            break
        time.sleep(1)
    t_indexed = time.time()
    # archive/normalized on disk
    while time.time() < deadline:
        a = files_bytes(str(paths.ARCHIVE_RAW / "*/raw-*.ndjson")) - arch0
        time.sleep(1.5)
        if files_bytes(str(paths.ARCHIVE_RAW / "*/raw-*.ndjson")) - arch0 == a and a > 0:
            break
    t_disk = time.time()
    wall = max(t_indexed, t_disk) - t0
    res = sampler.finish(wall)
    c.request("POST", f"/{s['read_alias']}/_flush")
    store1 = store_bytes(c)
    lat = [(found[h]["metadata"]["processed_time"] / 1000 - shas[h]) * 1000 for h in want if h in found]
    st = {}
    ratios = []
    for h in want:
        d = found.get(h)
        if not d:
            continue
        u = d.get("ulpf") or {}
        st[u.get("status")] = st.get(u.get("status"), 0) + 1
        cov = u.get("coverage") or {}
        if cov.get("fields"):
            ratios.append(cov.get("mapped", 0) / max(cov["fields"] - cov.get("empty", 0), 1))
    arch = files_bytes(str(paths.ARCHIVE_RAW / "*/raw-*.ndjson")) - arch0
    norm = files_bytes(str(paths.NORMALIZED / "*/events-*.ndjson")) - norm0
    got = len(want & set(found))
    return {
        "target_eps": rate, "events": n, "indexed": got, "missing": n - got,
        "send_seconds": round(t_sent - t0, 2), "sent_eps": round(n / (t_sent - t0), 1),
        "end_to_end_seconds": round(wall, 2), "end_to_end_eps": round(n / wall, 1),
        "raw_mb_per_s": round(raw_bytes / wall / 1e6, 3),
        "latency_ms_send_to_normalized": {"p50": round(percentile(lat, 0.5), 1), "p95": round(percentile(lat, 0.95), 1),
                                          "p99": round(percentile(lat, 0.99), 1), "max": round(max(lat), 1)} if lat else None,
        "resources": res,
        "status": st, "mean_mapped_ratio": round(statistics.fmean(ratios), 4) if ratios else None,
        "storage_bytes": {"raw": raw_bytes, "archive_ndjson": arch, "normalized_ndjson": norm, "opensearch_primary_delta": store1 - store0},
        "storage_expansion_vs_raw": {"archive": round(arch / raw_bytes, 2), "normalized": round(norm / raw_bytes, 2),
                                     "opensearch": round((store1 - store0) / raw_bytes, 2)},
        "events_per_day_EXTRAPOLATED": int(n / wall * 86400),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rates", default="200,500,1000,max")
    ap.add_argument("--seconds", type=int, default=20)
    a = ap.parse_args()
    s = load()
    c = Client.from_settings(s)
    host = {"cpus": os.cpu_count(), "mem_gb": round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2**30, 1),
            "loadavg_before": os.getloadavg(), "kernel": os.uname().release,
            "note": "single VM: generator, Vector, OpenSearch (secured, 1 GB heap) and UI share the host"}
    out = {"started": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "host": host,
           "opensearch_security": bool(s["opensearch"].get("security")), "vendors": VENDORS, "runs": []}
    for i, r in enumerate(a.rates.split(",")):
        print(f"rate {r} ...", flush=True)
        res = run_rate(r, a.seconds, c, seed=100 + i)
        out["runs"].append(res)
        print(json.dumps({k: res[k] for k in ("target_eps", "events", "missing", "sent_eps", "end_to_end_eps",
                                              "latency_ms_send_to_normalized")}), flush=True)
        time.sleep(5)
    p = REPO / "verification" / f"benchmark-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    p.write_text(json.dumps(out, indent=2) + "\n")
    print(f"written {p.relative_to(REPO)}")


if __name__ == "__main__":
    main()
