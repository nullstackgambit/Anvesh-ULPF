"""Detections over normalized OCSF events (downstream demos of ULPF's output).

* Sigma: rules in detections/sigma/rules are converted with pySigma and the
  OpenSearch Lucene backend through the ULPF pipeline
  (detections/sigma/pipelines/ulpf_ocsf.yml: firewall logsource -> OCSF
  Network Activity, rule field names -> OCSF paths). One rule therefore
  matches every vendor ULPF normalizes.
* Anomaly: an unsupervised IsolationForest over per-source time windows
  (log1p of event count, distinct destination ports, distinct destination
  hosts, denied events). It ranks sources; flags are reported with the
  feature values that explain them. Trees are built on the full window set
  (max_samples=1.0 up to 50k windows): with the default 256-point subsample,
  thousands of near-identical windows masked a 500-port scanner (rank 26 vs
  rank 1; verification/scenario8_anomaly.md).

Both read the index; neither feeds back into normalization.
"""
from __future__ import annotations

import datetime as dt
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from . import paths

SIGMA = paths.DETECTIONS / "sigma"


# ------------------------------------------------------------------- sigma
def sigma_queries(rules_dir: Path | None = None, pipeline_file: Path | None = None) -> list[dict]:
    from sigma.backends.opensearch import OpensearchLuceneBackend
    from sigma.collection import SigmaCollection
    from sigma.processing.pipeline import ProcessingPipeline

    pipe = ProcessingPipeline.from_yaml((pipeline_file or SIGMA / "pipelines" / "ulpf_ocsf.yml").read_text())
    backend = OpensearchLuceneBackend(processing_pipeline=pipe)
    out = []
    for f in sorted((rules_dir or SIGMA / "rules").glob("*.yml")):
        col = SigmaCollection.from_yaml(f.read_text())
        for rule in col.rules:
            queries = backend.convert(SigmaCollection([rule]))
            out.append({"id": str(rule.id), "title": rule.title, "level": str(rule.level.name).lower() if rule.level else None,
                        "file": str(f.relative_to(paths.HOME)) if paths.HOME in f.parents else str(f), "queries": list(queries)})
    return out


def run_sigma(client, index: str, *, since_minutes: float | None = None, samples: int = 3,
              rules_dir: Path | None = None) -> list[dict]:
    results = []
    for r in sigma_queries(rules_dir):
        for q in r["queries"]:
            flt = []
            if since_minutes is not None:
                start = int((dt.datetime.now(dt.timezone.utc).timestamp() - since_minutes * 60) * 1000)
                flt.append({"range": {"time": {"gte": start}}})
            body = {"size": samples, "track_total_hits": True,
                    "query": {"bool": {"must": [{"query_string": {"query": q, "analyze_wildcard": True}}], "filter": flt}},
                    "sort": [{"time": "desc"}],
                    "_source": ["metadata.uid", "metadata.product.name", "src_endpoint.ip", "dst_endpoint.ip", "dst_endpoint.port",
                                "action", "ulpf.parser.id", "time"],
                    "aggs": {"products": {"terms": {"field": "metadata.product.name", "size": 20}}}}
            res = client.search(index, body)
            results.append({**{k: r[k] for k in ("id", "title", "level", "file")}, "query": q,
                            "hits": res["hits"]["total"]["value"],
                            "products": {b["key"]: b["doc_count"] for b in res["aggregations"]["products"]["buckets"]},
                            "samples": [h["_source"] for h in res["hits"]["hits"]]})
    return results


# ----------------------------------------------------------------- anomaly
FEATURES = ["events", "distinct_dst_ports", "distinct_dst_hosts", "denied_events"]


@dataclass
class Window:
    src_ip: str
    start_ms: int
    events: int = 0
    ports: set = field(default_factory=set)
    hosts: set = field(default_factory=set)
    denied: int = 0
    uids: list = field(default_factory=list)

    def vector(self) -> list[float]:
        return [self.events, len(self.ports), len(self.hosts), self.denied]


def windows(events: Iterable[dict], window_s: int = 60) -> list[Window]:
    w: dict[tuple, Window] = {}
    size = window_s * 1000
    for e in events:
        src = (e.get("src_endpoint") or {}).get("ip")
        t = e.get("time")
        if not src or t is None:
            continue
        key = (src, t // size)
        win = w.get(key) or w.setdefault(key, Window(src, (t // size) * size))
        win.events += 1
        dst = e.get("dst_endpoint") or {}
        if dst.get("port") is not None:
            win.ports.add(dst["port"])
        if dst.get("ip"):
            win.hosts.add(dst["ip"])
        if e.get("action_id") == 2:
            win.denied += 1
        if len(win.uids) < 5:
            win.uids.append((e.get("metadata") or {}).get("uid"))
    return sorted(w.values(), key=lambda x: (x.start_ms, x.src_ip))


def detect_anomalies(events: Iterable[dict], *, window_s: int = 60, seed: int = 0, top: int = 10,
                     contamination: str | float = "auto") -> dict:
    import numpy as np
    from sklearn.ensemble import IsolationForest

    ws = windows(events, window_s)
    if len(ws) < 10:
        return {"windows": len(ws), "flagged": [], "note": "fewer than 10 source windows: not enough data"}
    X = np.array([w.vector() for w in ws], dtype=float)
    Xt = np.log1p(X)      # counts: one huge burst must not flatten everything else
    max_samples = 1.0 if len(ws) <= 50_000 else 50_000 / len(ws)
    model = IsolationForest(n_estimators=200, random_state=seed, contamination=contamination,
                            max_samples=max_samples).fit(Xt)
    score = -model.score_samples(Xt)          # higher = more anomalous
    pred = model.predict(Xt)                  # -1 = outlier
    med = np.median(X, axis=0)
    order = sorted(range(len(ws)), key=lambda i: -score[i])
    flagged = []
    for i in order:
        if pred[i] != -1:
            continue
        w = ws[i]
        why = {f: {"value": round(float(X[i, k]), 3), "median": round(float(med[k]), 3)}
               for k, f in enumerate(FEATURES) if X[i, k] > med[k] * 3 + 1}
        flagged.append({"src_ip": w.src_ip, "window_start": dt.datetime.fromtimestamp(w.start_ms / 1000, dt.timezone.utc).isoformat(),
                        "score": round(float(score[i]), 4), "features": dict(zip(FEATURES, (round(float(v), 3) for v in X[i]))),
                        "explanation": why, "sample_event_uids": w.uids})
    return {"windows": len(ws), "model": "IsolationForest(n_estimators=200, contamination=%r, max_samples=%s, random_state=%d)"
            % (contamination, max_samples, seed), "features": FEATURES, "window_s": window_s, "flagged_count": len(flagged),
            "flagged": flagged[:top], "all_flagged": [(f["src_ip"], f["window_start"], f["score"]) for f in flagged],
            "score_threshold": None if not flagged else min(f["score"] for f in flagged)}


def network_events(client, index: str, *, since_minutes: float | None = None) -> Iterable[dict]:
    q: dict = {"bool": {"filter": [{"term": {"class_uid": 4001}}]}}
    if since_minutes is not None:
        start = int((dt.datetime.now(dt.timezone.utc).timestamp() - since_minutes * 60) * 1000)
        q["bool"]["filter"].append({"range": {"time": {"gte": start}}})
    src = ["time", "src_endpoint.ip", "dst_endpoint.ip", "dst_endpoint.port", "action_id", "metadata.uid"]
    for h in client.scroll_all(index, q, source=src):
        yield h["_source"]


def evaluate(report: dict, truth_src: str) -> dict:
    """Against a known scanner address (SYNTHETIC scenario ground truth),
    over ALL flagged windows (not just the top-N shown)."""
    flagged = report.get("all_flagged") or []
    hit = [f for f in flagged if f[0] == truth_src]
    return {"scanner": truth_src, "windows": report.get("windows"), "flagged": len(flagged),
            "scanner_windows_flagged": len(hit), "other_windows_flagged": len(flagged) - len(hit),
            "scanner_rank": next((i + 1 for i, f in enumerate(flagged) if f[0] == truth_src), None)}
