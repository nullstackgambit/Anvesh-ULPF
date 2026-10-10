"""Replay from the raw archive (Scenario 6) and backfill.

The raw archive is the source of truth, so any index can be rebuilt with the
current approved specs:

new-index  every archived record (or a time range) is re-processed into a new
           backing index `<prefix>-v<N+1>` by a batch Vector run (same
           pipeline as live, OpenSearch document id = event_uid). After the
           counts verify, the read and write aliases are moved in ONE
           `_aliases` request (atomic for searchers and for the live writer),
           then a catch-up pass replays what was archived meanwhile and any
           document still only in the old index is copied from the archive.
           `ulpf replay rollback --to <index>` moves the aliases back.
backfill   re-process archived events whose indexed status is e.g. fallback
           (after onboarding a source) into the index each document lives in;
           identical `_id` means the fallback document is replaced in place.

Replayed events keep their event_uid, ingest time, collector and transport
and carry `ulpf.replay.run`; the archive bytes are re-verified on the way.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import time
from typing import Iterable, Iterator

from . import paths, pipeline, settings, vector
from .compile import compile_specs
from .opensearch import Client
from .spec import discover


def _ingest_ms(rec: dict) -> int:
    s = rec.get("ingest_time") or ""
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$", s)
    if not m:
        return 0
    base = dt.datetime.fromisoformat(m.group(1)).replace(tzinfo=dt.timezone.utc)
    frac = (m.group(2) or "0")[:3].ljust(3, "0")
    return int(base.timestamp()) * 1000 + int(frac)


def archive_records(*, since_ms: int | None = None, until_ms: int | None = None,
                    uids: set[str] | None = None) -> Iterator[dict]:
    for f in sorted(paths.ARCHIVE_RAW.glob("*/raw-*.ndjson")):
        with open(f, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                rec = json.loads(line)
                if uids is not None and rec.get("event_uid") not in uids:
                    continue
                t = _ingest_ms(rec)
                if (since_ms is not None and t < since_ms) or (until_ms is not None and t >= until_ms):
                    continue
                yield rec


def run_to_index(records: list[dict], index: str, *, run_id: str) -> dict:
    """Batch Vector: archive records -> current approved specs -> `index`."""
    if not records:
        return {"records": 0, "seconds": 0.0}
    s = settings.load()
    pl, _ = compile_specs(discover())
    sink = {"type": "elasticsearch", "endpoints": [s.opensearch_url], "api_version": "v8", "mode": "bulk",
            "bulk": {"index": index, "action": "index"}, "id_key": "_osid",
            "healthcheck": {"enabled": True}, "acknowledgements": {"enabled": True}}
    cfg_dir = paths.RUNTIME / "tmp"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = cfg_dir / f"vector-replay-{run_id}.yaml"
    cfg.write_text(pipeline.dump(pipeline.batch_config(s, pl, replay_run=run_id, sink=sink), specs=pl.parsers,
                                 purpose=f"replay {run_id} -> {index}"))
    (paths.VECTOR_DATA / f"batch-{run_id}").mkdir(parents=True, exist_ok=True)
    t = time.time()
    stdin = "".join(json.dumps(r) + "\n" for r in records).encode()
    _, err = vector.run_batch(cfg, stdin, timeout=max(300, len(records) / 200))
    problems = [ln for ln in err.splitlines() if " ERROR " in ln or ("WARN" in ln and "dropped" in ln.lower())]
    return {"records": len(records), "seconds": round(time.time() - t, 2), "vector_problems": problems[:10]}


def index_versions(client: Client, prefix: str) -> list[tuple[int, str]]:
    res = client.request("GET", f"/_cat/indices/{prefix}-v*?format=json&h=index")
    out = []
    for row in res if isinstance(res, list) else []:
        m = re.fullmatch(re.escape(prefix) + r"-v(\d+)", row["index"])
        if m:
            out.append((int(m.group(1)), row["index"]))
    return sorted(out)


def _uids_in(client: Client, index: str, uids: list[str]) -> set[str]:
    found: set[str] = set()
    for i in range(0, len(uids), 1000):
        chunk = uids[i:i + 1000]
        res = client.request("POST", f"/{index}/_mget", {"ids": chunk})
        found.update(d["_id"] for d in res.get("docs", []) if d.get("found"))
    return found


def _status_counts(client: Client, index: str) -> dict:
    res = client.search(index, {"size": 0, "aggs": {"s": {"terms": {"field": "ulpf.status", "size": 10}}}})
    return {b["key"]: b["doc_count"] for b in res["aggregations"]["s"]["buckets"]}


def replay_new_index(*, switch: bool = True, since_ms: int | None = None, until_ms: int | None = None,
                     client: Client | None = None) -> dict:
    s = settings.load()
    osc = s["opensearch"]
    c = client or Client.from_settings(s)
    run_id = "replay-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    t_start_ms = int(time.time() * 1000)
    versions = index_versions(c, osc["index_prefix"])
    new = f"{osc['index_prefix']}-v{(versions[-1][0] if versions else 0) + 1}"
    old_read, old_write = c.alias_targets(osc["read_alias"]), c.alias_targets(osc["write_alias"])
    c.request("PUT", f"/{new}", {})            # template applies by name pattern
    records = list(archive_records(since_ms=since_ms, until_ms=until_ms))
    uniq = {r["event_uid"] for r in records}
    rep: dict = {"run": run_id, "new_index": new, "old_read": old_read, "old_write": old_write,
                 "archive_records": len(records), "distinct_event_uids": len(uniq)}
    rep["replay"] = run_to_index(records, new, run_id=run_id)
    c.refresh(new)
    rep["new_count"] = c.count(new)
    rep["new_status"] = _status_counts(c, new)
    rep["old_status"] = _status_counts(c, osc["read_alias"]) if old_read else {}
    verified = rep["new_count"] == len(uniq)
    rep["verified"] = verified
    if not verified:
        rep["switched"] = False
        rep["note"] = "count mismatch: aliases NOT switched; the new index is left for inspection"
        return rep
    if not switch:
        rep["switched"] = False
        return rep
    actions = [{"remove": {"index": i, "alias": osc["read_alias"]}} for i in old_read]
    actions += [{"remove": {"index": i, "alias": osc["write_alias"]}} for i in old_write]
    actions += [{"add": {"index": new, "alias": osc["read_alias"]}},
                {"add": {"index": new, "alias": osc["write_alias"], "is_write_index": True}}]
    c.aliases(actions)                        # one request: atomic
    rep["switched"] = True
    rep["switched_at"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")
    # catch-up: archived while the replay ran (overlap is harmless: same _id)
    time.sleep(5)
    late = list(archive_records(since_ms=t_start_ms - 60_000))
    rep["catch_up"] = run_to_index(late, new, run_id=run_id + "-catchup")
    # anything indexed in the old index since the start but still missing in the new one
    missing: list[str] = []
    for old in old_write:
        c.refresh(old)
        q = {"range": {"ulpf.ingest.time": {"gte": dt.datetime.fromtimestamp((t_start_ms - 60_000) / 1000, dt.timezone.utc).isoformat()}}}
        recent = [h["_id"] for h in c.scroll_all(old, q, source=False)]
        missing += sorted(set(recent) - _uids_in(c, new, recent))
    if missing:
        rep["catch_up_2"] = run_to_index(list(archive_records(uids=set(missing))), new, run_id=run_id + "-catchup2")
    c.refresh(new)
    still = []
    if missing:
        still = sorted(set(missing) - _uids_in(c, new, missing))
    rep["missing_after_catch_up"] = still
    rep["final_count"] = c.count(new)
    _log(rep)
    return rep


def backfill(*, statuses: Iterable[str] = ("fallback",), client: Client | None = None) -> dict:
    s = settings.load()
    osc = s["opensearch"]
    c = client or Client.from_settings(s)
    run_id = "backfill-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    statuses = list(statuses)
    by_index: dict[str, list[str]] = {}
    q = {"terms": {"ulpf.status": statuses}}
    for h in c.scroll_all(osc["read_alias"], q, source=False):
        by_index.setdefault(h["_index"], []).append(h["_id"])
    rep: dict = {"run": run_id, "selected": {k: len(v) for k, v in by_index.items()}, "statuses": statuses, "runs": {}}
    for index, uids in by_index.items():
        recs = list(archive_records(uids=set(uids)))
        rep["runs"][index] = run_to_index(recs, index, run_id=f"{run_id}-{index}")
        rep["runs"][index]["archive_records_found"] = len(recs)
        c.refresh(index)
    after: dict[str, int] = {}
    for index, uids in by_index.items():
        for i in range(0, len(uids), 1000):
            res = c.request("POST", f"/{index}/_mget?_source_includes=ulpf.status,ulpf.parser.id", {"ids": uids[i:i + 1000]})
            for d in res.get("docs", []):
                if d.get("found"):
                    u = (d["_source"].get("ulpf") or {})
                    k = f"{u.get('status')}:{(u.get('parser') or {}).get('id')}"
                    after[k] = after.get(k, 0) + 1
    rep["after"] = after
    _log(rep)
    return rep


def missing(*, client: Client | None = None) -> dict:
    """Re-index archived events that are absent from the index (e.g. dropped
    by the OpenSearch sink's full buffer during an outage)."""
    s = settings.load()
    osc = s["opensearch"]
    c = client or Client.from_settings(s)
    run_id = "missing-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    c.refresh(osc["read_alias"])
    indexed = {h["_id"] for h in c.scroll_all(osc["read_alias"], None, source=False)}
    recs = [r for r in archive_records() if r["event_uid"] not in indexed]
    rep: dict = {"run": run_id, "indexed_before": len(indexed), "missing": len(recs)}
    if recs:
        rep["replay"] = run_to_index(recs, osc["write_alias"], run_id=run_id)
        c.refresh(osc["read_alias"])
        now = {h["_id"] for h in c.scroll_all(osc["read_alias"], None, source=False)}
        rep["still_missing"] = sorted({r["event_uid"] for r in recs} - now)[:50]
    _log(rep)
    return rep


def rollback(to_index: str, client: Client | None = None) -> dict:
    s = settings.load()
    osc = s["opensearch"]
    c = client or Client.from_settings(s)
    if not c.exists(to_index):
        raise ValueError(f"index {to_index} does not exist")
    cur_r, cur_w = c.alias_targets(osc["read_alias"]), c.alias_targets(osc["write_alias"])
    actions = [{"remove": {"index": i, "alias": osc["read_alias"]}} for i in cur_r]
    actions += [{"remove": {"index": i, "alias": osc["write_alias"]}} for i in cur_w]
    actions += [{"add": {"index": to_index, "alias": osc["read_alias"]}},
                {"add": {"index": to_index, "alias": osc["write_alias"], "is_write_index": True}}]
    c.aliases(actions)
    rep = {"event": "rollback", "from_read": cur_r, "from_write": cur_w, "to": to_index}
    _log(rep)
    return rep


def _log(rep: dict) -> None:
    paths.STATE.mkdir(parents=True, exist_ok=True)
    with open(paths.STATE / "replays.ndjson", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), **rep}, default=str) + "\n")
