"""`ulpf repair`: close accounting gaps after an incident.

1. indexed but not archived (e.g. events in flight in replaced archive
   components during a Vector hot reload - P6 finding): the original bytes are
   taken from the indexed document (`ulpf.raw.b64`, else `raw_data`) and
   accepted ONLY if their SHA-256 and length equal the values the envelope
   computed at ingest (`ulpf.raw.sha256` / `raw_data_hash` / `ulpf.raw.len`).
   They are written to a NEW archive file `raw-<bucket>-<collector>-recovered-
   <time>.ndjson`, each record flagged `"recovered": {"from": "opensearch",...}`
   so they are never mistaken for records the archive sink wrote itself.
   Trust note: SHA-256 makes the bytes identical to what was hashed at
   ingest, but that hash was read back from the (unsealed) index; review
   recovered records before relying on them as evidence.
2. archived but not in the normalized store: the archive records are run
   through the current specs (batch Vector) and written to
   `events-<bucket>-<collector>-recovered-<time>.ndjson` (they carry
   `ulpf.replay.run`).
3. archived but not indexed: `ulpf replay missing`.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
from pathlib import Path

from . import paths, settings
from .accounting import archive_records, normalized_events
from .opensearch import Client


def _stamp() -> tuple[str, str]:
    now = dt.datetime.now(dt.timezone.utc)
    return now.strftime(settings.load().archive_bucket_format), now.strftime("%H%M%S")


def recover_archive_from_index(*, dry_run: bool = False, client: Client | None = None) -> dict:
    s = settings.load()
    c = client or Client.from_settings(s)
    archived = {r["event_uid"] for r in archive_records()}
    alias = s["opensearch"]["read_alias"]
    c.refresh(alias)
    src = ["ulpf.event_uid", "ulpf.ingest", "ulpf.raw", "raw_data", "raw_data_hash", "metadata.uid"]
    good, bad = [], []
    for h in c.scroll_all(alias, None, source=src):
        if h["_id"] in archived:
            continue
        d = h["_source"]
        u = d.get("ulpf") or {}
        raw_meta = u.get("raw") or {}
        if raw_meta.get("b64") is not None:
            raw = base64.b64decode(raw_meta["b64"])
        elif d.get("raw_data") is not None:
            raw = d["raw_data"].encode("utf-8")
        else:
            bad.append({"uid": h["_id"], "why": "no raw bytes in the indexed document"})
            continue
        sha = hashlib.sha256(raw).hexdigest()
        if sha != raw_meta.get("sha256") or sha != (d.get("raw_data_hash") or {}).get("value") or len(raw) != raw_meta.get("len"):
            bad.append({"uid": h["_id"], "why": "bytes do not match the ingest-time sha256/length"})
            continue
        ing = u.get("ingest") or {}
        good.append({"v": 1, "event_uid": h["_id"], "ingest_time": ing.get("time"), "collector_id": ing.get("collector_id"),
                     "transport": ing.get("transport"), "peer": ing.get("peer") or {}, "raw_len": len(raw),
                     "raw_sha256": sha, "raw_b64": base64.b64encode(raw).decode(),
                     "recovered": {"from": "opensearch", "index": h["_index"],
                                   "at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}})
    rep: dict = {"indexed_not_archived": len(good) + len(bad), "recoverable": len(good), "rejected": bad[:20], "written": None}
    if good and not dry_run:
        bucket, hms = _stamp()
        cid = s["collector_id"]
        day = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
        out = paths.ARCHIVE_RAW / day / f"raw-{bucket}-{cid}-recovered-{hms}.ndjson"
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "x", encoding="utf-8") as fh:
            for r in sorted(good, key=lambda r: (r["ingest_time"] or "", r["event_uid"])):
                fh.write(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n")
        rep["written"] = str(out.relative_to(paths.HOME)) if paths.HOME in out.parents else str(out)
    return rep


def normalize_missing(*, dry_run: bool = False) -> dict:
    from .spec import discover
    from .testing import run_records

    s = settings.load()
    have = {e["metadata"]["uid"] for e in normalized_events()}
    recs = [r for r in archive_records() if r["event_uid"] not in have]
    rep: dict = {"archived_not_normalized": len(recs), "written": None}
    if recs and not dry_run:
        bucket, hms = _stamp()
        events = run_records(discover(), [{k: v for k, v in r.items() if k != "recovered"} for r in recs],
                             replay_run="repair-normalized")
        day = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
        out = paths.NORMALIZED / day / f"events-{bucket}-{s['collector_id']}-recovered-{hms}.ndjson"
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "x", encoding="utf-8") as fh:
            for e in events:
                e.pop("_osid", None)
                fh.write(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n")
        rep["written"] = str(out.relative_to(paths.HOME)) if paths.HOME in out.parents else str(out)
        rep["events"] = len(events)
    return rep


def repair(*, dry_run: bool = False) -> dict:
    from .replay import missing

    rep = {"archive_from_index": recover_archive_from_index(dry_run=dry_run),
           "normalized_from_archive": normalize_missing(dry_run=dry_run)}
    if not dry_run:
        rep["index_from_archive"] = missing()
    return rep
