"""Onboarding inputs: unknown-event clusters and raw samples.

Raw-first: clusters are found in the DLQ (events no approved spec claimed),
but the sample *bytes* always come from the raw archive and are re-verified
against their recorded SHA-256 -- never from a normalized document.
"""
from __future__ import annotations

import base64
import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from .. import paths, pipeline, settings, vector


def iter_ndjson(files: Iterable[Path]) -> Iterator[dict]:
    for f in files:
        with open(f, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield json.loads(line)


def fallback_events(root: Path | None = None) -> Iterator[dict]:
    """DLQ documents with status fallback (failed events are not onboardable:
    they are oversized or failed archive re-verification)."""
    for doc in iter_ndjson(sorted((root or paths.DLQ).glob("*/dlq-*.ndjson"))):
        if (doc.get("ulpf") or {}).get("status") == "fallback":
            yield doc


@dataclass
class Cluster:
    fingerprint: str
    format: str
    count: int = 0
    first_seen: int | None = None
    last_seen: int | None = None
    transports: Counter = field(default_factory=Counter)
    peers: Counter = field(default_factory=Counter)
    uids: list[str] = field(default_factory=list)
    example: str = ""

    def to_dict(self, *, with_uids: bool = False) -> dict:
        d = {"fingerprint": self.fingerprint, "format": self.format, "count": self.count,
             "first_seen": self.first_seen, "last_seen": self.last_seen,
             "transports": dict(self.transports), "peers": dict(self.peers.most_common(5)),
             "example": self.example}
        if with_uids:
            d["uids"] = self.uids
        return d


def clusters(events: Iterable[dict]) -> list[Cluster]:
    out: dict[str, Cluster] = {}
    for doc in events:
        u = doc.get("ulpf") or {}
        fp = u.get("fingerprint") or "?"
        c = out.get(fp)
        if c is None:
            c = out[fp] = Cluster(fp, u.get("format") or "?")
            c.example = (doc.get("raw_data") or "<non-UTF-8 payload; see ulpf raw get>")[:240]
        c.count += 1
        t = (u.get("ingest") or {}).get("time_ms")
        if t is None:
            t = (doc.get("metadata") or {}).get("logged_time")
        if t is not None:
            c.first_seen = t if c.first_seen is None else min(c.first_seen, t)
            c.last_seen = t if c.last_seen is None else max(c.last_seen, t)
        ing = u.get("ingest") or {}
        c.transports[ing.get("transport") or "?"] += 1
        peer = (ing.get("peer") or {}).get("ip")
        if peer:
            c.peers[peer] += 1
        c.uids.append(u.get("event_uid") or doc["metadata"]["uid"])
    return sorted(out.values(), key=lambda c: (-c.count, c.fingerprint))


def spread(items: list[str], limit: int) -> list[str]:
    """Up to `limit` items evenly spaced over the list (covers the time range)."""
    if len(items) <= limit:
        return list(items)
    step = len(items) / limit
    return [items[int(i * step)] for i in range(limit)]


@dataclass
class RawSample:
    event_uid: str
    raw: bytes
    record: dict          # the archive record, unchanged (replayable)


def fetch_raw(uids: Iterable[str], root: Path | None = None) -> tuple[dict[str, RawSample], list[str]]:
    """One pass over the raw archive. Returns (found, problems)."""
    want = set(uids)
    found: dict[str, RawSample] = {}
    problems: list[str] = []
    root = root or paths.ARCHIVE_RAW
    for f in sorted(root.glob("*/raw-*.ndjson")):
        if len(found) == len(want):
            break
        with open(f, "rb") as fh:
            for line in fh:
                if not line.strip():
                    continue
                rec = json.loads(line)
                uid = rec.get("event_uid")
                if uid not in want or uid in found:
                    continue
                raw = base64.b64decode(rec["raw_b64"])
                if hashlib.sha256(raw).hexdigest() != rec.get("raw_sha256") or len(raw) != rec.get("raw_len"):
                    problems.append(f"{uid}: archive record does not match its raw_sha256/raw_len (skipped)")
                    continue
                found[uid] = RawSample(uid, raw, rec)
    for uid in sorted(want - set(found)):
        if not any(p.startswith(uid) for p in problems):
            problems.append(f"{uid}: not found in the raw archive")
    return found, problems


def preparse(records: list[dict], *, run: str = "onboard") -> dict[str, dict]:
    """Run archive records through the runtime pre-parser (real Vector)."""
    if not records:
        return {}
    s = settings.load()
    cfg_dir = paths.RUNTIME / "tmp"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = cfg_dir / f"vector-preparse-{run}.yaml"
    cfg.write_text(pipeline.dump(pipeline.preparse_config(s, replay_run=run), specs=[], purpose=f"preparse {run}"))
    (paths.VECTOR_DATA / f"batch-{run}").mkdir(parents=True, exist_ok=True)
    stdin = "".join(json.dumps(r) + "\n" for r in records).encode()
    out, _ = vector.run_batch(cfg, stdin)
    res = {}
    for line in out.decode("utf-8").splitlines():
        if line.strip():
            d = json.loads(line)
            res[d["event_uid"]] = d
    return res


def write_samples(path: Path, samples: Iterable[RawSample]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        for s in samples:
            fh.write(json.dumps(s.record, sort_keys=True) + "\n")
            n += 1
    tmp.replace(path)
    return n


def read_samples(path: Path) -> list[dict]:
    return list(iter_ndjson([path])) if path.exists() else []
