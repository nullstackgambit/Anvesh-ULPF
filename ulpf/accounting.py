"""End-to-end event accounting.

Proves (or disproves) sent = received = archived = normalized = indexed, using
event UIDs and raw SHA-256 values rather than just counts, and surfaces every
loss Vector recorded about itself.
"""
from __future__ import annotations

import json
import re
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Iterator

from . import paths
from .settings import load as load_settings


def iter_ndjson(root: Path, pattern: str) -> Iterator[dict]:
    for f in sorted(root.glob(pattern)):
        with open(f, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield json.loads(line)


def archive_records() -> Iterator[dict]:
    return iter_ndjson(paths.ARCHIVE_RAW, "*/raw-*.ndjson")


def normalized_events() -> Iterator[dict]:
    """NDJSON files, plus the Parquet copies of files pruned after compaction."""
    from .lake import normalized_lines

    for line in normalized_lines():
        yield json.loads(line)


# Connection-level rejections are not losses of accepted events (nothing was
# received): reported separately so they never mask or fake a loss.
REJECTION_PATTERNS = {
    "tls_handshake_rejected": re.compile(r"TLS handshake failed"),
}
LOSS_PATTERNS = {
    "frame_discarded": re.compile(r"Discarding frame larger than max_length"),
    "framing_error": re.compile(r"Failed framing bytes"),
    "events_dropped": re.compile(r"Events dropped"),
    "request_failed": re.compile(r"Service call failed|Not retriable|Response contained errors"),
    "line_too_long": re.compile(r"[Ff]ound line that exceeds max_line_bytes|line too long", re.I),
}


def recorded_losses() -> Counter:
    c: Counter = Counter()
    for rec in iter_ndjson(paths.DLQ, "*/vector-internal-*.ndjson"):
        msg = str(rec.get("message", "")) + " " + str(rec.get("error", ""))
        rej = next((k for k, rx in REJECTION_PATTERNS.items() if rx.search(msg)), None)
        if rej:
            c[rej] += 1
            continue
        for kind, rx in LOSS_PATTERNS.items():
            if rx.search(msg):
                c[kind] += 1
                break
        else:
            c[f"other_{(rec.get('metadata') or {}).get('level', '?').lower()}"] += 1
    return c


def vector_received(metrics_url: str) -> dict[str, float] | None:
    try:
        with urllib.request.urlopen(metrics_url, timeout=3) as r:  # noqa: S310 (loopback)
            text = r.read().decode()
    except OSError:
        return None
    out: dict[str, float] = {}
    for line in text.splitlines():
        m = re.match(r'vector_component_received_events_total\{([^}]*)\} (\S+)', line)
        if m and 'component_kind="source"' in m.group(1):
            cid = re.search(r'component_id="([^"]+)"', m.group(1))
            if cid and cid.group(1).startswith("in_"):
                out[cid.group(1)] = out.get(cid.group(1), 0) + float(m.group(2))
    return out


def _store_lines() -> tuple[int, int]:
    def n(root: Path, pattern: str) -> int:
        total = 0
        for f in root.glob(pattern):
            try:
                total += f.stat().st_size
            except FileNotFoundError:   # pruned meanwhile
                pass
        return total
    return n(paths.ARCHIVE_RAW, "*/raw-*.ndjson"), n(paths.NORMALIZED, "*/events-*.ndjson")


def settle(max_wait_s: float, *, quiet_s: float = 4.0, poll_s: float = 1.0, index_count=None) -> float:
    """Wait until the archive and normalized stores (and, if given, the index
    document count) stop growing.

    Vector's sinks flush independently; the raw archive's file sink was
    measured to complete a few seconds AFTER the same events were indexed
    (P6 finding), so a count taken right after a burst can show a transient
    gap that is not a loss. Returns the seconds waited.
    """
    import time

    def state():
        return _store_lines() + ((index_count(),) if index_count else ())

    start = last_change = time.time()
    prev = state()
    while time.time() - start < max_wait_s:
        time.sleep(poll_s)
        cur = state()
        if cur != prev:
            prev, last_change = cur, time.time()
        elif time.time() - last_change >= quiet_s:
            break
    return round(time.time() - start, 1)


def reconcile(sendlog: Path | None = None, *, check_opensearch: bool = True, settle_s: float = 0) -> dict:
    s = load_settings()
    counter = None
    if check_opensearch and settle_s:
        from .opensearch import Client, OpenSearchError

        c0, alias = Client.from_settings(s), s["opensearch"]["read_alias"]

        def counter():  # noqa: F811 - the index can trail the file sinks by seconds
            try:
                c0.refresh(alias)
                return c0.count(alias)
            except (OSError, OpenSearchError):
                return -1
    waited = settle(settle_s, index_count=counter) if settle_s else 0
    arch = list(archive_records())
    norm_uids = Counter(e["metadata"]["uid"] for e in normalized_events())
    arch_uids = Counter(r["event_uid"] for r in arch)
    status = Counter(e["ulpf"]["status"] for e in normalized_events())
    rep: dict = {
        "settled_after_s": waited,
        "archived": len(arch),
        "normalized": sum(norm_uids.values()),
        "status": dict(status),
        "archive_uid_duplicates": sum(1 for v in arch_uids.values() if v > 1),
        "archived_not_normalized": len(set(arch_uids) - set(norm_uids)),
        "normalized_not_archived": len(set(norm_uids) - set(arch_uids)),
    }
    losses = recorded_losses()
    rep["recorded_losses"] = dict(losses)
    ok = rep["archived_not_normalized"] == 0 and rep["normalized_not_archived"] == 0 and rep["archive_uid_duplicates"] == 0
    if sendlog:
        sent = Counter(json.loads(l)["sha256"] for l in open(sendlog) if l.strip())
        got = Counter(r["raw_sha256"] for r in arch)
        missing = sent - got
        rep["sent"] = sum(sent.values())
        rep["sent_not_archived"] = sum(missing.values())
        ok = ok and not missing
    rx = vector_received(f"http://{s['vector']['metrics_address']}/metrics")
    if rx is not None:
        rep["vector_received_by_source"] = rx
    if check_opensearch:
        from .opensearch import Client, OpenSearchError

        try:
            c = Client.from_settings(s)
            alias = s["opensearch"]["read_alias"]
            c.refresh(alias)
            os_uids = {h["_id"] for h in c.scroll_all(alias, source=False)}
            rep["indexed"] = len(os_uids)
            rep["archived_not_indexed"] = len(set(arch_uids) - os_uids)
            rep["indexed_not_archived"] = len(os_uids - set(arch_uids))
            ok = ok and rep["archived_not_indexed"] == 0 and rep["indexed_not_archived"] == 0
        except (OSError, OpenSearchError) as e:
            rep["indexed"] = f"unavailable: {e}"
            ok = False
    loss_kinds = {k for k in losses if not k.startswith("other_") and k not in REJECTION_PATTERNS}
    rep["verdict"] = ("PASS" if ok and not loss_kinds else
                      "RECORDED_LOSS" if ok else "FAIL")
    return rep
