"""Parquet lake: closed normalized NDJSON files -> Parquet (`ulpf lake compact`).

Lossless by construction: every row keeps the exact normalized NDJSON line in
`event_json` (byte-for-byte, not re-serialized) next to typed columns for
analytics. Each file is verified after writing (row count, and every
`event_json` equal to its source line) and recorded in a manifest with both
SHA-256 values. The raw archive stays the source of truth for original bytes.

Layout: runtime/data/lake/ocsf/date=YYYY-MM-DD/<source stem>.parquet

Retention (`--prune`): once a closed file's Parquet copy has been re-read and
the source file can be re-assembled from it byte for byte (SHA-256 equal), the
NDJSON file may be deleted (it is ~16x larger). Readers (`normalized_lines()`:
accounting, drift, scorecard, repair) then read that file's events from
Parquet, so nothing downstream notices; `ulpf lake restore` re-materialises the
NDJSON files with their original SHA-256.

Empty lines (written by Vector when a hot reload re-encoded buffered events
with a changed codec, VERIFICATION_REPORT finding P6-4) are not events; their
positions are recorded in the manifest (`gaps`, 1-based line ranges) so that
the re-assembled file is byte-identical to the original.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import time
from pathlib import Path

from . import paths

# (column, arrow type name, dotted source path)
COLUMNS = [
    ("event_uid", "string", "metadata.uid"),
    ("time", "timestamp_ms", "time"),
    ("ingest_time_ms", "int64", "ulpf.ingest.time_ms"),
    ("class_uid", "int32", "class_uid"),
    ("activity_id", "int32", "activity_id"),
    ("severity_id", "int32", "severity_id"),
    ("status", "string", "ulpf.status"),
    ("parser_id", "string", "ulpf.parser.id"),
    ("vendor", "string", "metadata.product.vendor_name"),
    ("product", "string", "metadata.product.name"),
    ("src_ip", "string", "src_endpoint.ip"),
    ("src_port", "int32", "src_endpoint.port"),
    ("dst_ip", "string", "dst_endpoint.ip"),
    ("dst_port", "int32", "dst_endpoint.port"),
    ("protocol_num", "int32", "connection_info.protocol_num"),
    ("action_id", "int32", "action_id"),
    ("bytes_out", "int64", "traffic.bytes_out"),
    ("bytes_in", "int64", "traffic.bytes_in"),
    ("fingerprint", "string", "ulpf.fingerprint"),
    ("raw_sha256", "string", "raw_data_hash.value"),
]


def _schema():
    import pyarrow as pa

    t = {"string": pa.string(), "int32": pa.int32(), "int64": pa.int64(), "timestamp_ms": pa.timestamp("ms", tz="UTC")}
    return pa.schema([(c, t[k]) for c, k, _ in COLUMNS] + [("event_json", pa.string())])


def _get(doc: dict, dotted: str):
    cur = doc
    for p in dotted.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def _row(line: str) -> dict:
    d = json.loads(line)
    row = {}
    for col, kind, src in COLUMNS:
        v = _get(d, src)
        if kind in ("int32", "int64", "timestamp_ms"):
            v = int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None
        elif v is not None and not isinstance(v, str):
            v = str(v)
        row[col] = v
    row["event_json"] = line
    return row


def _closed(path: Path, grace_s: int) -> bool:
    # events-<YYYYmmddTHHMM|YYYYmmddTHH>-<collector>.ndjson ; bucket = archive write time
    stem = path.stem.split("-")[1]
    fmt, width = ("%Y%m%dT%H%M", dt.timedelta(minutes=1)) if len(stem) == 13 else ("%Y%m%dT%H", dt.timedelta(hours=1))
    end = dt.datetime.strptime(stem, fmt).replace(tzinfo=dt.timezone.utc) + width
    now = time.time()
    return now >= end.timestamp() + grace_s and now >= path.stat().st_mtime + grace_s


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest_path() -> Path:
    return paths.LAKE / "_manifest.json"


def _load_manifest() -> dict:
    return json.loads(manifest_path().read_text()) if manifest_path().exists() else {"files": {}}


def _save_manifest(man: dict) -> None:
    paths.LAKE.mkdir(parents=True, exist_ok=True)
    tmp = manifest_path().with_suffix(".tmp")
    tmp.write_text(json.dumps(man, indent=2, sort_keys=True) + "\n")
    tmp.replace(manifest_path())


def _parquet_lines(p: Path) -> list[str]:
    import pyarrow.parquet as pq

    return pq.read_table(p, columns=["event_json"]).column("event_json").to_pylist()


def _split(text: str) -> tuple[list[str], list[list[int]], bool]:
    """Physical layout of an NDJSON file: event lines, 1-based ranges of empty
    lines, and whether the file ends with a newline."""
    phys = text.split("\n")
    final_newline = phys[-1] == ""
    if final_newline:
        phys.pop()
    gaps: list[list[int]] = []
    for i, ln in enumerate(phys, start=1):
        if ln == "":
            if gaps and gaps[-1][1] == i - 1:
                gaps[-1][1] = i
            else:
                gaps.append([i, i])
    return [ln for ln in phys if ln != ""], gaps, final_newline


def _reassemble(lines: list[str], entry: dict) -> bytes:
    """The original file bytes from its event lines and the recorded layout."""
    gaps = entry.get("gaps") or []
    blank = {i for a, b in gaps for i in range(a, b + 1)}
    it = iter(lines)
    out = ["" if i in blank else next(it) for i in range(1, len(lines) + len(blank) + 1)]
    return ("\n".join(out) + ("\n" if entry.get("final_newline", True) and out else "")).encode("utf-8")


def _find_single_gap_block(lines: list[str], entry: dict) -> list[list[int]] | None:
    """Layout recovery for entries written before gaps were recorded: the
    position of ONE contiguous block of empty lines that reproduces the
    recorded source SHA-256 (the only shape the codec-reload failure produced)."""
    import hashlib as _h

    enc = [ln.encode("utf-8") + b"\n" for ln in lines]
    k = entry["source_bytes"] - sum(map(len, enc))
    if k <= 0 or not entry.get("final_newline", True):
        return None
    total, offs = b"".join(enc), [0]
    for e in enc:
        offs.append(offs[-1] + len(e))
    pre, view = _h.sha256(), memoryview(total)
    for s in range(len(enc) + 1):            # block placed before event line s (0-based)
        h = pre.copy()
        h.update(b"\n" * k)
        h.update(view[offs[s]:])
        if h.hexdigest() == entry["source_sha256"]:
            return [[s + 1, s + k]]
        if s < len(enc):
            pre.update(enc[s])
    return None


def _prune(src: Path, entry: dict, man: dict, rel: str) -> str | None:
    """Delete a source NDJSON file whose Parquet copy re-assembles it byte for byte."""
    pq_path = paths.LAKE / entry["parquet"]
    if _sha(src) != entry["source_sha256"]:
        return f"{rel}: source changed since compaction; NOT pruned"
    body = _reassemble(_parquet_lines(pq_path), entry)
    if _sha(pq_path) != entry["parquet_sha256"] or hashlib.sha256(body).hexdigest() != entry["source_sha256"]:
        return f"{rel}: parquet does not reproduce the source; NOT pruned"
    entry["pruned"] = True
    entry["pruned_at"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    _save_manifest(man)                     # record first: readers switch to Parquet
    src.unlink()
    return None


def compact(*, grace_s: int = 120, force: bool = False, prune: bool = False) -> dict:
    import pyarrow as pa
    import pyarrow.parquet as pq

    man = _load_manifest()
    schema = _schema()
    written, skipped, open_files, problems, pruned = [], 0, [], [], 0
    for src in sorted(paths.NORMALIZED.glob("*/events-*.ndjson")):
        rel = str(src.relative_to(paths.NORMALIZED))
        if not force and not _closed(src, grace_s):
            open_files.append(rel)
            continue
        ssha = _sha(src)
        prev = man["files"].get(rel)
        if prev and prev["source_sha256"] == ssha and (paths.LAKE / prev["parquet"]).exists():
            skipped += 1
            if prune:
                err = _prune(src, prev, man, rel)
                problems += [err] if err else []
                pruned += 0 if err else 1
            continue
        lines, gaps, final_newline = _split(src.read_text(encoding="utf-8"))
        try:
            rows = [_row(ln) for ln in lines]
        except ValueError as e:              # json.JSONDecodeError: partial or foreign line
            problems.append(f"{rel}: unreadable line ({e}); not compacted")
            continue
        table = pa.Table.from_pylist(rows, schema=schema)
        out = paths.LAKE / "ocsf" / f"date={src.parent.name}" / (src.stem + ".parquet")
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp = out.with_suffix(".parquet.tmp")
        pq.write_table(table, tmp, compression="zstd")
        back = pq.read_table(tmp, columns=["event_json"]).column("event_json").to_pylist()
        if back != lines:
            tmp.unlink()
            problems.append(f"{rel}: read-back mismatch, not written")
            continue
        os.replace(tmp, out)
        entry = {"parquet": str(out.relative_to(paths.LAKE)), "rows": len(lines), "source_sha256": ssha,
                 "parquet_sha256": _sha(out), "bytes": out.stat().st_size, "source_bytes": src.stat().st_size,
                 "written_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
        if gaps:
            entry["gaps"] = gaps
        if not final_newline:
            entry["final_newline"] = False
        man["files"][rel] = entry
        written.append(rel)
        _save_manifest(man)
        if prune:
            err = _prune(src, man["files"][rel], man, rel)
            problems += [err] if err else []
            pruned += 0 if err else 1
    _save_manifest(man)
    return {"written": len(written), "unchanged": skipped, "pruned": pruned, "not_closed_yet": len(open_files),
            "problems": problems,
            "rows_total": sum(f["rows"] for f in man["files"].values()),
            "parquet_bytes": sum(f["bytes"] for f in man["files"].values()),
            "ndjson_bytes": sum(f["source_bytes"] for f in man["files"].values())}


def verify(*, repair_layout: bool = False) -> dict:
    """Re-check every manifest entry: parquet hash, row count, and that the
    source file re-assembles byte for byte (SHA-256) from the Parquet copy --
    for pruned sources the Parquet copy is now the only normalized copy.

    `repair_layout` recovers the empty-line layout of entries compacted before
    layouts were recorded (searching one contiguous block that reproduces the
    recorded SHA-256) and stores it in the manifest."""
    import pyarrow.parquet as pq

    man = _load_manifest()
    bad, repaired, gap_lines = [], [], 0
    for rel, f in man["files"].items():
        p = paths.LAKE / f["parquet"]
        if not p.exists():
            bad.append(f"{rel}: parquet missing{' (source was PRUNED: data loss)' if f.get('pruned') else ''}")
            continue
        if _sha(p) != f["parquet_sha256"]:
            bad.append(f"{rel}: parquet sha256 differs from manifest")
            continue
        if pq.read_metadata(p).num_rows != f["rows"]:
            bad.append(f"{rel}: row count differs")
            continue
        lines = _parquet_lines(p)
        if hashlib.sha256(_reassemble(lines, f)).hexdigest() != f["source_sha256"]:
            found = _find_single_gap_block(lines, f) if repair_layout and not f.get("gaps") else None
            if found:
                f["gaps"] = found
                f["layout_recovered_at"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
                repaired.append(rel)
            else:
                bad.append(f"{rel}: the source cannot be re-assembled byte for byte (unknown empty-line layout; "
                           f"every event line is intact) -- try `ulpf lake verify --repair-layout`")
        gap_lines += sum(b - a + 1 for a, b in f.get("gaps") or [])
    if repaired:
        _save_manifest(man)
    return {"files": len(man["files"]), "pruned_sources": sum(1 for f in man["files"].values() if f.get("pruned")),
            "gap_lines": gap_lines, "layouts_recovered": repaired, "problems": bad, "ok": not bad}


def normalized_lines():
    """Every normalized event line exactly once: from the NDJSON file while it
    exists, else (pruned) from its verified Parquet copy."""
    man = _load_manifest()
    present = set()
    for src in sorted(paths.NORMALIZED.glob("*/events-*.ndjson")):
        present.add(str(src.relative_to(paths.NORMALIZED)))
        with open(src, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield line.rstrip("\n")
    for rel, f in sorted(man["files"].items()):
        if f.get("pruned") and rel not in present:
            yield from _parquet_lines(paths.LAKE / f["parquet"])


def restore() -> dict:
    """Re-materialise pruned NDJSON files from Parquet (byte-identical lines)."""
    man = _load_manifest()
    restored = []
    for rel, f in man["files"].items():
        src = paths.NORMALIZED / rel
        if not f.get("pruned") or src.exists():
            continue
        body = _reassemble(_parquet_lines(paths.LAKE / f["parquet"]), f)
        src.parent.mkdir(parents=True, exist_ok=True)
        tmp = src.with_suffix(".restore")
        tmp.write_bytes(body)
        if _sha(tmp) != f["source_sha256"]:
            tmp.unlink()
            raise RuntimeError(f"{rel}: restored bytes do not match the recorded source sha256")
        tmp.replace(src)
        f["pruned"] = False
        f.pop("pruned_at", None)
        restored.append(rel)
    _save_manifest(man)
    return {"restored": restored}


def stats() -> dict:
    import pyarrow.dataset as ds

    root = paths.LAKE / "ocsf"
    if not root.exists():
        return {"rows": 0}
    t = ds.dataset(str(root), format="parquet", partitioning="hive").to_table(columns=["class_uid", "product", "status"])

    def counts(col: str) -> dict:
        g = t.group_by(col).aggregate([(col, "count")]).to_pydict()
        return dict(sorted(zip((str(k) for k in g[col]), g[f"{col}_count"]), key=lambda kv: -kv[1]))

    return {"rows": t.num_rows, "by_product": counts("product"), "by_status": counts("status")}
