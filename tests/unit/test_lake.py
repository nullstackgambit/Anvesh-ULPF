"""Parquet lake: lossless compaction, verified pruning, readers, restore.

Events are SYNTHETIC TEST DATA (minimal normalized-event shapes).
"""
import hashlib
import json

import pytest

from ulpf import lake, paths


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "NORMALIZED", tmp_path / "normalized")
    monkeypatch.setattr(paths, "LAKE", tmp_path / "lake")
    files = {}
    for b, n in (("20261001T1000", 3), ("20261001T1001", 2)):
        f = paths.NORMALIZED / "2026-10-01" / f"events-{b}-c1.ndjson"
        f.parent.mkdir(parents=True, exist_ok=True)
        lines = [json.dumps({"metadata": {"uid": f"{b}-{i}"}, "time": 1791367200000 + i, "class_uid": 4001,
                             "ulpf": {"status": "parsed", "parser": {"id": "x.y.z"}},
                             "raw_data": "SYNTHETIC éè \\\\ \"q\""}, sort_keys=True, separators=(",", ":"))
                 for i in range(n)]
        f.write_text("".join(ln + "\n" for ln in lines), encoding="utf-8")
        files[f] = (lines, hashlib.sha256(f.read_bytes()).hexdigest())
    return files


def test_prune_keeps_every_line_and_restore_is_exact(store):
    before = sorted(ln for lines, _ in store.values() for ln in lines)
    rep = lake.compact(grace_s=0, prune=True)
    assert (rep["written"], rep["pruned"], rep["problems"]) == (2, 2, [])
    assert not any(f.exists() for f in store)                      # NDJSON gone
    assert sorted(lake.normalized_lines()) == before                # readers see the same lines
    from ulpf.accounting import normalized_events
    assert sorted(e["metadata"]["uid"] for e in normalized_events()) == sorted(json.loads(x)["metadata"]["uid"] for x in before)
    v = lake.verify()
    assert v["ok"] and v["pruned_sources"] == 2
    assert lake.restore()["restored"]
    for f, (_, sha) in store.items():
        assert hashlib.sha256(f.read_bytes()).hexdigest() == sha  # byte-identical restore
    assert sorted(lake.normalized_lines()) == before                # no double counting after restore


def test_verify_detects_a_damaged_parquet(store):
    lake.compact(grace_s=0, prune=True)
    man = json.loads(lake.manifest_path().read_text())
    pq = paths.LAKE / next(iter(man["files"].values()))["parquet"]
    data = bytearray(pq.read_bytes())
    data[len(data) // 2] ^= 0x01
    pq.write_bytes(bytes(data))
    v = lake.verify()
    assert not v["ok"] and "sha256 differs" in v["problems"][0]


def test_open_files_are_not_compacted(store, monkeypatch):
    import time as _t

    monkeypatch.setattr(_t, "time", lambda: 1791367200.0 + 30)     # inside the 10:00 bucket's grace window
    rep = lake.compact(grace_s=120, prune=True)
    assert rep["written"] == 0 and rep["not_closed_yet"] == 2 and all(f.exists() for f in store)


def _write(lines_with_gaps: list[str], bucket: str = "20261001T1002") -> tuple:
    f = paths.NORMALIZED / "2026-10-01" / f"events-{bucket}-c1.ndjson"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("".join(ln + "\n" for ln in lines_with_gaps), encoding="utf-8")
    return f, hashlib.sha256(f.read_bytes()).hexdigest()


def _ev(i: int, text: str = "x") -> str:
    return json.dumps({"metadata": {"uid": f"g-{i}"}, "time": 1791367320000 + i, "raw_data": text},
                      ensure_ascii=False, separators=(",", ":"))


def test_empty_lines_are_recorded_and_restore_is_byte_exact(store):
    # empty lines at the start, in the middle and at the end (finding P6-4);
    # U+2028 inside a JSON string is legal and must not split a line
    f, sha = _write(["", "", _ev(0), "", _ev(1, "a b"), _ev(2), "", ""])
    rep = lake.compact(grace_s=0, prune=True)
    assert rep["problems"] == [] and rep["pruned"] == 3
    entry = json.loads(lake.manifest_path().read_text())["files"]["2026-10-01/events-20261001T1002-c1.ndjson"]
    assert entry["gaps"] == [[1, 2], [4, 4], [7, 8]] and entry["rows"] == 3
    assert [json.loads(x)["metadata"]["uid"] for x in lake.normalized_lines() if '"g-' in x] == ["g-0", "g-1", "g-2"]
    assert lake.verify()["ok"] and lake.verify()["gap_lines"] == 5
    lake.restore()
    assert hashlib.sha256(f.read_bytes()).hexdigest() == sha


def test_layout_of_a_legacy_entry_is_recovered(store):
    f, sha = _write([""] * 3 + [_ev(i) for i in range(4)])
    lake.compact(grace_s=0, prune=True)
    man = json.loads(lake.manifest_path().read_text())
    man["files"]["2026-10-01/events-20261001T1002-c1.ndjson"].pop("gaps")   # as written before layouts existed
    lake.manifest_path().write_text(json.dumps(man))
    v = lake.verify()
    assert not v["ok"] and "re-assembled byte for byte" in v["problems"][0]
    v = lake.verify(repair_layout=True)
    assert v["ok"] and v["layouts_recovered"] == ["2026-10-01/events-20261001T1002-c1.ndjson"]
    lake.restore()
    assert hashlib.sha256(f.read_bytes()).hexdigest() == sha


def test_unreadable_line_is_not_compacted_or_pruned(store):
    f, _ = _write([_ev(0), '{"truncated": '])
    rep = lake.compact(grace_s=0, prune=True)
    assert f.exists() and any("unreadable line" in p for p in rep["problems"])
