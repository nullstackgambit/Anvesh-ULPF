"""Spec test harness: golden, expectation, schema, completeness and round-trip
tests, executed through the real Vector binary (ADR-010).

All test vectors of all selected specs are encoded as raw-archive records
(deterministic event_uid and receipt time) and pushed through one batch
Vector run that contains *every* compiled spec, so routing is tested as well:
a vector for spec X must be claimed by X.

Checks per vector
* expect:        dotted-path subset assertions from the spec
* golden:        full normalized event == tests/golden/<id>/<name>.expected.json
                 (volatile fields removed; `--update` rewrites after review)
* schema:        OCSF 1.9.0 JSON Schema + ULPF semantic checks + envelope schema
* completeness:  an INDEPENDENT Python tokenizer re-derives the source field
                 names from the raw bytes; each must be mapped, unmapped or
                 recorded as empty (nothing may silently disappear)
* round-trip:    raw_data / ulpf.raw.b64 reproduce the input bytes exactly
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import paths, pipeline, settings, vector
from .compile import compile_specs
from .ocsf import Ocsf, default as default_ocsf
from .provenance import validate_envelope
from .spec import Spec, load

GOLDEN = paths.HOME / "tests" / "golden"
TEST_INGEST_TIME = "2026-10-07T12:00:00.000000000Z"
TEST_INGEST_MS = 1791374400000
NAMESPACE = uuid.UUID("6f3b2a3e-0d1c-4b8e-9a51-1c2d3e4f5a6b")

# Fields that legitimately differ between runs.
VOLATILE = [("metadata", "processed_time"), ("metadata", "transformation_info_list", "*", "time")]


@dataclass
class CaseResult:
    spec_id: str
    name: str
    checks: dict[str, str] = field(default_factory=dict)  # check -> "ok" | failure message
    event: dict | None = None

    @property
    def ok(self) -> bool:
        return all(v == "ok" or v.startswith("skipped") for v in self.checks.values())


def raw_bytes(test: dict) -> bytes:
    if "raw" in test:
        return test["raw"].encode("utf-8")
    return (paths.HOME / test["raw_file"]).read_bytes()


def archive_record(event_uid: str, raw: bytes, *, ingest_time: str = TEST_INGEST_TIME, transport: str = "test",
                   collector: str = "golden") -> dict:
    return {"v": 1, "event_uid": event_uid, "ingest_time": ingest_time, "collector_id": collector,
            "transport": transport, "peer": {}, "raw_len": len(raw),
            "raw_sha256": hashlib.sha256(raw).hexdigest(), "raw_b64": base64.b64encode(raw).decode()}


def case_uid(spec_id: str, name: str) -> str:
    return str(uuid.uuid5(NAMESPACE, f"{spec_id}/{name}"))


def run_records(spec_paths: list[Path], records: list[dict], *, replay_run: str = "golden") -> list[dict]:
    """Push archive records through a batch Vector built from spec_paths."""
    pl, _ = compile_specs(spec_paths)
    s = settings.load()
    cfg_dir = paths.RUNTIME / "tmp"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = cfg_dir / f"vector-batch-{replay_run}.yaml"
    cfg.write_text(pipeline.dump(pipeline.batch_config(s, pl, replay_run=replay_run), specs=pl.parsers,
                                 purpose=f"batch run {replay_run}"))
    (paths.VECTOR_DATA / f"batch-{replay_run}").mkdir(parents=True, exist_ok=True)
    stdin = "".join(json.dumps(r) + "\n" for r in records).encode()
    # Deterministic, test-only PII key so golden files contain stable
    # pseudonyms. Never used outside test runs.
    out, _err = vector.run_batch(cfg, stdin, env={"ULPF_PII_KEY": "ulpf-golden-test-key-not-a-secret"})
    return [json.loads(line) for line in out.decode("utf-8").splitlines() if line.strip()]


# ------------------------------------------------------------- comparisons
def get_path(doc: Any, dotted: str) -> Any:
    cur = doc
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, dict):
            # unmapped keys may themselves contain dots (e.g. "id.orig_h")
            rest = dotted.split(".")
            return _MISSING
        else:
            return _MISSING
    return cur


class _Missing:
    def __repr__(self) -> str:
        return "<missing>"


_MISSING = _Missing()


def get_unmapped(doc: dict, key: str) -> Any:
    return (doc.get("unmapped") or {}).get(key, _MISSING)


def strip_volatile(doc: dict) -> dict:
    d = json.loads(json.dumps(doc))
    for path in VOLATILE:
        _drop(d, list(path))
    return d


def _drop(obj: Any, path: list[str]) -> None:
    if not path:
        return
    head, rest = path[0], path[1:]
    if head == "*" and isinstance(obj, list):
        for it in obj:
            _drop(it, rest)
    elif isinstance(obj, dict) and head in obj:
        if not rest:
            del obj[head]
        else:
            _drop(obj[head], rest)


def diff(a: Any, b: Any, path: str = "") -> list[str]:
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            p = f"{path}.{k}" if path else k
            if k not in a:
                out.append(f"+ {p} = {json.dumps(b[k])[:120]}")
            elif k not in b:
                out.append(f"- {p} (expected {json.dumps(a[k])[:120]})")
            else:
                out.extend(diff(a[k], b[k], p))
        return out
    if a != b:
        return [f"~ {path}: expected {json.dumps(a)[:120]} got {json.dumps(b)[:120]}"]
    return []


# ------------------------------------------------- independent field oracle
_KV_KEY = re.compile(r'(?:^|\s)([A-Za-z_][A-Za-z0-9_.\-]*)=')


def oracle_fields(spec: Spec, raw: bytes, event: dict) -> set[str] | None:
    """Re-derive source field names from the raw bytes WITHOUT using Vector."""
    p = spec.data["parse"]
    text = raw.decode("utf-8", "replace").rstrip("\r\n")
    body = text
    m = re.match(r"^<\d{1,3}>(.*)$", text, re.S)
    if m:
        body = m.group(1)
        # strip an RFC 5424 header (VERSION TS HOST APP PROCID MSGID SD) when present
        m5 = re.match(r"^1 \S+ \S+ \S+ \S+ \S+ (?:-|(?:\[.*?\])+) ?(.*)$", body, re.S)
        if m5:
            body = m5.group(1)
    kind = p["kind"]
    if p.get("extract"):
        src_text = {"text": text, "after_pri": re.sub(r"^<\d{1,3}>", "", text), "body": body}[p.get("input", "body")]
        mm = re.search(p["extract"], src_text, re.S)
        if not mm:
            return set()
        body = mm.group("payload")
        extra = {k for k, v in mm.groupdict().items() if k != "payload" and v is not None}
    else:
        extra = set()
    if kind == "kv":
        fd = (p.get("kv") or {}).get("field_delimiter", " ")
        if fd == " ":
            return set(_KV_KEY.findall(body))
        return {seg.split((p.get("kv") or {}).get("value_delimiter", "="), 1)[0].strip()
                for seg in body.split(fd) if (p.get("kv") or {}).get("value_delimiter", "=") in seg}
    if kind == "json":
        try:
            obj = json.loads(body[body.index("{"):])
        except (ValueError, json.JSONDecodeError):
            return None
        if not isinstance(obj, dict):
            return None
        return set(_flatten(obj)) if (p.get("json") or {}).get("flatten", True) else set(obj)
    if kind == "csv":
        delim = p["csv"].get("delimiter", ",")
        payload = body if p.get("extract") else _csv_payload(body, event)
        rows = list(csv.reader(io.StringIO(payload), delimiter=delim))
        if not rows:
            return set()
        n = len(rows[0])
        cov = (event.get("ulpf") or {}).get("coverage") or {}
        # CSV columns are positional: compare counts (names are spec-assigned).
        return {f"#col{i}" for i in range(n)} | {f"#x:{e}" for e in extra} if cov else None
    if kind == "regex":
        rx = re.compile(p["regex"]["pattern"])
        mm = rx.search(_regex_input(text, body, p))
        return {k for k, v in mm.groupdict().items() if v is not None} if mm else set()
    if kind == "cef":
        m = re.search(r"CEF:\d+\|.*$", text, re.S)
        if not m:
            return set()
        # split on unescaped pipes: 7 header fields + extension
        parts = re.split(r"(?<!\\)\|", m.group(0), maxsplit=7)
        if len(parts) < 8:
            return None
        keys = {"cefVersion", "deviceVendor", "deviceProduct", "deviceVersion", "deviceEventClassId", "name", "severity"}
        keys |= set(re.findall(r"(?:^|\s)([A-Za-z0-9_.\-\[\]]+)=", parts[7]))
        return keys
    if kind == "leef":
        m = re.search(r"LEEF:([0-9.]+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$", text, re.S)
        if not m:
            return set()
        rest, delim = m.group(6), "\t"
        if m.group(1).startswith("2"):
            d, _, rest = rest.partition("|")
            hx = re.fullmatch(r"0?x([0-9A-Fa-f]{1,4})", d)
            delim = chr(int(hx.group(1), 16)) if hx else (d or "\t")
        keys = {"leef.version", "leef.vendor", "leef.product", "leef.product_version", "leef.event_id"}
        keys |= {kv.split("=", 1)[0] for kv in rest.split(delim) if "=" in kv}
        return keys
    return None


def _csv_payload(body: str, event: dict) -> str:
    # The CSV payload starts after the syslog tag ("filterlog[123]: ").
    m = re.match(r"^(?:[A-Z][a-z]{2} [ 0-9]\d \d{2}:\d{2}:\d{2} \S+ )?(?:\S+?(?:\[\d+\])?: )?(.*)$", body, re.S)
    return m.group(1) if m else body


def _regex_input(text: str, body: str, p: dict) -> str:
    return {"text": text, "after_pri": re.sub(r"^<\d{1,3}>", "", text), "body": body}[p.get("input", "body")]


def _flatten(obj: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in obj.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict) and v:
            out.update(_flatten(v, key + "."))
        else:
            out[key] = v
    return out


def accounted_fields(event: dict) -> set[str]:
    u = event.get("ulpf") or {}
    acc: set[str] = set()
    for v in (u.get("lineage") or {}).values():
        if v in ("const", "ingest", "default:unknown") or v.startswith(("derived:", "copy:", "enum_missing:")):
            continue
        v = v.split(":", 1)[1] if v.startswith("enum:") else v
        acc.update(v.split("+"))
    acc.update((event.get("unmapped") or {}).keys())
    acc.update((u.get("coverage") or {}).get("empty_fields") or [])
    return acc


def check_completeness(spec: Spec, raw: bytes, event: dict) -> str:
    cov = (event.get("ulpf") or {}).get("coverage") or {}
    if not cov:
        return "skipped (no field accounting: not parsed by a spec)"
    if cov and cov.get("mapped", 0) + cov.get("unmapped", 0) + cov.get("empty", 0) != cov.get("fields"):
        return f"runtime accounting violated: {cov}"
    expected = oracle_fields(spec, raw, event)
    if expected is None:
        return "skipped (no independent oracle for this parse kind)"
    if spec.data["parse"]["kind"] == "csv":
        # syslog header fields (include_syslog) are not CSV columns
        acc = accounted_fields(event)
        header = len({f for f in acc if f.startswith("syslog.")})
        if cov.get("fields") - header != len(expected):
            return f"oracle counted {len(expected)} CSV columns (+ extract groups), runtime accounted {cov.get('fields') - header} (+{header} syslog header fields)"
        return "ok"
    acc = accounted_fields(event)
    extra_ok = {f for f in acc if f.startswith("syslog.")}
    missing = sorted(expected - acc)
    if missing:
        return f"fields found in raw but not accounted for: {missing}"
    del extra_ok
    return "ok"


def check_roundtrip(raw: bytes, event: dict) -> str:
    u = event.get("ulpf") or {}
    if u.get("raw", {}).get("b64") is not None:
        got = base64.b64decode(u["raw"]["b64"])
    else:
        got = (event.get("raw_data") or "").encode("utf-8")
    if got != raw:
        return f"raw bytes differ (len {len(got)} vs {len(raw)})"
    if (event.get("raw_data_hash") or {}).get("value") != hashlib.sha256(raw).hexdigest():
        return "raw_data_hash does not match the input bytes"
    return "ok"


def check_expect(expect: dict, event: dict) -> str:
    bad = []
    for path, want in expect.items():
        if path.startswith("unmapped."):
            got = get_unmapped(event, path[len("unmapped."):])
        else:
            got = get_path(event, path)
        if got != want:
            bad.append(f"{path}: expected {want!r}, got {got!r}")
    return "ok" if not bad else "; ".join(bad)


# ------------------------------------------------------------------ runner
def run_spec_tests(spec_paths: list[Path], *, update_golden: bool = False, only: set[str] | None = None,
                   ocsf: Ocsf | None = None) -> list[CaseResult]:
    o = ocsf or default_ocsf()
    specs = [load(p) for p in spec_paths]
    records, cases = [], {}
    for sp in specs:
        if only and sp.id not in only:
            continue
        for t in sp.data["tests"]:
            uid = case_uid(sp.id, t["name"])
            raw = raw_bytes(t)
            records.append(archive_record(uid, raw))
            cases[uid] = (sp, t, raw)
    events = {e["metadata"]["uid"]: e for e in run_records(spec_paths, records)} if records else {}
    results = []
    for uid, (sp, t, raw) in cases.items():
        r = CaseResult(sp.id, t["name"])
        ev = events.get(uid)
        if ev is None:
            r.checks["delivered"] = "event missing from Vector output (silently dropped?)"
            results.append(r)
            continue
        r.event = ev
        r.checks["delivered"] = "ok"
        pid = ((ev.get("ulpf") or {}).get("parser") or {}).get("id")
        r.checks["routed"] = "ok" if pid == sp.id else f"claimed by {pid!r}"
        if t.get("expect"):
            r.checks["expect"] = check_expect(t["expect"], ev)
        vr = o.validate(ev)
        env = validate_envelope(ev)
        r.checks["schema"] = "ok" if vr.ok and not env else "; ".join([str(i) for i in vr.issues][:4] + env[:3])
        r.checks["completeness"] = check_completeness(sp, raw, ev)
        r.checks["roundtrip"] = check_roundtrip(raw, ev)
        if t.get("golden", True):
            gp = GOLDEN / sp.id / f"{t['name']}.expected.json"
            actual = strip_volatile(ev)
            if update_golden:
                gp.parent.mkdir(parents=True, exist_ok=True)
                gp.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n")
                r.checks["golden"] = "ok"
            elif not gp.exists():
                r.checks["golden"] = f"missing golden file {gp.relative_to(paths.HOME)} (review output, then --update)"
            else:
                d = diff(json.loads(gp.read_text()), actual)
                r.checks["golden"] = "ok" if not d else "; ".join(d[:6])
        results.append(r)
    return results
