"""Deterministic structure and type inference over sample events.

Used only to *propose* a draft spec. Everything it proposes is re-checked by
the gate (lint, real-Vector compile, golden/schema/completeness tests) and a
human approves before promotion. Nothing here is used at runtime.
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import re
import statistics
from collections import Counter
from dataclasses import dataclass, field

DELIMS = ["|", ";", ",", "\t"]
KV_SEPS = ["=", ":"]
MAC = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
TS_FORMATS = [
    ("rfc3339", re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})$")),
    ("%Y-%m-%d %H:%M:%S", re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")),
    ("%Y/%m/%d %H:%M:%S", re.compile(r"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}$")),
    ("%b %e %H:%M:%S", re.compile(r"^[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}$")),
]


@dataclass
class FieldStats:
    name: str
    values: list[str] = field(default_factory=list)
    type: str = "string"
    time_format: str | None = None
    distinct: int = 0
    examples: list[str] = field(default_factory=list)
    present_in: int = 0

    def summary(self) -> dict:
        return {"type": self.type, "time_format": self.time_format, "distinct": self.distinct,
                "present_in": self.present_in, "examples": self.examples[:3]}


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _is_int(v: str) -> bool:
    return bool(re.fullmatch(r"-?\d{1,19}", v))


def infer_type(values: list[str]) -> tuple[str, str | None]:
    vals = [v for v in values if v not in ("", "-")]
    if not vals:
        return "string", None
    if all(_is_ip(v) for v in vals):
        return "ip", None
    if all(MAC.match(v) for v in vals):
        return "mac", None
    for fmt, rx in TS_FORMATS:
        if all(rx.match(v) for v in vals):
            return "timestamp", fmt
    if all(re.fullmatch(r"\d{10}(\.\d+)?|\d{13}|\d{16}|\d{19}", v) for v in vals):
        try:
            ints = [int(float(v)) for v in vals]
            # plausible epoch (2001..2100) in s/ms/us/ns
            if all(1_000_000_000 <= int(str(i)[:10]) <= 4_102_444_800 for i in ints):
                return "timestamp", "epoch_auto"
        except ValueError:
            pass
    if all(_is_int(v) for v in vals):
        ints = [int(v) for v in vals]
        if all(0 <= i <= 65535 for i in ints):
            return "int_small", None   # port candidate; decided by name/position
        return "long", None
    if all(re.fullmatch(r"-?\d+\.\d+", v) for v in vals):
        return "float", None
    return "string", None


def stats_for(records: list[dict[str, str]]) -> dict[str, FieldStats]:
    out: dict[str, FieldStats] = {}
    for rec in records:
        for k, v in rec.items():
            fs = out.setdefault(k, FieldStats(k))
            fs.values.append("" if v is None else str(v))
            fs.present_in += 1
    for fs in out.values():
        fs.type, fs.time_format = infer_type(fs.values)
        c = Counter(fs.values)
        fs.distinct = len(c)
        fs.examples = [v for v, _ in c.most_common(3)]
    return out


# ------------------------------------------------------------- structure
@dataclass
class Structure:
    kind: str                       # json | kv | csv | delimited_kv | regex
    delimiter: str | None = None
    kv_field_delim: str | None = None
    kv_value_delim: str | None = None
    header_fields: list[str] = field(default_factory=list)
    extract: str | None = None
    regex: str | None = None
    columns: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def records(self, lines: list[str]) -> list[dict[str, str]]:
        """Python re-tokenisation of the samples (used for type inference and
        to derive *independent* test expectations for the draft)."""
        out = []
        for ln in lines:
            if self.kind == "json":
                try:
                    obj = json.loads(ln)
                    out.append({k: (json.dumps(v) if isinstance(v, (dict, list)) else str(v)) for k, v in _flat(obj).items()})
                except json.JSONDecodeError:
                    out.append({})
            elif self.kind == "kv":
                out.append(_kv(ln, self.kv_field_delim or " ", self.kv_value_delim or "="))
            elif self.kind == "csv":
                parts = ln.split(self.delimiter)
                out.append({self.columns[i] if i < len(self.columns) else f"_extra_{i}": p for i, p in enumerate(parts)})
            elif self.kind == "delimited_kv":
                m = re.match(self.extract, ln) if self.extract else None
                if not m:
                    out.append({})
                    continue
                rec = {k: v for k, v in m.groupdict().items() if k != "payload" and v is not None}
                rec.update(_kv(m.group("payload"), self.kv_field_delim, self.kv_value_delim))
                out.append(rec)
            else:  # regex
                m = re.match(self.regex, ln) if self.regex else None
                out.append({k: v for k, v in (m.groupdict() if m else {}).items() if v is not None})
        return out


def _flat(obj: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in obj.items():
        if isinstance(v, dict) and v:
            out.update(_flat(v, f"{prefix}{k}."))
        else:
            out[f"{prefix}{k}"] = v
    return out


def _kv(s: str, fd: str, vd: str) -> dict[str, str]:
    out = {}
    for tok in (s.split(fd) if fd != " " else re.findall(r'[^\s"]+(?:"[^"]*")?', s)):
        if vd in tok:
            k, _, v = tok.partition(vd)
            out[k.strip()] = v.strip().strip('"')
    return out


def rx_escape(s: str) -> str:
    """Escape for both Python `re` and Rust `regex` (VRL): only the classic
    metacharacters, and control characters as \\xHH."""
    out = []
    for ch in s:
        if ch in "\\.+*?()|[]{}^$":
            out.append("\\" + ch)
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(ch)
    return "".join(out)


def class_escape(ch: str) -> str:
    """One character for use inside [...]."""
    if ch in "\\]^-[":
        return "\\" + ch
    if ord(ch) < 0x20 or ord(ch) == 0x7F:
        return f"\\x{ord(ch):02x}"
    return ch


def _consistent(lines: list[str], ch: str) -> int | None:
    counts = [ln.count(ch) for ln in lines]
    if not counts or min(counts) == 0:
        return None
    mode, n = Counter(counts).most_common(1)[0]
    return mode if n / len(counts) >= 0.9 else None


def _kv_ratio(segment_values: list[str]) -> tuple[str, str] | None:
    """If segment values look like 'k<vd>v<fd>k<vd>v', return (fd, vd)."""
    for fd in (";", ",", " ", "&"):
        for vd in KV_SEPS:
            ok = 0
            for s in segment_values:
                toks = [t for t in s.split(fd) if t]
                if len(toks) >= 2 and all(re.fullmatch(r"[A-Za-z_][\w.\-]*" + re.escape(vd) + r".*", t) for t in toks):
                    ok += 1
            if segment_values and ok / len(segment_values) >= 0.9:
                return fd, vd
    return None


def infer_structure(lines: list[str], *, layer: str | None = None) -> Structure:
    """`layer` is the format layer the runtime detected (from Vector output)."""
    if layer == "json" or all(ln.lstrip().startswith("{") for ln in lines):
        return Structure("json", evidence=["runtime detected a JSON object layer" if layer == "json" else "all lines start with '{'"])
    if layer == "kv":
        return Structure("kv", kv_field_delim=" ", kv_value_delim="=", evidence=["runtime detected a key=value layer"])
    for d in DELIMS:
        n = _consistent(lines, d)
        if n is None or n < 2:
            continue
        segs = [ln.split(d) for ln in lines]
        width = Counter(len(s) for s in segs).most_common(1)[0][0]
        segs = [s for s in segs if len(s) == width]
        last = [s[-1] for s in segs]
        kv = _kv_ratio(last)
        if kv:
            fd, vd = kv
            names = [f"h{i}" for i in range(width - 1)]
            ex = "^" + rx_escape(d).join(f"(?P<{n_}>[^{class_escape(d)}]*)" for n_ in names) + rx_escape(d) + "(?P<payload>.*)$"
            return Structure("delimited_kv", delimiter=d, kv_field_delim=fd, kv_value_delim=vd, header_fields=names, extract=ex,
                             evidence=[f"{d!r} occurs {n}x in >=90% of lines ({width} segments)",
                                       f"last segment is a {fd!r}-separated list of key{vd}value pairs"])
        return Structure("csv", delimiter=d, columns=[f"col_{i}" for i in range(width)],
                         evidence=[f"{d!r} occurs {n}x in >=90% of lines -> {width} positional columns"])
    return Structure("regex", regex=None, evidence=["no consistent delimiter; template mining required"])


def mean(xs: list[float]) -> float:
    return statistics.fmean(xs) if xs else 0.0


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
