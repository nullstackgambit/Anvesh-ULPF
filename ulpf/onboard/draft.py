"""Draft specification writer (`ulpf onboard`).

Input: raw samples of ONE unknown-source cluster (bytes from the archive) and
the runtime pre-parser's view of them. Output: a draft spec in specs/_drafts
with every proposal explained, plus test vectors whose expectations are
computed here in Python -- independently of the VRL the compiler will emit.

Nothing written here is trusted: the draft must pass `ulpf gate` and a named
human must `ulpf promote` it. Low-confidence and LLM suggestions are written
as inactive comments for the reviewer, never as active mappings.
"""
from __future__ import annotations

import datetime as dt
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .. import __version__, paths
from ..ocsf import Ocsf, default as default_ocsf
from ..spec import SYSLOG_FIELDS, load_iana_protocols
from . import suggest
from .infer import FieldStats, Structure, class_escape, infer_structure, rx_escape, stats_for
from .mining import mine, template_pattern
from .store import Cluster, RawSample

PROFILE_COMBOS: tuple[list[str], ...] = ([], ["security_control"], ["host", "security_control"])
LAYERS = ("json", "cef", "leef", "kv", "csv")
ACTIVE_MIN = 0.5            # suggestions below this are written as comments only
DRAFT_PRIORITY = 150        # above the generic specs (10-20), below vendor specs (200)
_IDENT_VALUE = re.compile(r"^[A-Za-z][A-Za-z0-9_.\-]{0,40}$")
_UPPER_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{1,31}$")


class OnboardError(Exception):
    pass


@dataclass
class Proposal:
    spec_id: str
    data: dict
    text: str
    report: dict
    inactive: list[dict] = field(default_factory=list)


# ------------------------------------------------------------------ helpers
def _s(v) -> str:
    if isinstance(v, (dict, list)):
        return json.dumps(v, sort_keys=True)
    return "" if v is None else str(v)


def _flat(obj: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in obj.items():
        if isinstance(v, dict) and v:
            out.update(_flat(v, f"{prefix}{k}."))
        else:
            out[f"{prefix}{k}"] = v
    return out


def minimal_profiles(o: Ocsf, cls: str, dests: list[str]) -> list[str] | None:
    """Smallest vendored profile combination under which every dest resolves."""
    for combo in PROFILE_COMBOS:
        try:
            for d in dests:
                o.resolve(cls, d, combo)
        except KeyError:
            continue
        return list(combo)
    return None


def common_layer(pres: list[dict]) -> str | None:
    for layer in LAYERS:
        if pres and all(layer in (p.get("pre") or {}) for p in pres):
            return layer
    return None


def syslog_fields(pre: dict) -> dict[str, str]:
    sy = pre.get("syslog") or {}
    out = {f"syslog.{f}": _s(sy[f]) for f in SYSLOG_FIELDS if f != "timestamp_raw" and f in sy}
    if pre.get("syslog_ts_raw") is not None:
        out["syslog.timestamp_raw"] = _s(pre["syslog_ts_raw"])
    return out


def layer_records(layer: str, pres: list[dict]) -> list[dict[str, str]]:
    out = []
    for p in pres:
        pre = p["pre"]
        if layer == "json":
            out.append({k: _s(v) for k, v in _flat(pre["json"]).items()})
        elif layer == "kv":
            out.append({k: _s(v) for k, v in pre["kv"].items()})
        elif layer == "cef":
            out.append({k: _s(v) for k, v in pre["cef"].items()})
        elif layer == "leef":
            lf = pre["leef"]
            rec = {k: _s(v) for k, v in (lf.get("attributes") or {}).items()}
            rec.update({f"leef.{h}": _s(lf[h]) for h in ("version", "vendor", "product", "product_version", "event_id") if h in lf})
            out.append(rec)
        elif layer == "csv":
            out.append({f"col_{i}": _s(v) for i, v in enumerate(pre["csv"])})
    return out


# ------------------------------------------------------------- structure
@dataclass
class Shape:
    parse: dict
    match: dict
    records: list[dict[str, str]]
    evidence: list[str]
    templates: list[dict] = field(default_factory=list)


def _constant(records: list[dict], key: str) -> str | None:
    vals = {r.get(key) for r in records}
    return next(iter(vals)) if len(vals) == 1 and None not in vals else None


def _kv_or_json_match(layer: str, records: list[dict]) -> list[dict]:
    present = set.intersection(*(set(k for k, v in r.items() if v not in ("", None)) for r in records)) if records else set()
    present = {k for k in present if "." not in k and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\-]*", k)}
    conds = []
    consts = sorted(k for k in present if (v := _constant(records, k)) and _IDENT_VALUE.match(v) and not v.isdigit())
    for k in consts[:2]:
        conds.append({"field": f"{layer}.{k}", "equals": _constant(records, k)})
    for k in sorted(present - set(consts), key=lambda k: (-len(k), k))[: max(0, 3 - len(conds))]:
        conds.append({"field": f"{layer}.{k}", "exists": True})
    return conds


def _skeleton(delim: str, names: list[str], records: list[dict], tail: str = "") -> str:
    parts = []
    for i, n in enumerate(names):
        v = _constant(records, n)
        if v is not None and v and (i == 0 or _UPPER_TOKEN.match(v)) and _IDENT_VALUE.match(v):
            parts.append(rx_escape(v))
        else:
            parts.append(f"[^{class_escape(delim)}]*")
    return "^" + rx_escape(delim).join(parts) + rx_escape(delim) + tail


def shape_for(samples: list[RawSample], pres: list[dict]) -> Shape:
    layer = common_layer(pres)
    bodies = [_s(p["pre"].get("body")) for p in pres]
    if layer in ("json", "kv"):
        recs = layer_records(layer, pres)
        parse = {"kind": layer, "input": "body"}
        if layer == "kv":
            parse["kv"] = {"field_delimiter": " ", "value_delimiter": "="}
        conds = _kv_or_json_match(layer, recs)
        return Shape(parse, {"all": [{"layer": layer}] + conds}, recs,
                     [f"runtime pre-parser found a {layer} layer in {len(pres)}/{len(pres)} samples"])
    if layer in ("cef", "leef"):
        recs = layer_records(layer, pres)
        keys = ("deviceVendor", "deviceProduct") if layer == "cef" else ("leef.vendor", "leef.product")
        conds = [{"layer": layer}]
        for k in keys:
            v = _constant(recs, k)
            if v and all(0x20 <= ord(c) < 0x7F for c in v):
                conds.append({"field": f"{layer}.{k.split('.')[-1]}", "equals": v})
        return Shape({"kind": layer}, {"all": conds}, recs,
                     [f"runtime pre-parser found a {layer.upper()} layer in all samples; vendor/product header is constant"])
    if layer == "csv":
        recs = layer_records(layer, pres)
        width = max(len(r) for r in recs)
        cols = [f"col_{i}" for i in range(width)]
        return Shape({"kind": "csv", "input": "body", "csv": {"delimiter": ",", "segments": [{"columns": cols}]}},
                     {"all": [{"layer": "csv"}, {"field": "body", "regex": _skeleton(",", cols[:6], recs)}]}, recs,
                     [f"runtime pre-parser found a comma-separated layer ({width} columns)"])
    # plain text: infer the structure from the bodies themselves
    st = infer_structure(bodies)
    if st.kind == "delimited_kv":
        recs = st.records(bodies)
        tail = "[A-Za-z_][A-Za-z0-9_.\\-]*" + rx_escape(st.kv_value_delim or "=")
        parse = {"kind": "kv", "input": "body", "extract": st.extract,
                 "kv": {"field_delimiter": st.kv_field_delim, "value_delimiter": st.kv_value_delim}}
        return Shape(parse, {"all": [{"field": "body", "regex": _skeleton(st.delimiter, st.header_fields, recs, tail)}]},
                     recs, st.evidence)
    if st.kind == "csv":
        recs = st.records(bodies)
        return Shape({"kind": "csv", "input": "body", "csv": {"delimiter": st.delimiter, "segments": [{"columns": st.columns}]}},
                     {"all": [{"field": "body", "regex": _skeleton(st.delimiter, st.columns[:6], recs)}]}, recs, st.evidence)
    if st.kind == "json":
        raise OnboardError("samples look like JSON but the runtime found no JSON layer (invalid JSON?)")
    # free text: Drain3 templates; the dominant template becomes a regex parser
    templates = mine(bodies)
    top = templates[0]
    share = top.count / len(bodies)
    pattern, groups = template_pattern(top.text)
    st = Structure("regex", regex=pattern)
    recs = st.records(bodies)
    ev = st.evidence + [f"drain3: {len(templates)} template(s); dominant template covers {share:.0%} of samples: {top.text!r}"]
    if share < 0.9:
        ev.append("WARNING: the dominant template covers < 90% of samples; onboard the rest separately")
    return Shape({"kind": "regex", "input": "body", "regex": {"pattern": pattern}},
                 {"all": [{"field": "body", "regex": pattern}]}, recs, ev,
                 [t.to_dict() for t in templates[:10]])


# ---------------------------------------------------------- expectations
def _coerce(sg_type: str, transform: str | None, v: str):
    if transform == "lower":
        v = v.lower()
    elif transform == "upper":
        v = v.upper()
    elif transform == "trim":
        v = v.strip()
    if sg_type in ("port", "int", "long"):
        return int(v)
    if sg_type == "float":
        return float(v)
    return v


def _epoch_ms(v: str) -> int | None:
    digits = v.split(".")[0]
    n = len(digits)
    if not digits.isdigit():
        return None
    if n <= 11:
        return int(round(float(v) * 1000))
    if n == 13:
        return int(digits)
    if n == 16:
        return int(digits) // 1000
    if n == 19:
        return int(digits) // 1_000_000
    return None


def _expected_time(entry: dict, rec: dict) -> int | None:
    v = rec.get(entry["field"])
    if not v:
        return None
    fmt = entry["format"]
    if fmt == "rfc3339":
        t = dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
        return (t - dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)) // dt.timedelta(milliseconds=1)
    if fmt.startswith("epoch"):
        return _epoch_ms(v)
    if entry.get("year") or entry.get("timezone", "UTC") != "UTC":
        return None  # year inference / zone rules: asserted by the golden file instead
    t = dt.datetime.strptime(v, fmt).replace(tzinfo=dt.timezone.utc)
    return (t - dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)) // dt.timedelta(milliseconds=1)


def expectations(spec_id: str, rec: dict, active: list[suggest.Suggestion], time_entry: dict | None,
                 enum: dict | None, derive: list[dict], iana_num: dict[str, int]) -> dict:
    exp: dict = {"ulpf.status": "parsed", "ulpf.parser.id": spec_id}
    for sg in active:
        v = rec.get(sg.source)
        if v in (None, "", "-"):
            continue
        try:
            exp[sg.to] = _coerce(sg.type, sg.transform, v)
        except ValueError:
            continue
    if time_entry:
        t = _expected_time(time_entry, rec)
        if t is not None:
            exp["time"] = t
    if enum:
        v = rec.get(enum["source"])
        if v not in (None, ""):
            hit = next((tbl for k, tbl in enum["map"].items() if k.lower() == v.lower()), None)
            exp.update(hit if hit is not None else enum["default"])
    for dv in derive:
        if dv["using"] == "iana_protocol_num" and dv["from"] in exp:
            num = iana_num.get(str(exp[dv["from"]]).lower())
            if num is not None:
                exp[dv["to"]] = num
    return exp


def pick_tests(records: list[dict], samples: list[RawSample], enum_src: str | None, n_max: int) -> list[int]:
    ok = [i for i, s in enumerate(samples) if _utf8(s.raw) is not None]
    chosen: list[int] = []
    if enum_src:
        seen = set()
        for i in ok:
            v = records[i].get(enum_src)
            if v not in seen:
                seen.add(v)
                chosen.append(i)
    rest = [i for i in ok if i not in chosen]
    k = max(0, n_max - len(chosen))
    if rest and k:
        step = max(1, len(rest) // k)
        chosen += rest[::step][:k]
    return sorted(chosen[:n_max])


def _utf8(b: bytes) -> str | None:
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return None


# ------------------------------------------------------------------ propose
def propose(samples: list[RawSample], pres: dict[str, dict], *, spec_id: str, vendor: str, product: str,
            cls: str = "network_activity", samples_kind: str, cluster: Cluster | None = None,
            use_llm: bool = False, max_tests: int = 5, o: Ocsf | None = None) -> Proposal:
    o = o or default_ocsf()
    if not re.fullmatch(r"[a-z0-9_]+(\.[a-z0-9_]+){2,}", spec_id):
        raise OnboardError("spec id must look like vendor.product.logtype (lowercase, dot-separated)")
    samples = [s for s in samples if s.event_uid in pres]
    plist = [pres[s.event_uid] for s in samples]
    if len(samples) < 3:
        raise OnboardError(f"need at least 3 samples, have {len(samples)}")
    bad = [p["event_uid"] for p in plist if p.get("oversized") or p.get("integrity_error")]
    if bad:
        raise OnboardError(f"{len(bad)} sample(s) are oversized or failed archive re-verification: {bad[:3]}")
    shape = shape_for(samples, plist)
    records = shape.records
    if all(not r for r in records):
        raise OnboardError("the inferred structure extracted no fields from the samples")
    include_syslog = all("syslog" in (p["pre"] or {}) for p in plist)
    if include_syslog:
        shape.parse["include_syslog"] = True
        for r, p in zip(records, plist):
            r.update(syslog_fields(p["pre"]))
    stats = stats_for(records)

    # --- suggestions (resolved with every vendored profile, minimised later)
    widest = PROFILE_COMBOS[-1]
    sugg = suggest.deterministic(stats, cls, widest, o)
    if include_syslog and "syslog.hostname" in stats and not any(s.to == "device.hostname" for s in sugg):
        sugg.append(suggest.Suggestion("syslog.hostname", "device.hostname", "string", 0.6,
                                       ["syslog HOSTNAME field identifies the sending device (RFC 5424 6.2.4 / RFC 3164 4.1.2)"]))
    times = suggest.time_candidates(stats)
    if not times and include_syslog and "syslog.timestamp_raw" in stats:
        times = suggest.time_candidates({"syslog.timestamp_raw": stats["syslog.timestamp_raw"]})
    enum_s = suggest.action_enum(stats, cls)
    if enum_s and any(s.source == enum_s["enum"]["source"] for s in sugg):
        enum_s = None  # the field is already mapped as a plain value
    llm: list[suggest.Suggestion] = []
    llm_info: dict = {"used": False}
    if use_llm:
        if not suggest.llm_enabled():
            raise OnboardError("--llm given but ULPF_LLM_URL is not set (local OpenAI-compatible endpoint)")
        free = {n: f for n, f in stats.items() if n not in {s.source for s in sugg}}
        llm = suggest.llm_suggestions(free, cls, widest, o)
        llm_info = {"used": True, "endpoint_host": "localhost", "accepted_after_validation": len(llm)}

    active = [s for s in sugg if s.confidence >= ACTIVE_MIN]
    inactive = [s for s in sugg if s.confidence < ACTIVE_MIN] + llm
    time_entry = times[0]["entry"] if times else None
    derive: list[dict] = []
    dests = {s.to for s in active}
    if "connection_info.protocol_name" in dests and "connection_info.protocol_num" not in dests:
        derive.append({"to": "connection_info.protocol_num", "using": "iana_protocol_num", "from": "connection_info.protocol_name"})
    if "connection_info.protocol_num" in dests and "connection_info.protocol_name" not in dests:
        derive.append({"to": "connection_info.protocol_name", "using": "iana_protocol_name", "from": "connection_info.protocol_num"})
    all_dests = dests | {d["to"] for d in derive}
    if {"src_endpoint.ip", "dst_endpoint.ip", "connection_info.protocol_num"} <= all_dests:
        derive.append({"to": "connection_info.community_uid", "using": "community_id"})
    enum_dests = sorted({k for tbl in (enum_s["enum"]["map"].values() if enum_s else []) for k in tbl})
    profiles = minimal_profiles(o, cls, sorted(all_dests | {d["to"] for d in derive}) + enum_dests)
    if profiles is None:
        raise OnboardError("no vendored profile combination covers the suggested attributes")

    # --- tests with independently computed expectations
    iana_num = {v: k for k, v in load_iana_protocols().items()}
    enum = enum_s["enum"] if enum_s else None
    idx = pick_tests(records, samples, enum["source"] if enum else None, max_tests)
    tests = []
    for n, i in enumerate(idx, 1):
        tests.append({"name": f"sample_{n:02d}", "raw": samples[i].raw.decode("utf-8"),
                      "expect": expectations(spec_id, records[i], active, time_entry, enum, derive, iana_num)})
    if not tests:
        raise OnboardError("no UTF-8 sample available for a test vector")

    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    unmapped = sorted(n for n in stats if n not in {s.source for s in active}
                      and n != (time_entry or {}).get("field") and n != (enum or {}).get("source"))
    review = [f"confirm {s.source} -> {s.to}: {s.reasons[0]}" for s in active if s.confidence < 0.8]
    review += [r for t in times[:1] for r in t["review"]] + (enum_s["review"] if enum_s else [])
    review.append("direction: confirm that the src/dst fields are the connection initiator/responder "
                  "(then set is_src_dst_assignment_known: true)")
    if unmapped:
        review.append(f"{len(unmapped)} field(s) stay in `unmapped`: {', '.join(unmapped[:12])}{' ...' if len(unmapped) > 12 else ''}")
    report = {
        "generated_by": f"ulpf {__version__} onboard",
        "generated_at": now,
        "fingerprint": cluster.fingerprint if cluster else plist[0].get("fingerprint"),
        "format": cluster.format if cluster else plist[0].get("format"),
        "samples": {"count": len(samples), "file": f"runtime/data/onboarding/{spec_id}/samples.ndjson",
                    "first_seen": cluster.first_seen if cluster else None, "last_seen": cluster.last_seen if cluster else None},
        "structure": {"parse_kind": shape.parse["kind"], "evidence": shape.evidence},
        "fields": {n: f.summary() for n, f in sorted(stats.items())},
        "suggestions": [dict(s.to_dict(), active=s in active) for s in sugg + llm],
        "time": times,
        "enum": {"source": enum["source"], "reasons": enum_s["reasons"]} if enum_s else None,
        "llm": llm_info,
        "review_required": review,
    }
    if shape.templates:
        report["templates"] = shape.templates
    data: dict = {
        "id": spec_id, "version": "0.1.0", "status": "draft", "vendor": vendor, "product": product,
        "description": f"Onboarded from unknown-source fingerprint {report['fingerprint']} ({report['format']}) with ulpf onboard.",
        "samples": samples_kind, "priority": DRAFT_PRIORITY,
        "ocsf": {"class": cls, "profiles": profiles} if profiles else {"class": cls},
        "match": shape.match, "parse": shape.parse,
    }
    if time_entry:
        data["time"] = [time_entry]
    data["fields"] = {s.source: s.field_entry() for s in active}
    if enum:
        data["enums"] = [enum]
    if derive:
        data["derive"] = derive
    data["tests"] = tests
    data["onboarding"] = report
    text = render(data, active, inactive, unmapped)
    return Proposal(spec_id, data, text, report, [s.to_dict() for s in inactive])


# ------------------------------------------------------------------ render
def _block(obj: dict) -> str:
    return yaml.safe_dump(obj, sort_keys=False, default_flow_style=False, width=1_000_000, allow_unicode=False)


def _flow_entry(key: str, value) -> str:
    s = yaml.safe_dump({key: value}, sort_keys=False, default_flow_style=True, width=1_000_000, allow_unicode=False).strip()
    assert s.startswith("{") and s.endswith("}")
    return s[1:-1]


def _comment(text: str) -> str:
    return re.sub(r"[\r\n]+", " ", text)


def render(data: dict, active: list, inactive: list, unmapped: list[str]) -> str:
    out = [
        f"# DRAFT generated by `ulpf onboard` (ulpf {__version__}) on {data['onboarding']['generated_at']}.",
        "# NOT APPROVED -- not compiled into the live pipeline. Review every mapping, then:",
        f"#   ulpf gate specs/_drafts/{data['id']}.yaml",
        f"#   ulpf promote specs/_drafts/{data['id']}.yaml --approver <your name>",
        "# Evidence for each proposal is under `onboarding:` (ignored by the compiler).",
        f"# The tests embed captured samples verbatim (samples: {data['samples']}): check them for sensitive data.",
    ]
    head = {k: data[k] for k in ("id", "version", "status", "vendor", "product", "description", "samples", "priority", "ocsf")}
    out.append(_block(head).rstrip())
    out.append("")
    out.append(_block({"match": data["match"]}).rstrip())
    out.append(_block({"parse": data["parse"]}).rstrip())
    if "time" in data:
        out.append(_block({"time": data["time"]}).rstrip())
    out.append("")
    out.append("fields:" if data["fields"] else "fields: {}")
    for s in active:
        out.append(f"  {_flow_entry(s.source, s.field_entry())}  # {s.confidence:.2f} {s.origin}: {_comment(s.reasons[0])}")
    for s in inactive:
        tag = "LLM SUGGESTION (unverified)" if s.origin == "llm" else f"low-confidence suggestion {s.confidence:.2f}"
        out.append(f"  # {tag}: {_flow_entry(s.source, s.field_entry())}  -- {_comment(s.reasons[0])}")
    if unmapped:
        out.append(f"  # not mapped (kept in `unmapped` automatically): {', '.join(unmapped)}")
    for key in ("enums", "derive"):
        if key in data:
            out.append(_block({key: data[key]}).rstrip())
    out.append("")
    out.append(_block({"tests": data["tests"]}).rstrip())
    out.append("")
    out.append(_block({"onboarding": data["onboarding"]}).rstrip())
    return "\n".join(out) + "\n"


def write(proposal: Proposal, *, drafts_dir: Path | None = None, force: bool = False) -> Path:
    from ..yamlsafe import load_text

    d = drafts_dir or paths.DRAFTS
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{proposal.spec_id}.yaml"
    if path.exists() and not force:
        raise OnboardError(f"{path} exists (use --force to overwrite the draft)")
    back = load_text(proposal.text)
    if back != json.loads(json.dumps(proposal.data)):
        raise OnboardError("internal error: rendered YAML does not round-trip to the proposal data")
    tmp = path.with_suffix(".yaml.tmp")
    tmp.write_text(proposal.text)
    tmp.replace(path)
    return path
