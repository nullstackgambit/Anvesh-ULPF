"""Source specifications: loading, structural validation and semantic lint.

``ulpf spec lint`` = strict YAML (duplicate keys are errors) + JSON Schema
(schema/spec.schema.json) + the semantic checks below, all against the
vendored OCSF schema. A spec with lint *errors* is never compiled.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from functools import cached_property, lru_cache
from pathlib import Path
from typing import Any, Iterable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import jsonschema

from . import paths
from .ocsf import Ocsf, default as default_ocsf
from .yamlsafe import DuplicateKeyError, load_file

# DSL coercion type -> OCSF types it may be written to.
TYPE_COMPAT: dict[str, set[str]] = {
    "string": {"string_t", "hostname_t", "url_t", "file_name_t", "file_path_t", "username_t",
               "process_name_t", "resource_uid_t", "file_hash_t", "reg_key_path_t"},
    "ip": {"ip_t"},
    "subnet": {"subnet_t"},
    "mac": {"mac_t"},
    "port": {"port_t", "integer_t", "long_t"},
    "int": {"integer_t", "long_t"},
    "long": {"long_t"},
    "float": {"float_t"},
    "bool": {"boolean_t"},
    "timestamp": {"timestamp_t"},
    "json": {"json_t"},
}

# Attributes ULPF itself owns; specs must not write them.
RESERVED = {
    "class_uid", "class_name", "category_uid", "category_name", "type_uid", "type_name",
    "metadata.version", "metadata.uid", "metadata.logged_time", "metadata.processed_time",
    "metadata.log_format", "metadata.loggers", "metadata.transformation_info_list",
    "metadata.profiles", "metadata.product", "metadata.product.name", "metadata.product.vendor_name",
    "raw_data", "raw_data_size", "raw_data_hash", "unmapped", "time",
}

SYSLOG_FIELDS = ("hostname", "appname", "procid", "msgid", "facility", "severity", "version", "timestamp_raw")
TIME_FORMATS = {"epoch_auto", "epoch_s", "epoch_ms", "epoch_us", "epoch_ns", "rfc3339"}
# Rust's regex crate (used by VRL) has no look-around and no backreferences.
_RUST_INCOMPATIBLE = re.compile(r"\(\?<?[=!]|\\[1-9]")
_PRINTABLE = re.compile(r"^[\x20-\x7e]*$")


@dataclass
class Issue:
    level: str  # error | warning
    where: str
    message: str

    def __str__(self) -> str:
        return f"{self.level.upper():7s} {self.where}: {self.message}"


@dataclass
class Spec:
    path: Path
    data: dict

    @cached_property
    def sha256(self) -> str:
        """Hash of the canonical JSON form (comments/formatting do not count)."""
        canon = {k: v for k, v in self.data.items() if k not in ("approval", "onboarding")}
        return hashlib.sha256(json.dumps(canon, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    @cached_property
    def content_sha256(self) -> str:
        """Like sha256, but also ignores `status`: a gated draft and the spec
        promoted from it have the same content hash (ulpf gate/promote)."""
        canon = {k: v for k, v in self.data.items() if k not in ("approval", "onboarding", "status")}
        return hashlib.sha256(json.dumps(canon, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    @property
    def id(self) -> str:
        return self.data["id"]

    @property
    def version(self) -> str:
        return self.data["version"]

    @property
    def class_name(self) -> str:
        return self.data["ocsf"]["class"]

    @property
    def profiles(self) -> list[str]:
        return sorted(self.data["ocsf"].get("profiles") or [])

    @property
    def priority(self) -> int:
        return int(self.data.get("priority", 100))

    @property
    def is_draft(self) -> bool:
        return self.data.get("status", "approved") == "draft"

    @property
    def transform_id(self) -> str:
        return "p_" + re.sub(r"[^a-z0-9_]", "_", self.id)

    def declared_source_fields(self) -> set[str] | None:
        """Source fields the parse step can produce, if knowable statically."""
        p = self.data["parse"]
        extra = {f"syslog.{f}" for f in SYSLOG_FIELDS} if p.get("include_syslog") else set()
        if p.get("extract"):
            try:
                extra |= set(re.compile(p["extract"]).groupindex) - {"payload"}
            except re.error:
                pass
        if p["kind"] == "csv":
            cols = {c for seg in p["csv"]["segments"] for c in seg["columns"]}
            return cols | extra
        if p["kind"] == "regex":
            try:
                return set(re.compile(_py_regex(p["regex"]["pattern"])).groupindex) | extra
            except re.error:
                return None
        if p["kind"] == "leef":
            return None
        return None


def _py_regex(pattern: str) -> str:
    return pattern


@lru_cache(maxsize=1)
def _schema_validator() -> jsonschema.Draft202012Validator:
    schema = json.loads(paths.SPEC_SCHEMA.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def load(path: Path) -> Spec:
    data = load_file(path)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top level must be a mapping")
    return Spec(Path(path), data)


def discover(include_drafts: bool = False, root: Path = paths.SPECS) -> list[Path]:
    out = []
    for p in sorted(root.rglob("*.yaml")):
        if paths.DRAFTS in p.parents and not include_drafts:
            continue
        out.append(p)
    return out


# ------------------------------------------------------------------- lint
def lint_file(path: Path, ocsf: Ocsf | None = None, seen_ids: Counter | None = None) -> tuple[Spec | None, list[Issue]]:
    where = str(path)
    try:
        spec = load(path)
    except DuplicateKeyError as e:
        return None, [Issue("error", where, f"invalid YAML: {e}")]
    except Exception as e:  # noqa: BLE001 - report any YAML/IO problem as a lint error
        return None, [Issue("error", where, f"invalid YAML: {e}")]
    issues = [Issue("error", f"{where}:{'/'.join(str(p) for p in e.absolute_path) or '<root>'}", e.message)
              for e in sorted(_schema_validator().iter_errors(spec.data), key=lambda e: list(e.absolute_path))]
    if issues:
        return spec, issues  # semantic checks assume a structurally valid spec
    issues.extend(semantic_lint(spec, ocsf or default_ocsf()))
    if seen_ids is not None and seen_ids[spec.id] > 1:
        issues.append(Issue("error", where, f"spec id {spec.id!r} is not unique ({seen_ids[spec.id]} files)"))
    return spec, issues


def lint_all(paths_: Iterable[Path], ocsf: Ocsf | None = None) -> dict[Path, tuple[Spec | None, list[Issue]]]:
    plist = list(paths_)
    ids: Counter = Counter()
    for p in plist:
        try:
            d = load_file(p)
            if isinstance(d, dict) and isinstance(d.get("id"), str):
                ids[d["id"]] += 1
        except Exception:  # noqa: BLE001 - reported by lint_file
            pass
    return {p: lint_file(p, ocsf, ids) for p in plist}


def _sibling_names(o: Ocsf, cls: str) -> set[str]:
    out = set()
    for a in o.class_def(cls)["attributes"].values():
        if a.get("sibling"):
            out.add(a["sibling"])
    return out


def semantic_lint(spec: Spec, o: Ocsf) -> list[Issue]:
    issues: list[Issue] = []
    W = str(spec.path)

    def err(where: str, msg: str) -> None:
        issues.append(Issue("error", f"{W}:{where}", msg))

    def warn(where: str, msg: str) -> None:
        issues.append(Issue("warning", f"{W}:{where}", msg))

    d = spec.data
    cls = spec.class_name
    try:
        cdef = o.class_def(cls)
    except KeyError as e:
        err("ocsf.class", str(e))
        return issues
    for p in spec.profiles:
        if p not in (cdef.get("profiles") or []):
            err("ocsf.profiles", f"profile {p!r} is not defined for class {cls} in OCSF {o.version}")
    if o.schema_file(cls, spec.profiles) is None:
        err("ocsf.profiles", f"no vendored JSON Schema for {cls} with profiles {spec.profiles}; "
                             "add the combination to tools/fetch_ocsf.py and re-vendor")

    # ---- match
    m = d["match"]
    if not (m.get("all") or m.get("any")):
        err("match", "match needs a non-empty `all` or `any` (an empty match would claim every event)")
    for kind in ("all", "any", "none"):
        for i, c in enumerate(m.get(kind) or []):
            _lint_condition(c, f"match.{kind}[{i}]", err)

    # ---- parse
    p = d["parse"]
    if p.get("extract"):
        _lint_regex(p["extract"], "parse.extract", err)
        try:
            if "payload" not in re.compile(p["extract"]).groupindex:
                err("parse.extract", "extract regex needs a named group (?P<payload>...)")
        except re.error:
            pass
    if p["kind"] == "csv" and "csv" not in p:
        err("parse.csv", "kind csv requires parse.csv.segments")
    if p["kind"] == "regex":
        if "regex" not in p:
            err("parse.regex", "kind regex requires parse.regex.pattern")
        else:
            _lint_regex(p["regex"]["pattern"], "parse.regex.pattern", err)
            try:
                if not re.compile(p["regex"]["pattern"]).groupindex:
                    err("parse.regex.pattern", "pattern has no named groups (?P<name>...)")
            except re.error as e:
                err("parse.regex.pattern", f"invalid regex: {e}")
    if p["kind"] == "csv":
        seen_cols: Counter = Counter(c for seg in p["csv"]["segments"] for c in seg["columns"])
        defined: set[str] = set()
        for i, seg in enumerate(p["csv"]["segments"]):
            w = seg.get("when")
            if w and w["column"] not in defined:
                err(f"parse.csv.segments[{i}].when", f"column {w['column']!r} is not defined by an earlier segment")
            if w and not ("equals" in w or "in" in w):
                err(f"parse.csv.segments[{i}].when", "needs equals or in")
            defined.update(seg["columns"])
        for col, n in seen_cols.items():
            # The same column name may appear in mutually exclusive branches only.
            if n > 1 and not _all_conditional(p["csv"]["segments"], col):
                err("parse.csv.segments", f"column {col!r} defined {n} times in unconditional segments")
    for k in (p.get("kv") or {}).values():
        if not _PRINTABLE.match(k) and k not in ("\t",):
            err("parse.kv", f"delimiter {k!r} must be printable ASCII or TAB")

    declared = spec.declared_source_fields()
    used_sources: Counter = Counter()
    dests: dict[str, str] = {}
    siblings = _sibling_names(o, cls)

    generic_ok = {"metadata.product.name", "metadata.product.vendor_name", "metadata.product.version"} if d.get("generic") else set()

    def claim_dest(dest: str, by: str) -> None:
        if dest in RESERVED and dest not in generic_ok:
            err(by, f"{dest!r} is owned by ULPF and cannot be written by a spec")
        elif dest in siblings:
            err(by, f"{dest!r} is a caption sibling filled from its *_id attribute; map the *_id instead")
        if dest in dests:
            err(by, f"destination {dest!r} is already written by {dests[dest]}")
        dests[dest] = by

    def use_source(name: str, by: str) -> None:
        # one value mapping (fields) and one enum derivation may share a source
        # field (e.g. an HTTP method feeds http_method and activity_id); two of
        # the same kind would be ambiguous.
        used_sources[(by.split(".")[0].split("[")[0], name)] += 1
        if not _PRINTABLE.match(name) or any(c in name for c in '"\\{}'):
            err(by, f"source field name {name!r} must be printable ASCII without quotes, backslashes or braces")
        if declared is not None and name not in declared:
            err(by, f"source field {name!r} is not produced by parse ({sorted(declared)[:8]}...)")

    def resolve(dest: str, by: str):
        try:
            return o.resolve(cls, dest, spec.profiles)
        except KeyError as e:
            err(by, str(e).strip('"'))
            return None

    # ---- time (candidates are alternatives: their fields count once)
    time_fields: set[str] = set()
    time_offsets: set[str] = set()
    for t in d.get("time") or []:
        time_fields.update([t["field"]] if "field" in t else t["fields"])
        if t.get("offset_field"):
            time_offsets.add(t["offset_field"])
    for f in sorted(time_fields | time_offsets):
        use_source(f, "time")
    for i, t in enumerate(d.get("time") or []):
        w = f"time[{i}]"
        fmt = t["format"]
        if fmt not in TIME_FORMATS and "%" not in fmt:
            err(w, f"format {fmt!r} is neither {sorted(TIME_FORMATS)} nor a strftime pattern")
        if fmt.startswith("epoch") and ("timezone" in t or "offset_field" in t):
            warn(w, "epoch timestamps are absolute; timezone/offset_field are ignored")
        if "%" in fmt and "%Y" not in fmt and "%G" not in fmt and t.get("year") != "infer":
            err(w, "strftime format has no year; set year: infer to use the receipt year")
        _lint_tz(t.get("timezone"), w, err)
    if not d.get("time"):
        warn("time", "no time block: event time will be the receipt time (recorded in ulpf.time.source=ingest)")

    # ---- fields
    for src, f in (d.get("fields") or {}).items():
        w = f"fields.{src}"
        use_source(src, w)
        if f.get("unmapped"):
            continue
        dest, typ = f["to"], f["type"]
        claim_dest(dest, w)
        a = resolve(dest, w)
        if a is None:
            continue
        if a.is_object:
            err(w, f"{dest!r} is an object ({a.object_type}); map a scalar attribute inside it")
            continue
        if a.is_array:
            err(w, f"{dest!r} is an array attribute; array mappings are not supported")
        if a.enum and not a.is_string_enum:
            err(w, f"{dest!r} is an enum attribute; use an `enums` entry so the caption sibling is filled")
        if a.is_string_enum and typ != "string":
            err(w, f"{dest!r} is a string enumeration; map it with type string")
        if a.type not in TYPE_COMPAT[typ]:
            err(w, f"type {typ!r} cannot be written to {dest!r} ({a.type}); allowed for {a.type}: "
                   f"{sorted(k for k, v in TYPE_COMPAT.items() if a.type in v) or 'none'}")
        if typ == "timestamp" and not f.get("format"):
            err(w, "type timestamp needs format")
        if f.get("transform") and typ != "string":
            err(w, "transform applies to type string only")
        if f.get("scale") is not None and typ not in ("int", "long", "float"):
            err(w, "scale applies to numeric types only")
        _lint_tz(f.get("timezone"), w, err)

    # ---- enums
    for i, e in enumerate(d.get("enums") or []):
        w = f"enums[{i}]"
        use_source(e["source"], w)
        if "default" in e and "otherwise" in e:
            err(w, "use either default (flagged as partial) or otherwise (expected catch-all), not both")
        targets: set[str] = set()
        for key in ("map", "default", "missing", "otherwise"):
            tables = e[key].values() if key == "map" else ([e[key]] if key in e else [])
            for tbl in tables:
                targets.update(tbl)
        for dest in sorted(targets):
            claim_dest(dest, w)
            a = resolve(dest, w)
            if a is None:
                continue
            if not a.enum:
                err(w, f"{dest!r} is not an enum attribute")
                continue
            for key in ("map", "default", "missing", "otherwise"):
                tables = list(e[key].items()) if key == "map" else ([("", e[key])] if key in e else [])
                for val, tbl in tables:
                    if dest in tbl and tbl[dest] not in a.enum:
                        err(f"{w}.{key}{('.' + val) if val else ''}", f"{tbl[dest]} is not a valid {dest} value {sorted(a.enum)}")
        keys = list(e["map"])
        if e.get("case_insensitive", True):
            low = Counter(k.lower() for k in keys)
            for k, n in low.items():
                if n > 1:
                    err(f"{w}.map", f"keys collide case-insensitively: {k!r}")

    # ---- set
    for dest, val in (d.get("set") or {}).items():
        w = f"set.{dest}"
        claim_dest(dest, w)
        a = resolve(dest, w)
        if a is None:
            continue
        base = o.base_type(a.type)
        if a.enum is not None:
            if not isinstance(val, int) or val not in a.enum:
                err(w, f"{val!r} is not a valid {dest} value {sorted(a.enum)}")
        elif base in ("integer_t", "long_t") and (not isinstance(val, int) or isinstance(val, bool)):
            err(w, f"{dest} is {a.type}; value must be an integer")
        elif base == "string_t" and not isinstance(val, str):
            err(w, f"{dest} is {a.type}; value must be a string")
        elif base == "boolean_t" and not isinstance(val, bool):
            err(w, f"{dest} is {a.type}; value must be true/false")

    # ---- derive
    for i, dv in enumerate(d.get("derive") or []):
        w = f"derive[{i}]"
        claim_dest(dv["to"], w)
        resolve(dv["to"], w)
        using = dv["using"]
        if using in ("iana_protocol_name", "iana_protocol_num", "copy"):
            if not dv.get("from"):
                err(w, f"{using} needs from: <OCSF path>")
            elif dv["from"] not in dests:
                err(w, f"from {dv['from']!r} is not written by fields/enums/set before this derive")
        if using == "tz_offset_minutes":
            if not dv.get("source"):
                err(w, "tz_offset_minutes needs source: <source field>")
            elif dv["source"] not in time_offsets:
                # the same offset field may serve the time block and timezone_offset
                use_source(dv["source"], w)
        if using == "community_id":
            for need in ("src_endpoint.ip", "dst_endpoint.ip", "connection_info.protocol_num"):
                if need not in dests:
                    err(w, f"community_id needs {need} to be mapped")

    for (kind, name), n in used_sources.items():
        if n > 1:
            err(kind, f"source field {name!r} is consumed {n} times by {kind} (each source field may feed one {kind} entry)")
    fsrc = {nm for (k, nm) in used_sources if k == "fields"}
    for (k, nm) in used_sources:
        if k == "time" and nm in fsrc:
            err("time", f"source field {nm!r} is used by both time and fields")

    # ---- required OCSF attributes
    for attr, a in cdef["attributes"].items():
        if a.get("requirement") != "required" or a.get("profiles"):
            continue
        if attr in RESERVED or attr in ("metadata",):
            continue
        if attr not in dests:
            if attr in ("activity_id", "severity_id"):
                warn("ocsf", f"required {attr} is not mapped; it will default to 0 (Unknown)")
            else:
                err("ocsf", f"required attribute {attr!r} of {cls} is not mapped")
    for kind, names in (cdef.get("constraints") or {}).items():
        if kind == "at_least_one" and not any(any(dd == n or dd.startswith(n + ".") for dd in dests) for n in names):
            err("ocsf", f"class constraint at_least_one{names}: map at least one of them")

    # ---- pii / tests
    for i, pi in enumerate(d.get("pii") or []):
        if pi["field"] not in {nm for (_, nm) in used_sources} and declared is not None and pi["field"] not in declared:
            warn(f"pii[{i}]", f"{pi['field']!r} is not a known source field")
    names = Counter(t["name"] for t in d["tests"])
    for n, c in names.items():
        if c > 1:
            err("tests", f"duplicate test name {n!r}")
    for i, t in enumerate(d["tests"]):
        if t.get("raw_file") and not (paths.HOME / t["raw_file"]).exists():
            err(f"tests[{i}]", f"raw_file {t['raw_file']!r} not found")
    if d.get("samples") is None:
        warn("samples", "declare samples: synthetic|real|mixed (no-fabrication policy)")
    return issues


def _all_conditional(segments: list[dict], col: str) -> bool:
    return all(seg.get("when") for seg in segments if col in seg["columns"])


def _lint_condition(c: dict, where: str, err) -> None:
    ops = [k for k in ("equals", "in", "prefix", "contains", "regex", "exists") if k in c]
    if "layer" in c and ops:
        err(where, "a condition is either `layer` or `field` + one operator")
    if "field" in c and len(ops) != 1:
        err(where, "a field condition needs exactly one operator (equals/in/prefix/contains/regex/exists)")
    if "field" in c and not re.match(r"^(body|after_pri|text|raw|(syslog|json|cef|leef|kv)(\.[^.]+)+)$", c["field"]):
        err(where, f"field {c['field']!r} must be body|after_pri|text or <layer>.<key> (layers: syslog, json, cef, leef, kv)")
    if "regex" in c:
        _lint_regex(c["regex"], where, err)
    for k in ("equals", "prefix", "contains"):
        if isinstance(c.get(k), str) and not _PRINTABLE.match(c[k]):
            err(where, f"{k} literal must be printable ASCII")


def _lint_regex(pattern: str, where: str, err) -> None:
    if _RUST_INCOMPATIBLE.search(pattern):
        err(where, "look-around and backreferences are not supported by VRL's regex engine")
    if "'" in pattern:
        err(where, "regex may not contain a single quote (VRL raw string literal); use \\x27")
    try:
        re.compile(pattern)
    except re.error as e:
        err(where, f"invalid regex: {e}")


def _lint_tz(tz: str | None, where: str, err) -> None:
    if not tz or tz == "UTC":
        return
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError):
        err(where, f"unknown IANA timezone {tz!r}")


def load_iana_protocols() -> dict[int, str]:
    """IANA protocol numbers -> lowercase keyword (OCSF protocol_name convention)."""
    import csv

    out: dict[int, str] = {}
    with open(paths.SCHEMA / "iana" / "protocol-numbers-1.csv", newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            dec, kw = row["Decimal"].strip(), row["Keyword"].strip()
            if dec.isdigit() and kw and " " not in kw:
                out[int(dec)] = kw.lower()
    return out
