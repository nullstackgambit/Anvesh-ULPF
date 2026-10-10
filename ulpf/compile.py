"""Spec -> VRL compiler.

Each spec becomes one Vector `remap` program plus one boolean match
expression. The generated VRL follows a fixed set of patterns whose
fallibility was verified on Vector 0.58 (verification/P0_REPORT.md):

* every value read from the parsed source object is typed `any`, so
  conversions (`to_string`, `to_int`, ...) are always fallible and always
  branch on the error -- an invalid port never silently becomes 0 (V6);
* variables are declared before blocks (VRL block scoping);
* all literals go through ulpf.vrl (template braces escaped).

Field accounting is computed *inside* the generated program:
``fields = mapped + unmapped + empty``. A violation is reported as an error
and makes the event `partial`; the completeness test oracle additionally
re-derives the field set independently in Python.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from . import __version__, paths, vrl
from .ocsf import Ocsf, default as default_ocsf
from .pipeline import CompiledParser, Pipeline
from .spec import Spec, load_iana_protocols, lint_all, discover

MAC_RE = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"   # OCSF 1.9.0 mac_t regex
SUBNET_RE = r"^[0-9A-Fa-f:.]+/[0-9]{1,3}$"


class CompileError(RuntimeError):
    pass


def _rd(dotted: str) -> str:
    """Read an event path the program may itself have written, as type `any`.

    VRL infers precise types for paths assigned earlier in the same program,
    which makes `to_string(x) ?? ""` an E651 error when x is known; `get` on
    the event erases that type, so the generated fallbacks are always valid.
    """
    segs = ", ".join(vrl.string(s) for s in dotted.split("."))
    return f"(get(., [{segs}]) ?? null)"


# Bookkeeping objects/arrays are created with an opaque type and written with
# set(): statically keyed writes (`lin."a.b" = ...`) and pushes onto an array
# of known shape make VRL's type checker track every key/index and merge them
# at each branch -- quadratic in the number of mapped fields (finding P4b-1:
# FortiGate compile 1.8 s -> 0.9 s, see verification/VERIFICATION_REPORT.md).
_OPAQUE_OBJ = 'object(parse_json("{}") ?? null) ?? {}'
_OPAQUE_ARR = 'array(parse_json("[]") ?? null) ?? []'


def _set(var: str, key_vrl: str, value: str) -> str:
    return f"{var} = set({var}, [{key_vrl}], {value}) ?? {var}"


class _Gen:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.ind = 0

    def w(self, s: str = "") -> None:
        self.lines.append(("  " * self.ind + s) if s else "")

    def open(self, header: str) -> None:
        self.w(header + " {")
        self.ind += 1

    def mid(self, header: str) -> None:  # "} else if ... {"
        self.ind -= 1
        self.w("} " + header + " {")
        self.ind += 1

    def close(self) -> None:
        self.ind -= 1
        self.w("}")

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


# ------------------------------------------------------------------ matching
def _cond(c: dict) -> str:
    if "layer" in c:
        layer = c["layer"]
        if layer == "text":
            return 'contains(string(.ulpf.format) ?? "", "text")'
        return f"exists(._pre.{layer})"
    f = c["field"]
    if f == "text":
        p = "._raw"
    elif f in ("body", "after_pri"):
        p = f"._pre.{f}"
    else:
        p = vrl.layer_path(f)
    if "exists" in c:
        return f"exists({p})" if c["exists"] else f"!exists({p})"
    sv = f'(to_string({p}) ?? "")'
    if "equals" in c:
        return f"{sv} == {vrl.string(str(c['equals']))}"
    if "in" in c:
        return f"includes({vrl.literal([str(x) for x in c['in']])}, {sv})"
    if "prefix" in c:
        return f"starts_with({sv}, {vrl.string(c['prefix'])})"
    if "contains" in c:
        return f"contains({sv}, {vrl.string(c['contains'])})"
    if "regex" in c:
        return f"match({sv}, {vrl.regex(c['regex'])})"
    raise CompileError(f"unsupported condition {c}")


def compile_match(spec: Spec) -> str:
    m = spec.data["match"]
    parts = []
    if m.get("all"):
        parts.append(" && ".join(f"({_cond(c)})" for c in m["all"]))
    if m.get("any"):
        parts.append("(" + " || ".join(f"({_cond(c)})" for c in m["any"]) + ")")
    if m.get("none"):
        parts.append("!(" + " || ".join(f"({_cond(c)})" for c in m["none"]) + ")")
    return "(" + ") && (".join(parts) + ")"


# ------------------------------------------------------------------ parsing
def _emit_parse(g: _Gen, spec: Spec) -> None:
    p = spec.data["parse"]
    kind, inp = p["kind"], p.get("input", "body")
    g.w("pre = object(._pre) ?? {}")
    # cef/leef read the pre-parsed layer; every other kind (and extract) reads text
    needs_text = kind not in ("cef", "leef") or bool(p.get("extract"))
    if needs_text and inp == "text":
        g.w(f'itext = replace(string(._raw) ?? "", {vrl.regex(r"\r?\n\z")}, "")')
    elif needs_text:
        g.w(f'itext = string(pre.{inp}) ?? ""')
    g.w("src = {}")
    g.w("perr = null")
    if p.get("extract"):
        import re as _re

        g.w("xsrc = {}")

        xgroups = [n for n in _re.compile(p["extract"]).groupindex if n != "payload"]
        g.w(f"xm, xerr = parse_regex(itext, {vrl.regex(p['extract'])})")
        g.open("if xerr != null")
        g.w('perr = "input did not match parse.extract"')
        g.mid("else")
        g.w('itext = string(get(xm, ["payload"]) ?? "") ?? ""')
        for grp in xgroups:
            g.w(f'xv = get(xm, [{vrl.string(grp)}]) ?? null')
            g.open("if xv != null")
            g.w(f'{vrl.key("xsrc", grp)} = xv')
            g.close()
        g.close()
    if kind == "kv":
        o = p.get("kv") or {}
        g.w(f"kvo, perr = parse_key_value(itext, key_value_delimiter: {vrl.string(o.get('value_delimiter', '='))}, "
            f"field_delimiter: {vrl.string(o.get('field_delimiter', ' '))})")
        g.w("src = kvo")
    elif kind == "json":
        g.w("jv = null")
        g.open("if exists(pre.json)")
        g.w("jv = pre.json")
        g.mid("else")
        g.w("jv, perr = parse_json(itext)")
        g.close()
        g.w("src = object(jv) ?? {}")
        g.open("if perr == null && !is_object(jv)")
        g.w('perr = "payload is not a JSON object"')
        g.close()
        if (p.get("json") or {}).get("flatten", True):
            g.w("src = flatten(src)")
    elif kind == "cef":
        g.w("src = object(pre.cef) ?? {}")
        g.open("if !exists(pre.cef)")
        g.w('perr = "no CEF layer"')
        g.close()
    elif kind == "leef":
        g.w("lf = object(pre.leef) ?? {}")
        g.w("src = object(lf.attributes) ?? {}")
        g.open("if !exists(pre.leef)")
        g.w('perr = "no LEEF layer"')
        g.close()
        for h in ("version", "vendor", "product", "product_version", "event_id"):
            g.open(f"if exists(lf.{h})")
            g.w(f'{vrl.key("src", "leef." + h)} = lf.{h}')
            g.close()
    elif kind == "csv":
        o = p["csv"]
        g.w(f"cols, perr = parse_csv(itext, delimiter: {vrl.string(o.get('delimiter', ','))})")
        g.w("ci = 0")
        g.w("nc = length(cols)")
        # An object of unknown shape: `set()` keeps the static type of its
        # input, and an exact `{}` would make every later read typed `null`.
        g.w(f"src = {_OPAQUE_OBJ}")
        # Columns are assigned through a name table with dynamic keys: one
        # static `src."col" = ...` per column makes VRL's type checker track
        # an object with N optional keys and merge it at every branch, which
        # cost ~18 s of Vector start-up for PAN-OS's 130 columns.
        for seg in o["segments"]:
            w = seg.get("when")
            if w:
                sv = f'(to_string({vrl.key("src", w["column"])}) ?? "")'
                cond = f"{sv} == {vrl.string(w['equals'])}" if "equals" in w else f"includes({vrl.literal(w['in'])}, {sv})"
                g.open(f"if {cond}")
            g.w(f"names = {vrl.literal(list(seg['columns']))}")
            g.w("for_each(names) -> |k, n| { if ci + k < nc { src = set(src, [n], get(cols, [ci + k]) ?? null) ?? src } }")
            g.w(f"ci = ci + {len(seg['columns'])}")
            if w:
                g.close()
        g.w("# columns beyond the declared layout are kept as _extra_<index>")
        g.open("if ci < nc")
        g.w("extra = slice(cols, ci) ?? []")
        g.w('for_each(extra) -> |j, v| { src = set(src, ["_extra_" + to_string(ci + j)], v) ?? src }')
        g.close()
    elif kind == "regex":
        import re as _re

        g.w(f"rm, perr = parse_regex(itext, {vrl.regex(p['regex']['pattern'])})")
        # dynamic keys (see the csv branch): one static write per group made
        # VRL type checking quadratic in the number of groups
        g.w(f"src = {_OPAQUE_OBJ}")
        g.open("if perr == null")
        g.w("for_each(rm) -> |k, gv| { if gv != null { src = set(src, [k], gv) ?? src } }")
        g.close()
    else:  # pragma: no cover - schema prevents this
        raise CompileError(f"unknown parse kind {kind}")
    if p.get("extract"):
        g.w("src = merge(src, xsrc)")
    if p.get("include_syslog"):
        g.w("sy = object(pre.syslog) ?? {}")
        for f in ("hostname", "appname", "procid", "msgid", "facility", "severity", "version"):
            g.open(f"if exists(sy.{f})")
            g.w(f'{vrl.key("src", "syslog." + f)} = sy.{f}')
            g.close()
        g.open("if exists(pre.syslog_ts_raw)")
        g.w(f'{vrl.key("src", "syslog.timestamp_raw")} = pre.syslog_ts_raw')
        g.close()


# ------------------------------------------------------------- conversions
def _emit_time_conv(g: _Gen, value_expr: str, fmt: str, tz: str, *, offset_expr: str | None, year_infer: bool,
                    value_is_string: bool = False) -> None:
    """Emit code that sets `tms` (int epoch ms) and `terr` (null or code) from `tvs`."""
    g.w("tms = 0")
    g.w("terr = null")
    g.w('torig = ""')
    if value_is_string:  # already a string expression: to_string would be infallible (E104)
        g.w(f"tvs = {value_expr}")
        g.w("te = null")
    else:
        g.w(f"tvs, te = to_string({value_expr})")
    g.w("torig = tvs")
    g.open("if te != null")
    g.w('terr = "not_a_string"')
    g.mid('else if tvs == ""')
    g.w('terr = "empty"')
    g.mid("else")
    if fmt.startswith("epoch"):
        g.open(r"if match(tvs, r'^\d{1,19}$')")
        g.w("ti, ie = to_int(tvs)")
        g.w("n = length(tvs)")
        g.open("if ie != null")
        g.w('terr = "invalid_epoch"')
        if fmt == "epoch_auto":
            g.mid("else if n <= 11")
            g.w("tms = ti * 1000")
            g.mid("else if n <= 14")
            g.w("tms = ti")
            g.mid("else")
            g.w("cut = 3")
            g.open("if n >= 18")
            g.w("cut = 6")
            g.close()
            g.w("tsl, tse = slice(tvs, 0, n - cut)")
            g.w("tms, tie = to_int(tsl)")
            g.open("if tse != null || tie != null")
            g.w('terr = "invalid_epoch"')
            g.close()
        else:
            g.mid("else")
            if fmt == "epoch_s":
                g.w("tms = ti * 1000")
            elif fmt == "epoch_ms":
                g.w("tms = ti")
            else:
                cut = 3 if fmt == "epoch_us" else 6
                g.w(f"tsl, tse = slice(tvs, 0, n - {cut})")
                g.w("tms, tie = to_int(tsl)")
                g.open("if tse != null || tie != null || n <= " + str(cut))
                g.w('terr = "invalid_epoch"')
                g.close()
        g.close()
        g.mid(r"else if match(tvs, r'^\d{1,11}\.\d+$')")
        if fmt in ("epoch_auto", "epoch_s"):
            g.w('parts = split(tvs, ".")')
            g.w("sec, se = to_int(get(parts, [0]) ?? \"\")")
            g.w('fr = (string(get(parts, [1]) ?? "") ?? "") + "000"')
            g.w("f3, fe = slice(fr, 0, 3)")
            g.w("fi, fie = to_int(f3)")
            g.open("if se != null || fe != null || fie != null")
            g.w('terr = "invalid_epoch"')
            g.mid("else")
            g.w("tms = sec * 1000 + fi")
            g.close()
        else:
            g.w('terr = "invalid_epoch"')
        g.mid("else")
        g.w('terr = "invalid_epoch"')
        g.close()
    else:
        if fmt == "rfc3339":
            g.w('pt, pe = parse_timestamp(tvs, format: "%+")')
        else:
            text = "tvs"
            f = fmt
            if offset_expr:
                g.w(f"offv = to_string({offset_expr}) ?? \"\"")
                g.w('torig = tvs + " " + offv')
                text = 'tvs + " " + offv'
                f = f + " %z"
            if year_infer:
                # The format has no year: use the receipt year. A December event
                # received in early January would land in the future, so it is
                # re-parsed with the previous year.
                f = "%Y " + f
                g.w('iyr = "1970"')
                g.w('ity, itye = from_unix_timestamp(int(.ulpf.ingest.time_ms) ?? 0, unit: "milliseconds")')
                g.open("if itye == null")
                g.w('iyr = format_timestamp(ity, format: "%Y", timezone: "UTC") ?? "1970"')
                g.close()
                g.w(f'pt, pe = parse_timestamp(iyr + " " + {text}, format: {vrl.string(f)}, timezone: {vrl.string(tz)})')
                g.open('if pe == null && to_unix_timestamp(pt, unit: "milliseconds") > (int(.ulpf.ingest.time_ms) ?? 0) + 172800000')
                g.w("pyr = to_int(iyr) ?? 1970")
                g.w(f'pt, pe = parse_timestamp(to_string(pyr - 1) + " " + {text}, format: {vrl.string(f)}, timezone: {vrl.string(tz)})')
                g.close()
            else:
                g.w(f"pt, pe = parse_timestamp({text}, format: {vrl.string(f)}, timezone: {vrl.string(tz)})")
        g.open("if pe != null")
        g.w('terr = "invalid_time"')
        g.mid("else")
        g.w('tms = to_unix_timestamp(pt, unit: "milliseconds")')
        g.close()
    g.close()


def _emit_coerce(g: _Gen, typ: str, f: dict) -> None:
    """Emit code converting `v` into `cv`, setting `cerr` (null | "empty" | code)."""
    g.w("cv = null")
    g.w("cerr = null")
    if typ in ("string", "ip", "mac", "subnet"):
        g.w("cv, ce = to_string(v)")
        g.open("if ce != null")
        g.w('cerr = "not_a_string"')
        g.mid('else if cv == ""')
        g.w('cerr = "empty"')
        if typ == "ip":
            g.mid("else if !(is_ipv4(cv) || is_ipv6(cv))")
            g.w('cerr = "invalid_ip"')
        elif typ == "mac":
            g.mid(f"else if !match(cv, {vrl.regex(MAC_RE)})")
            g.w('cerr = "invalid_mac"')
        elif typ == "subnet":
            g.mid(f"else if !match(cv, {vrl.regex(SUBNET_RE)})")
            g.w('cerr = "invalid_subnet"')
        elif f.get("transform"):
            g.mid("else")
            fn = {"lower": "downcase", "upper": "upcase", "trim": "strip_whitespace"}[f["transform"]]
            g.w(f"cv = {fn}(cv)")
        g.close()
    elif typ in ("port", "int", "long", "float", "bool"):
        conv = {"port": "to_int", "int": "to_int", "long": "to_int", "float": "to_float", "bool": "to_bool"}[typ]
        accept = {"port": "is_string(v) || is_integer(v)", "int": "is_string(v) || is_integer(v)",
                  "long": "is_string(v) || is_integer(v)", "float": "is_string(v) || is_integer(v) || is_float(v)",
                  "bool": "is_string(v) || is_boolean(v)"}[typ]
        g.open('if v == ""')
        g.w('cerr = "empty"')
        g.mid(f"else if !({accept})")
        g.w(f'cerr = "not_{"a_boolean" if typ == "bool" else "a_number"}"')
        g.mid("else")
        g.w(f"cv, ce = {conv}(v)")
        g.open("if ce != null")
        g.w(f'cerr = "invalid_{typ}"')
        if typ == "port":
            g.mid("else if cv < 0 || cv > 65535")
            g.w('cerr = "port_out_of_range"')
        if f.get("scale") is not None:
            g.mid("else")
            scale = f["scale"]
            g.w(f"cv = cv * {int(scale) if typ != 'float' and float(scale).is_integer() else float(scale)}")
        g.close()
        g.close()
    elif typ == "timestamp":
        _emit_time_conv(g, "v", f["format"], f.get("timezone", "UTC"), offset_expr=None, year_infer=False)
        g.open("if terr != null")
        g.w("cerr = terr")
        g.mid("else")
        g.w("cv = tms")
        g.close()
    elif typ == "json":
        g.w("cv = v")
    else:  # pragma: no cover
        raise CompileError(f"unknown type {typ}")


def _written_paths(spec: Spec) -> set[str]:
    d = spec.data
    out = {f["to"] for f in (d.get("fields") or {}).values() if not f.get("unmapped")}
    for e in d.get("enums") or []:
        for tbl in list(e["map"].values()) + [e.get("default") or {}, e.get("missing") or {}]:
            out.update(tbl)
    out.update((d.get("set") or {}).keys())
    out.update(dv["to"] for dv in d.get("derive") or [])
    return out


def _object_paths(o: Ocsf, spec: Spec) -> list[tuple[str, dict]]:
    """Object attributes the spec writes into, deepest first, with their object definitions."""
    prefixes = set()
    for p in _written_paths(spec):
        parts = p.split(".")
        for i in range(1, len(parts)):
            prefixes.add(".".join(parts[:i]))
    out = []
    for op in sorted(prefixes, key=lambda s: (-s.count("."), s)):
        a = o.resolve(spec.class_name, op, spec.profiles)
        out.append((op, o.export["objects"][a.object_type]))
    return out


# ------------------------------------------------------------------ program
@dataclass
class _Ctx:
    spec: Spec
    o: Ocsf
    enum_attrs: set[str]   # OCSF paths of enum attributes written by this spec


def _sibling_path(o: Ocsf, spec: Spec, attr_path: str) -> tuple[str, dict[int, str]] | None:
    a = o.resolve(spec.class_name, attr_path, spec.profiles)
    if not a.enum or not a.sibling:
        return None
    parent = attr_path.rsplit(".", 1)[0] + "." if "." in attr_path else ""
    return parent + a.sibling, a.enum


def compile_spec(spec: Spec, o: Ocsf | None = None, iana: dict[int, str] | None = None) -> CompiledParser:
    o = o or default_ocsf()
    d = spec.data
    cdef = o.class_def(spec.class_name)
    g = _Gen()
    hdr = [
        "# GENERATED FILE - DO NOT EDIT (compiled by `ulpf spec compile`)",
        f"# spec: {spec.id} version {spec.version}",
        f"# spec sha256: {spec.sha256}",
        f"# source: {spec.path.relative_to(paths.HOME) if spec.path.is_relative_to(paths.HOME) else spec.path}",
        f"# compiler: ulpf {__version__} | OCSF {o.version} | class {spec.class_name} profiles {spec.profiles}",
    ]
    for h in hdr:
        g.w(h)
    g.w(".ulpf.parser = " + vrl.literal({"id": spec.id, "version": spec.version, "spec_sha256": spec.sha256,
                                       "compiler": f"ulpf {__version__}"}))
    _emit_parse(g, spec)

    g.open("if perr != null")
    g.w('.ulpf.status = "failed"')
    g.w('.ulpf.reasons = ["parse_error"]')
    g.w('.ulpf.errors = [{"code": "parse_error", "parser": ' + vrl.string(spec.id) + ', "message": perr}]')
    g.mid("else")

    markers = (d.get("unmapped") or {}).get("empty_markers") or []
    if markers:
        # format-specific "no value" markers (e.g. "-") are treated as empty
        g.w(f'src = map_values(src) -> |mv| {{ if includes({vrl.literal(markers)}, mv) {{ "" }} else {{ mv }} }}')

    # PII pseudonymisation happens before mapping so neither the mapped value
    # nor an unmapped copy can carry the clear text (the raw archive keeps it).
    pii = d.get("pii") or []
    if pii:
        g.w('pk = get_env_var("ULPF_PII_KEY") ?? ""')
        for pi in pii:
            k = vrl.key("src", pi["field"])
            g.w(f'pv = to_string(get(src, [{vrl.string(pi["field"])}]) ?? "") ?? ""')
            # only non-empty values are pseudonymised; empty stays empty (counted as empty)
            g.open('if pv != ""')
            g.open('if pk != ""')
            g.w(f'{k} = "hmac-sha256:" + encode_base16(hmac(pv, pk, algorithm: "SHA-256"))')
            g.mid("else")
            g.w(f'{k} = "[pii-redacted: ULPF_PII_KEY not set]"')
            g.close()
            g.close()

    g.w("um = src")
    g.w(f"errs = {_OPAQUE_ARR}")
    g.w(f"lin = {_OPAQUE_OBJ}")
    g.w(f"used = {_OPAQUE_OBJ}")
    g.w("ntotal = length(src)")
    g.w(f".class_uid = {cdef['uid']}")
    g.w(f".class_name = {vrl.string(cdef['caption'])}")
    g.w(f".category_uid = {cdef['category_uid']}")
    cat_enum = (cdef["attributes"].get("category_uid") or {}).get("enum") or {}
    cat_caption = (cat_enum.get(str(cdef["category_uid"])) or {}).get("caption") or o.category_caption(cdef["category_uid"])
    if not cat_caption:
        raise CompileError(f"no caption for category_uid {cdef['category_uid']} of {spec.class_name}")
    g.w(f".category_name = {vrl.string(cat_caption)}")
    md = {"version": o.version, "product": {"vendor_name": d["vendor"], "name": d["product"]}}
    if spec.profiles:
        md["profiles"] = spec.profiles
    g.w(".metadata = " + vrl.literal(md))

    enum_attrs: set[str] = set()

    # ---- set (constants)
    for dest, val in (d.get("set") or {}).items():
        g.w(f"{vrl.ocsf_path('', dest)} = {vrl.literal(val)}")
        g.w(_set("lin", vrl.string(dest), '"const"'))
        a = o.resolve(spec.class_name, dest, spec.profiles)
        if a.enum:
            enum_attrs.add(dest)

    # ---- time
    times = d.get("time") or []
    g.w("tdone = false")
    # errors of time candidates count only if NO candidate succeeds
    g.w(f"terrs = {_OPAQUE_ARR}")
    for t in times:
        srcs = [t["field"]] if "field" in t else t["fields"]
        cond = " && ".join(f"exists({vrl.key('src', s)})" for s in srcs)
        if t.get("offset_field"):
            cond += f" && exists({vrl.key('src', t['offset_field'])})"
        g.open(f"if !tdone && {cond}")
        if len(srcs) == 1:
            value_expr = vrl.key("src", srcs[0])
        else:
            value_expr = " + \" \" + ".join(f'(to_string({vrl.key("src", s)}) ?? "")' for s in srcs)
        _emit_time_conv(g, value_expr, t["format"], t.get("timezone", "UTC"),
                        offset_expr=vrl.key("src", t["offset_field"]) if t.get("offset_field") else None,
                        year_infer=t.get("year") == "infer", value_is_string=len(srcs) > 1)
        consumed = srcs + ([t["offset_field"]] if t.get("offset_field") else [])
        g.open("if terr == null")
        g.w(".time = tms")
        g.w(".metadata.original_time = torig")
        for s in consumed:
            g.w(f"del({vrl.key('um', s)})")
            g.w(_set("used", vrl.string(s), "true"))
        g.w(_set("lin", '"time"', vrl.string("+".join(consumed))))
        has_zone = t["format"].startswith("epoch") or t["format"] == "rfc3339" or "%z" in t["format"] or "%Z" in t["format"] or t.get("offset_field")
        tinfo = {"source": "field", "field": "+".join(consumed), "format": t["format"],
                 "assumed_timezone": None if has_zone else t.get("timezone", "UTC"),
                 "year_inferred": t.get("year") == "infer"}
        g.w(".ulpf.time = " + vrl.literal(tinfo))
        g.w(".ulpf.time.skew_ms = (int(.ulpf.ingest.time_ms) ?? 0) - tms")
        g.w("tdone = true")
        g.mid("else")
        g.w("terrs = push(terrs, " + "{" + f'"field": {vrl.string("+".join(srcs))}, "to": "time", "code": terr, "value": tvs' + "})")
        g.close()
        g.close()
    g.open("if !tdone")
    g.w("errs = append(errs, terrs)")
    g.w(".time = .ulpf.ingest.time_ms")
    g.w(_set("lin", '"time"', '"ingest"'))
    g.w('.ulpf.time = {"source": "ingest", "note": "no usable source time; time = receipt time"}')
    g.close()

    # ---- fields
    for src_name, f in (d.get("fields") or {}).items():
        if f.get("unmapped"):
            continue  # stays in `unmapped` by construction
        k = vrl.key("src", src_name)
        dest = f["to"]
        g.open(f"if exists({k})")
        g.w(f"v = {k}")
        g.w(f"del({vrl.key('um', src_name)})")
        _emit_coerce(g, f["type"], f)
        da = o.resolve(spec.class_name, dest, spec.profiles)
        if da.is_string_enum:
            # closed OCSF string enumeration (e.g. http_method): values outside it would make the event invalid
            g.open(f"if cerr == null && !includes({vrl.literal(sorted(da.enum))}, cv)")
            g.w('cerr = "not_in_ocsf_enumeration"')
            g.close()
        g.open("if cerr == null")
        g.w(f"{vrl.ocsf_path('', dest)} = cv")
        g.w(_set("lin", vrl.string(dest), vrl.string(src_name)))
        g.w(_set("used", vrl.string(src_name), "true"))
        g.mid('else if cerr == "empty"')
        g.w(_set("um", vrl.string(src_name), "v"))
        g.mid("else")
        g.w(_set("um", vrl.string(src_name), "v"))
        g.w("errs = push(errs, {" + f'"field": {vrl.string(src_name)}, "to": {vrl.string(dest)}, "code": cerr, "value": v' + "})")
        g.close()
        g.close()

    # ---- enums
    for e in d.get("enums") or []:
        k = vrl.key("src", e["source"])
        ci = e.get("case_insensitive", True)
        targets = sorted({t for tbl in e["map"].values() for t in tbl} | set(e.get("default", {}))
                         | set(e.get("missing", {})) | set(e.get("otherwise", {})))
        contains = e.get("match", "exact") == "contains"
        for t in targets:
            enum_attrs.add(t)
        g.open(f"if exists({k})")
        g.w(f"v = {k}")
        g.w(f"del({vrl.key('um', e['source'])})")
        g.w("ev, ee = to_string(v)")
        g.open("if ee != null")
        g.w(_set("um", vrl.string(e['source']), "v"))
        g.w("errs = push(errs, {" + f'"field": {vrl.string(e["source"])}, "code": "not_a_string", "value": v' + "})")
        g.mid("else")
        g.w("ek = downcase(ev)" if ci else "ek = ev")
        first = True
        for val, tbl in e["map"].items():
            key_lit = vrl.string(val.lower() if ci else val)
            cond = f"contains(ek, {key_lit})" if contains else f"ek == {key_lit}"
            if first:
                g.open(f"if {cond}")
                first = False
            else:
                g.mid(f"else if {cond}")
            for attr, num in tbl.items():
                g.w(f"{vrl.ocsf_path('', attr)} = {int(num)}")
        g.mid("else")
        if "otherwise" in e:
            for attr, num in e["otherwise"].items():
                g.w(f"{vrl.ocsf_path('', attr)} = {int(num)}")
        else:
            dflt = e.get("default") or {}
            for attr, num in dflt.items():
                g.w(f"{vrl.ocsf_path('', attr)} = {int(num)}")
                if num == 99:
                    sib = _sibling_path(o, spec, attr)
                    if sib:
                        g.w(f"{vrl.ocsf_path('', sib[0])} = ev")
            g.w("errs = push(errs, {" + f'"field": {vrl.string(e["source"])}, "code": "enum_value_not_in_table", "value": ev' + "})")
        g.close()
        for t in targets:
            g.w(_set("lin", vrl.string(t), vrl.string('enum:' + e['source'])))
        g.w(_set("used", vrl.string(e['source']), "true"))
        g.close()
        if e.get("missing"):
            g.mid("else")
            for attr, num in e["missing"].items():
                g.w(f"{vrl.ocsf_path('', attr)} = {int(num)}")
                g.w(_set("lin", vrl.string(attr), vrl.string('enum_missing:' + e['source'])))
        g.close()

    # ---- derive
    iana = iana if iana is not None else load_iana_protocols()
    for dv in d.get("derive") or []:
        to = vrl.ocsf_path("", dv["to"])
        using = dv["using"]
        if using == "iana_protocol_name":
            frm = vrl.ocsf_path("", dv["from"])
            table = {str(k): v for k, v in sorted(iana.items())}
            g.open(f"if exists({frm}) && !exists({to})")
            g.w(f"pnm = get({vrl.literal(table)}, [to_string({_rd(dv['from'])}) ?? \"\"]) ?? null")
            g.open("if pnm != null")
            g.w(f"{to} = pnm")
            g.w(_set("lin", vrl.string(dv['to']), vrl.string('derived:iana_protocol_name(' + dv['from'] + ')')))
            g.close()
            g.close()
        elif using == "iana_protocol_num":
            frm = vrl.ocsf_path("", dv["from"])
            table = {v: k for k, v in sorted(iana.items())}
            g.open(f"if exists({frm}) && !exists({to})")
            g.w(f"pnu = get({vrl.literal(table)}, [downcase(to_string({_rd(dv['from'])}) ?? \"\")]) ?? null")
            g.open("if pnu != null")
            g.w(f"{to} = pnu")
            g.w(_set("lin", vrl.string(dv['to']), vrl.string('derived:iana_protocol_num(' + dv['from'] + ')')))
            g.close()
            g.close()
        elif using == "community_id":
            g.open("if exists(.src_endpoint.ip) && exists(.dst_endpoint.ip) && exists(.connection_info.protocol_num)")
            g.w(f'csip = to_string({_rd("src_endpoint.ip")}) ?? ""')
            g.w(f'cdip = to_string({_rd("dst_endpoint.ip")}) ?? ""')
            g.w(f"cpr = to_int({_rd('connection_info.protocol_num')}) ?? 0")
            g.w("cid = null")
            g.open("if exists(.src_endpoint.port) && exists(.dst_endpoint.port)")
            g.w(f"csp = to_int({_rd('src_endpoint.port')}) ?? 0")
            g.w(f"cdp = to_int({_rd('dst_endpoint.port')}) ?? 0")
            g.w("cid = community_id(source_ip: csip, destination_ip: cdip, protocol: cpr, source_port: csp, destination_port: cdp) ?? null")
            g.mid("else if !includes([6, 17, 132], cpr)")
            # Community ID needs ports for TCP/UDP/SCTP; only port-less
            # protocols (e.g. ICMP) are hashed without them.
            g.w("cid = community_id(source_ip: csip, destination_ip: cdip, protocol: cpr) ?? null")
            g.close()
            g.open('if cid != null && cid != ""')
            g.w(f"{to} = cid")
            g.w(_set("lin", vrl.string(dv["to"]), '"derived:community_id"'))
            g.close()
            g.close()
        elif using == "tz_offset_minutes":
            k = vrl.key("src", dv["source"])
            g.open(f"if exists({k})")
            g.w(f"tzv = to_string({k}) ?? \"\"")
            g.w(f"tzm = parse_regex(tzv, {vrl.regex(r'^(?P<s>[+-])(?P<h>[0-9]{2}):?(?P<m>[0-9]{2})$')}) ?? null")
            g.open("if tzm != null")
            g.w('tzh = to_int(tzm.h) ?? 0')
            g.w('tzmi = to_int(tzm.m) ?? 0')
            g.w("tzo = tzh * 60 + tzmi")
            g.open('if tzm.s == "-"')
            g.w("tzo = 0 - tzo")
            g.close()
            g.w(f"{to} = tzo")
            g.w(f"del({vrl.key('um', dv['source'])})")
            g.w(_set("used", vrl.string(dv['source']), "true"))
            g.w(_set("lin", vrl.string(dv['to']), vrl.string(dv['source'])))
            g.mid("else")
            g.w("errs = push(errs, {" + f'"field": {vrl.string(dv["source"])}, "to": {vrl.string(dv["to"])}, "code": "invalid_tz_offset", "value": tzv' + "})")
            g.close()
            g.close()
        elif using == "copy":
            frm = vrl.ocsf_path("", dv["from"])
            g.open(f"if exists({frm})")
            g.w(f"{to} = {frm}")
            g.w(_set("lin", vrl.string(dv['to']), vrl.string('copy:' + dv['from'])))
            g.close()

    # ---- required defaults
    for attr, a in cdef["attributes"].items():
        if a.get("requirement") == "required" and not a.get("profiles") and attr in ("activity_id", "severity_id"):
            g.open(f"if !exists(.{attr})")
            g.w(f".{attr} = 0")
            g.w(_set("lin", vrl.string(attr), '"default:unknown"'))
            g.close()
            enum_attrs.add(attr)

    # ---- required enum attributes of objects the spec writes (schema-derived),
    # e.g. network_connection_info.direction_id: 0 (Unknown) when not mapped.
    applied = set(spec.profiles)
    objects = _object_paths(o, spec)
    for op, odef in objects:
        for an, ad in odef["attributes"].items():
            gated = set(ad.get("profiles") or ())
            if ad.get("requirement") != "required" or "enum" not in ad or (gated and not gated & applied):
                continue
            full = f"{op}.{an}"
            g.open(f"if exists({vrl.ocsf_path('', op)}) && !exists({vrl.ocsf_path('', full)})")
            g.w(f"{vrl.ocsf_path('', full)} = 0")
            g.w(_set("lin", vrl.string(full), '"default:unknown"'))
            g.close()
            enum_attrs.add(full)

    # ---- captions for every enum attribute this spec can write
    for attr in sorted(enum_attrs):
        sib = _sibling_path(o, spec, attr)
        if not sib:
            continue
        sp, table = sib
        spath = vrl.ocsf_path("", sp)
        caps = {str(k): v for k, v in sorted(table.items())}
        g.w(f"cvx = {_rd(attr)}")
        g.open("if cvx != null")
        g.open("if cvx == 99")
        g.open(f"if !exists({spath})")
        g.w(f'{spath} = "Other"')
        g.close()
        g.mid("else")
        g.w(f'{spath} = get({vrl.literal(caps)}, [to_string(cvx) ?? ""]) ?? "Unknown"')
        g.close()
        g.close()
    act = o.resolve(spec.class_name, "activity_id", spec.profiles)
    tcap = {str(cdef["uid"] * 100 + k): f"{cdef['caption']}: {v}" for k, v in sorted((act.enum or {}).items())}
    g.w(f"act = to_int({_rd('activity_id')}) ?? 0")
    g.w(f".type_uid = {cdef['uid'] * 100} + act")
    g.w(f".type_name = get({vrl.literal(tcap)}, [to_string({cdef['uid'] * 100} + act)]) ?? {vrl.string(cdef['caption'] + ': Unknown')}")

    # ---- unmapped + coverage
    keep_empty = (d.get("unmapped") or {}).get("empty_values", "count") == "keep"
    if keep_empty:
        g.w("nonempty = um")
    else:
        g.w('nonempty = filter(um) -> |_k, v| { v != "" && v != null }')
    g.w("nmap = length(used)")
    g.w("nempty = length(um) - length(nonempty)")
    g.w("nun = length(nonempty)")
    g.w('empties = keys(filter(um) -> |_k, v| { v == "" || v == null })')
    g.open("if nun > 0")
    g.w(".unmapped = nonempty")
    g.close()
    g.open("if nmap + nun + nempty != ntotal")
    g.w('errs = push(errs, {"code": "completeness_violation", "fields": ntotal, "mapped": nmap, "unmapped": nun, "empty": nempty})')
    g.close()
    # ---- OCSF object constraints (schema-derived). An object left incomplete
    # by a failed coercion (e.g. src_endpoint with only a port after an invalid
    # IP) is moved intact to unmapped["ulpf.incomplete.<path>"]; accounting is
    # unchanged because its source fields stay recorded in lineage.
    for op, odef in objects:
        checks = []
        for an, ad in odef["attributes"].items():
            gated = set(ad.get("profiles") or ())
            if ad.get("requirement") == "required" and "enum" not in ad and not (gated and not gated & applied):
                checks.append(f"exists({vrl.ocsf_path('', op + '.' + an)})")
        for kind, names in (odef.get("constraints") or {}).items():
            if kind == "at_least_one" and names:
                checks.append("(" + " || ".join(f"exists({vrl.ocsf_path('', op + '.' + n)})" for n in names) + ")")
        if not checks:
            continue
        opath = vrl.ocsf_path("", op)
        prefix = vrl.string(op + ".")
        g.open(f"if exists({opath}) && !({' && '.join(checks)})")
        # Does the incomplete object carry any source-derived value? An object
        # made only of spec constants (e.g. device.type_id with no device
        # identity in the log) carries no information and is simply dropped.
        g.w(f'srcd = filter(lin) -> |lk, lv| {{ starts_with(lk, {prefix}) && !includes(["const", "default:unknown"], lv) }}')
        g.open("if length(srcd) > 0")
        g.w(f'{vrl.key(".unmapped", "ulpf.incomplete." + op)} = {opath}')
        g.w("errs = push(errs, {" + f'"code": "ocsf_constraint", "object": {vrl.string(op)}' + "})")
        g.mid("else")
        g.w(f"lin = filter(lin) -> |lk, _lv| {{ !starts_with(lk, {prefix}) }}")
        g.close()
        g.w(f"del({opath})")
        g.close()
    class_fail = []
    for kind, names in (cdef.get("constraints") or {}).items():
        if kind == "at_least_one" and names:
            class_fail.append("(" + " || ".join(f"exists({vrl.ocsf_path('', n)})" for n in names) + ")")
    g.w("class_ok = true")
    if class_fail:
        g.open(f"if !({' && '.join(class_fail)})")
        g.w("class_ok = false")
        g.close()

    g.open("if !class_ok")
    # Not representable as this class: keep only the envelope and let
    # finalize emit a Base Event that preserves every generic layer.
    g.w('. = {"_raw": ._raw, "_pre": ._pre, "timestamp": .timestamp, "ulpf": .ulpf}')
    g.w('.ulpf.status = "failed"')
    g.w(f'.ulpf.reasons = ["ocsf_class_constraint"]')
    g.w(".ulpf.errors = push(errs, {" + f'"code": "ocsf_class_constraint", "class": {vrl.string(spec.class_name)}' + "})")
    if d.get("generic"):
        # format-level catch-all: structured, but no vendor semantics -> stays
        # in the onboarding queue
        g.mid("else")
        g.w('.ulpf.status = "fallback"')
        g.w('.ulpf.reasons = ["generic_parser"]')
        g.open("if length(errs) > 0")
        g.w(".ulpf.errors = errs")
        g.close()
        g.close()
    else:
        g.mid("else if length(errs) > 0")
        g.w('.ulpf.status = "partial"')
        g.w('.ulpf.reasons = ["field_errors"]')
        g.w(".ulpf.errors = errs")
        g.mid("else")
        g.w('.ulpf.status = "parsed"')
        g.w(".ulpf.reasons = []")
        g.close()
    g.open("if class_ok")
    g.w(".ulpf.lineage = lin")
    g.w('.ulpf.coverage = {"fields": ntotal, "mapped": nmap, "unmapped": nun, "empty": nempty}')
    g.open("if nempty > 0")
    g.w(".ulpf.coverage.empty_fields = empties")
    g.close()
    g.close()
    g.close()  # perr else
    return CompiledParser(spec_id=spec.id, version=spec.version, spec_sha256=spec.sha256,
                          transform_id=spec.transform_id, match_condition=compile_match(spec),
                          priority=spec.priority, vrl=g.text())


# ---------------------------------------------------------------- top level
def compile_specs(spec_paths: list[Path], o: Ocsf | None = None) -> tuple[Pipeline, dict]:
    """Lint and compile; raises CompileError if any spec has lint errors."""
    o = o or default_ocsf()
    results = lint_all(spec_paths, o)
    problems = {str(p): [str(i) for i in iss if i.level == "error"] for p, (_, iss) in results.items()}
    problems = {k: v for k, v in problems.items() if v}
    if problems:
        raise CompileError("refusing to compile specs with lint errors:\n" + json.dumps(problems, indent=1))
    iana = load_iana_protocols()
    parsers = [compile_spec(spec, o, iana) for p, (spec, _) in results.items() if spec is not None]
    return Pipeline(parsers), {str(p): [str(i) for i in iss] for p, (_, iss) in results.items()}
