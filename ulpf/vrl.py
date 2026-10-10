"""Safe construction of VRL source text.

Every value that originates from a spec (literals, field names, regexes) goes
through these helpers. VRL string literals interpolate ``{{ ... }}`` templates
(verified on Vector 0.58: ``"{{ a }}"`` raises E701 "undefined variable"), so
braces are escaped; quotes, backslashes and all non-printable characters are
escaped as well. Regexes use raw literals ``r'...'`` which cannot contain a
single quote (the linter rejects such patterns).
"""
from __future__ import annotations

import re

_OCSF_SEG = re.compile(r"^[a-z_][a-z0-9_]*$")


def string(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch in "{}":
            out.append("\\" + ch)
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif 0x20 <= o < 0x7F:
            out.append(ch)
        else:
            out.append(f"\\u{{{o:X}}}")
    return '"' + "".join(out) + '"'


def regex(pattern: str) -> str:
    if "'" in pattern:
        raise ValueError("regex literal may not contain a single quote")
    return "r'" + pattern + "'"


def literal(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return string(v)
    if v is None:
        return "null"
    if isinstance(v, list):
        return "[" + ", ".join(literal(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join(f"{string(str(k))}: {literal(x)}" for k, x in v.items()) + "}"
    raise TypeError(f"no VRL literal for {type(v).__name__}")


def ocsf_path(root: str, dotted: str) -> str:
    """`.src_endpoint.ip` style path; OCSF segments are plain identifiers."""
    segs = dotted.split(".")
    for s in segs:
        if not _OCSF_SEG.match(s):
            raise ValueError(f"invalid OCSF path segment {s!r}")
    return root + "".join("." + s for s in segs)


def key(root: str, name: str) -> str:
    """Quoted single-segment path for an arbitrary source field name: s."id.orig_h"."""
    if any(c in name for c in '"\\{}') or not name.isprintable():
        raise ValueError(f"source field name {name!r} cannot be used in a VRL path")
    return f'{root}."{name}"'


def layer_path(dotted: str) -> str:
    """Path into ._pre for match conditions: json.alert.signature -> ._pre.json."alert"."signature"."""
    first, *rest = dotted.split(".")
    if not _OCSF_SEG.match(first):
        raise ValueError(f"invalid layer {first!r}")
    p = "._pre." + first
    for seg in rest:
        p = key(p, seg)
    return p
