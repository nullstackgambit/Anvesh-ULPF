"""Validation of the ULPF envelope and field-level provenance queries."""
from __future__ import annotations

import base64
import hashlib
import json
from functools import lru_cache
from typing import Any

import jsonschema

from . import paths


@lru_cache(maxsize=1)
def _validator() -> jsonschema.Draft202012Validator:
    schema = json.loads(paths.PROVENANCE_SCHEMA.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def validate_envelope(doc: dict) -> list[str]:
    """Schema + cross-field rules between the envelope and the OCSF part."""
    u = doc.get("ulpf")
    if not isinstance(u, dict):
        return ["missing ulpf envelope"]
    out = [f"ulpf.{'.'.join(str(p) for p in e.absolute_path)}: {e.message}"
           for e in _validator().iter_errors(u)]
    if out:
        return out
    md = doc.get("metadata") or {}
    if md.get("uid") != u["event_uid"]:
        out.append("metadata.uid differs from ulpf.event_uid")
    if (doc.get("raw_data_hash") or {}).get("value") != u["raw"]["sha256"]:
        out.append("raw_data_hash.value differs from ulpf.raw.sha256")
    if doc.get("raw_data_size") != u["raw"]["len"]:
        out.append("raw_data_size differs from ulpf.raw.len")
    if not u["raw"]["utf8"]:
        if "b64" not in u["raw"]:
            out.append("raw bytes are not valid UTF-8 but ulpf.raw.b64 is missing")
        else:
            b = base64.b64decode(u["raw"]["b64"])
            if hashlib.sha256(b).hexdigest() != u["raw"]["sha256"]:
                out.append("ulpf.raw.b64 does not hash to ulpf.raw.sha256")
    st = u["status"]
    if st == "parsed" and u.get("errors"):
        out.append("status parsed but errors present")
    if st == "partial" and not u.get("errors"):
        out.append("status partial requires at least one error")
    if st in ("fallback", "failed") and not u.get("reasons"):
        out.append(f"status {st} requires a reason")
    if st in ("parsed", "partial") and "parser" not in u:
        out.append(f"status {st} requires ulpf.parser")
    cov = u.get("coverage")
    if cov and cov["mapped"] + cov["unmapped"] + cov["empty"] != cov["fields"]:
        out.append(f"coverage does not add up: {cov}")
    return out


def raw_bytes_of(doc: dict) -> bytes:
    """Exact raw bytes carried by a normalized document."""
    u = doc["ulpf"]
    if "b64" in u["raw"]:
        return base64.b64decode(u["raw"]["b64"])
    return (doc.get("raw_data") or "").encode("utf-8")


def explain(doc: dict, ocsf_path: str) -> dict[str, Any]:
    """Answer "where did this normalized value come from?" for one field."""
    u = doc.get("ulpf") or {}
    cur: Any = doc
    for part in ocsf_path.split("."):
        cur = cur.get(part) if isinstance(cur, dict) else None
    origin = (u.get("lineage") or {}).get(ocsf_path)
    out: dict[str, Any] = {
        "normalized_field": ocsf_path,
        "normalized_value": cur,
        "origin": origin,
        "parser": (u.get("parser") or {}).get("id"),
        "parser_version": (u.get("parser") or {}).get("version"),
        "spec_sha256": (u.get("parser") or {}).get("spec_sha256"),
        "event_uid": u.get("event_uid"),
        "raw_sha256": (u.get("raw") or {}).get("sha256"),
    }
    if origin and not origin.startswith(("const", "ingest", "default", "derived:", "copy:", "enum_missing:")):
        src = origin.split(":", 1)[1] if origin.startswith("enum:") else origin
        out["source_fields"] = src.split("+")
    return out
