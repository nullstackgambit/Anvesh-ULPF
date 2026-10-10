"""Offline OCSF schema registry and event validator.

Everything here reads the schema vendored under schema/ocsf/<version>/ by
tools/fetch_ocsf.py; nothing contacts the network.

Validation of a ULPF document has three layers:

1. **Official JSON Schema** (draft-07, ``additionalProperties: false``) that
   the OCSF server generated for the event's (class, profiles) combination.
   This catches invented attributes, wrong types and out-of-range enums.
2. **Semantic checks** derived *from the schema data*, not hard-coded:
   ``type_uid == class_uid*100 + activity_id``, category consistency, every
   ``*_id``/caption sibling pair, class ``constraints`` (``at_least_one``,
   ``just_one``) and ``metadata.version``.
3. The ULPF envelope (top-level ``ulpf`` key) against
   schema/provenance.schema.json -- see :mod:`ulpf.provenance`.

The OCSF layers run on the document *without* its ``ulpf`` key, because the
envelope is a ULPF extension and not an OCSF attribute.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from functools import cached_property, lru_cache
from pathlib import Path
from typing import Any, Iterable

import jsonschema

from . import paths

OTHER = 99  # OCSF convention: enum value 99 means "Other" (sibling holds the source value)


@dataclass(frozen=True)
class Attr:
    """A resolved OCSF attribute."""

    path: str
    name: str
    type: str                 # OCSF type, e.g. ip_t, port_t, object_t
    is_array: bool
    object_type: str | None   # for object_t
    requirement: str
    enum: dict[int, str] | None
    sibling: str | None
    profiles: tuple[str, ...]  # profiles that contribute this attribute (empty = always)

    @property
    def is_object(self) -> bool:
        return self.type == "object_t"

    @property
    def is_string_enum(self) -> bool:
        return bool(self.enum) and all(isinstance(k, str) for k in self.enum)


@dataclass
class Issue:
    path: str
    message: str
    layer: str  # jsonschema | semantic | envelope

    def __str__(self) -> str:
        return f"[{self.layer}] {self.path or '<root>'}: {self.message}"


@dataclass
class ValidationResult:
    issues: list[Issue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.issues


class Ocsf:
    def __init__(self, root: Path = paths.OCSF):
        self.root = Path(root)

    # ----------------------------------------------------------------- files
    @cached_property
    def manifest(self) -> dict:
        return json.loads((self.root / "MANIFEST.json").read_text())

    @cached_property
    def export(self) -> dict:
        return json.loads((self.root / "export_v2_schema.json").read_text())

    @property
    def version(self) -> str:
        return self.export["version"]

    def verify_files(self) -> list[str]:
        """Return problems if any vendored file differs from MANIFEST.json."""
        problems = []
        for rel, meta in self.manifest["files"].items():
            p = self.root / rel
            if not p.exists():
                problems.append(f"missing {rel}")
            elif hashlib.sha256(p.read_bytes()).hexdigest() != meta["sha256"]:
                problems.append(f"sha256 mismatch {rel}")
        return problems

    # --------------------------------------------------------------- lookups
    @cached_property
    def _class_by_uid(self) -> dict[int, str]:
        return {c["uid"]: name for name, c in self.export["classes"].items()}

    def class_def(self, name: str) -> dict:
        try:
            return self.export["classes"][name]
        except KeyError:
            raise KeyError(f"unknown OCSF class {name!r} in OCSF {self.version}") from None

    def class_name_for_uid(self, uid: int) -> str | None:
        return self._class_by_uid.get(uid)

    def category_caption(self, category_uid: int) -> str | None:
        for c in self.export["categories"]["attributes"].values():
            if c["uid"] == category_uid:
                return c["caption"]
        return None

    def type_info(self, type_name: str) -> dict:
        return self.export["dictionary"]["types"]["attributes"].get(type_name, {})

    def base_type(self, type_name: str) -> str:
        """Map a derived OCSF type (e.g. port_t) to its base (integer_t)."""
        return self.type_info(type_name).get("type", type_name)

    def class_profiles(self, class_name: str) -> list[str]:
        return list(self.class_def(class_name).get("profiles") or [])

    @staticmethod
    def _attr(path: str, name: str, a: dict) -> Attr:
        enum = None
        if "enum" in a:
            # Most OCSF enums are integer ids; a few (http_request.http_method,
            # osint.tlp, cvss.depth) are closed sets of strings.
            enum = {(int(k) if k.lstrip("-").isdigit() else k): v.get("caption", "") for k, v in a["enum"].items()}
        return Attr(
            path=path,
            name=name,
            type=a.get("type", ""),
            is_array=bool(a.get("is_array")),
            object_type=a.get("object_type"),
            requirement=a.get("requirement", "optional"),
            enum=enum,
            sibling=a.get("sibling"),
            profiles=tuple(a.get("profiles") or ()),
        )

    def resolve(self, class_name: str, dotted: str, profiles: Iterable[str] = ()) -> Attr:
        """Resolve ``a.b.c`` against a class, honouring profiles.

        Raises KeyError with a human-readable reason when the path does not
        exist in this OCSF version, traverses an array, or needs a profile
        that is not applied.
        """
        applied = set(profiles)
        attrs = self.class_def(class_name)["attributes"]
        parts = dotted.split(".")
        walked: list[str] = []
        for i, part in enumerate(parts):
            walked.append(part)
            a = attrs.get(part)
            where = ".".join(walked)
            if a is None:
                raise KeyError(f"{where!r} is not an attribute of {class_name} in OCSF {self.version}")
            needs = set(a.get("profiles") or ())
            if needs and not (needs & applied):
                raise KeyError(f"{where!r} requires profile {sorted(needs)} (applied: {sorted(applied) or 'none'})")
            attr = self._attr(where, part, a)
            if i == len(parts) - 1:
                return attr
            if not attr.is_object:
                raise KeyError(f"{where!r} is {attr.type}, cannot descend into {parts[i + 1]!r}")
            if attr.is_array:
                raise KeyError(f"{where!r} is an array of objects; mapping into array elements is not supported")
            obj = self.export["objects"].get(attr.object_type or "")
            if obj is None:
                raise KeyError(f"object {attr.object_type!r} missing from export")
            attrs = obj["attributes"]
        raise KeyError(dotted)  # unreachable

    # ------------------------------------------------------- JSON Schema layer
    def schema_file(self, class_name: str, profiles: Iterable[str]) -> Path | None:
        want = sorted(set(profiles))
        for combo in self.manifest["combinations"]:
            if combo["class"] == class_name and sorted(combo["profiles"]) == want:
                return self.root / combo["file"]
        return None

    def supported_combinations(self) -> list[tuple[str, tuple[str, ...]]]:
        return [(c["class"], tuple(sorted(c["profiles"]))) for c in self.manifest["combinations"]]

    def validator(self, class_name: str, profiles: Iterable[str]) -> jsonschema.Draft7Validator:
        f = self.schema_file(class_name, profiles)
        if f is None:
            raise KeyError(f"no vendored JSON Schema for {class_name} with profiles {sorted(set(profiles))}")
        return _validator_for(str(f))

    # ------------------------------------------------------------ validation
    def validate(self, document: dict) -> ValidationResult:
        """Validate the OCSF part of a ULPF document (the ``ulpf`` key is ignored)."""
        res = ValidationResult()
        ev = {k: v for k, v in document.items() if k != "ulpf"}

        cuid = ev.get("class_uid")
        cname = self.class_name_for_uid(cuid) if isinstance(cuid, int) else None
        if cname is None:
            res.issues.append(Issue("class_uid", f"unknown class_uid {cuid!r}", "semantic"))
            return res
        profiles = (ev.get("metadata") or {}).get("profiles") or []
        try:
            v = self.validator(cname, profiles)
        except KeyError as exc:
            res.issues.append(Issue("metadata.profiles", str(exc), "semantic"))
            return res
        for err in sorted(v.iter_errors(ev), key=lambda e: list(e.absolute_path)):
            res.issues.append(Issue(".".join(str(p) for p in err.absolute_path), err.message, "jsonschema"))
        res.issues.extend(self._semantic(cname, ev, profiles))
        return res

    def _semantic(self, cname: str, ev: dict, profiles: list[str]) -> list[Issue]:
        out: list[Issue] = []
        cdef = self.class_def(cname)
        attrs = cdef["attributes"]

        act = ev.get("activity_id")
        if isinstance(act, int) and ev.get("type_uid") != cdef["uid"] * 100 + act:
            out.append(Issue("type_uid", f"expected {cdef['uid'] * 100 + act} (class_uid*100+activity_id), got {ev.get('type_uid')!r}", "semantic"))
        if ev.get("category_uid") != cdef.get("category_uid"):
            out.append(Issue("category_uid", f"class {cname} belongs to category {cdef.get('category_uid')}, got {ev.get('category_uid')!r}", "semantic"))
        md_ver = (ev.get("metadata") or {}).get("version")
        if md_ver != self.version:
            out.append(Issue("metadata.version", f"expected {self.version!r}, got {md_ver!r}", "semantic"))

        # Sibling caption consistency, driven by the schema's own enum/sibling data.
        out.extend(self._siblings(ev, attrs, "", profiles))
        # Type constraints from the OCSF dictionary (ranges, regexes, lengths).
        # The server-generated JSON Schemas encode ip_t/mac_t as plain strings
        # and port_t as a plain integer (verified), so this layer enforces them.
        out.extend(self._types(ev, attrs, ""))

        for kind, names in (cdef.get("constraints") or {}).items():
            present = [n for n in names if ev.get(n) not in (None, {}, [])]
            if kind == "at_least_one" and not present:
                out.append(Issue("", f"constraint at_least_one{names} violated", "semantic"))
            elif kind == "just_one" and len(present) != 1:
                out.append(Issue("", f"constraint just_one{names} violated (present: {present})", "semantic"))
        return out

    def _siblings(self, obj: dict, attrs: dict, prefix: str, profiles: list[str]) -> list[Issue]:
        out: list[Issue] = []
        for name, a in attrs.items():
            if name not in obj:
                continue
            val = obj[name]
            path = f"{prefix}{name}"
            if "enum" in a and a.get("sibling") and isinstance(val, int) and not isinstance(val, bool):
                sib = a["sibling"]
                caption = (a["enum"].get(str(val)) or {}).get("caption")
                if val != OTHER and caption is not None and sib in obj and obj[sib] != caption:
                    out.append(Issue(f"{prefix}{sib}", f"must be {caption!r} for {name}={val}, got {obj[sib]!r}", "semantic"))
                if val == OTHER and sib in obj and not obj[sib]:
                    out.append(Issue(f"{prefix}{sib}", f"{name}=99 (Other) requires the source value in {sib}", "semantic"))
            if a.get("type") == "object_t" and isinstance(val, dict) and a.get("object_type") in self.export["objects"]:
                sub = self.export["objects"][a["object_type"]]["attributes"]
                out.extend(self._siblings(val, sub, path + ".", profiles))
        return out


    def _check_value(self, path: str, type_name: str, val: Any) -> str | None:
        info = self.type_info(type_name)
        base = info.get("type", type_name)
        if isinstance(val, bool):
            return None
        rng = info.get("range")
        if rng and isinstance(val, int) and not (rng[0] <= val <= rng[1]):
            return f"{val} outside {type_name} range {rng}"
        if not isinstance(val, str):
            return None
        mx = info.get("max_len")
        if mx and len(val) > int(mx):
            return f"length {len(val)} exceeds {type_name} max_len {mx}"
        if type_name == "ip_t":
            try:
                ipaddress.ip_address(val)
            except ValueError:
                return f"{val!r} is not a valid IP address (ip_t)"
        elif type_name == "subnet_t":
            try:
                ipaddress.ip_network(val, strict=False)
            except ValueError:
                return f"{val!r} is not a valid subnet (subnet_t)"
        elif info.get("regex") and base == "string_t":
            rx = _compiled(info["regex"])
            if rx is not None and not rx.search(val):
                return f"{val!r} does not match the {type_name} pattern"
        return None

    def _types(self, obj: dict, attrs: dict, prefix: str) -> list[Issue]:
        out: list[Issue] = []
        for name, val in obj.items():
            a = attrs.get(name)
            if a is None:
                continue
            path = f"{prefix}{name}"
            vals = val if isinstance(val, list) else [val]
            for v in vals:
                if a.get("type") == "object_t":
                    sub = self.export["objects"].get(a.get("object_type") or "")
                    if sub and isinstance(v, dict):
                        out.extend(self._types(v, sub["attributes"], path + "."))
                else:
                    msg = self._check_value(path, a.get("type", ""), v)
                    if msg:
                        out.append(Issue(path, msg, "semantic"))
        return out


@lru_cache(maxsize=64)
def _compiled(pattern: str):
    try:
        return re.compile(pattern)
    except re.error:
        return None


@lru_cache(maxsize=64)
def _validator_for(path: str) -> jsonschema.Draft7Validator:
    schema = json.loads(Path(path).read_text())
    jsonschema.Draft7Validator.check_schema(schema)
    return jsonschema.Draft7Validator(schema)


@lru_cache(maxsize=1)
def default() -> Ocsf:
    return Ocsf()


def caption_for(class_name: str, attr_path: str, value: int, profiles: Iterable[str] = ()) -> str | None:
    a = default().resolve(class_name, attr_path, profiles)
    return (a.enum or {}).get(value)


def jsonable_key(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))
