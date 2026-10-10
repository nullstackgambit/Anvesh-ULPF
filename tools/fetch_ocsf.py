#!/usr/bin/env python3
"""Vendor an OCSF schema version from the official OCSF schema server.

This is a *development-time* tool that needs internet access. Its output is
committed under schema/ocsf/<version>/ so that ULPF can validate events fully
offline (air-gapped). Nothing in the ULPF runtime calls the OCSF server.

What is fetched (all from https://schema.ocsf.io, the official OCSF server):
  * /<version>/export/v2/schema          compiled schema (classes, objects,
                                         dictionary, profiles, enums)
  * /schema/classes/<class>?profiles=..  official draft-07 JSON Schema per
                                         (class, profile-set) combination

The server's /schema/... JSON-Schema route has no version path segment; it
serves the server's *default* version. The tool therefore refuses to run when
the server default differs from the requested version, and records the
default it observed in the manifest.

Usage: python3 tools/fetch_ocsf.py 1.9.0
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import sys
import time
import urllib.request
from pathlib import Path

SERVER = "https://schema.ocsf.io"

# (class name, profiles) combinations ULPF specifications may target.
# Each combination becomes one JSON Schema file. Adding a combination here and
# re-running the tool is the only supported way to widen what specs may use.
COMBINATIONS: list[tuple[str, tuple[str, ...]]] = [
    (c, p)
    for c in (
        "base_event",
        "network_activity",
        "http_activity",
        "dns_activity",
        "detection_finding",
        "authentication",
        "ssh_activity",
    )
    # `device` (the reporting firewall/sensor) requires the `host` profile.
    for p in ((), ("security_control",), ("host", "security_control"))
]


def _get(url: str, attempts: int = 4) -> bytes:
    """GET with retries; the server generates JSON Schemas on demand and can be slow."""
    last: Exception | None = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ulpf-fetch-ocsf/1"})
            with urllib.request.urlopen(req, timeout=180) as resp:  # noqa: S310 (fixed https host)
                if resp.status != 200:
                    raise RuntimeError(f"{url} -> HTTP {resp.status}")
                return resp.read()
        except (OSError, RuntimeError) as exc:  # TimeoutError is an OSError
            last = exc
            time.sleep(5 * (i + 1))
    raise RuntimeError(f"giving up on {url}: {last}")


def schema_file_name(cls: str, profiles: tuple[str, ...]) -> str:
    suffix = "__" + "+".join(sorted(profiles)) if profiles else "__none"
    return f"{cls}{suffix}.json"


def main(version: str) -> int:
    out = Path(__file__).resolve().parent.parent / "schema" / "ocsf" / version
    (out / "jsonschema").mkdir(parents=True, exist_ok=True)

    default = json.loads(_get(f"{SERVER}/api/version"))["version"]
    if default != version:
        print(
            f"refusing: server default version is {default}, requested {version}; "
            "the JSON-Schema route only serves the default version",
            file=sys.stderr,
        )
        return 2

    # Incremental: files already vendored (and listed in the manifest with a
    # matching hash) are kept as-is; pass --force to re-download everything.
    force = "--force" in sys.argv
    old_manifest_path = out / "MANIFEST.json"
    old_doc = json.loads(old_manifest_path.read_text()) if old_manifest_path.exists() else {}
    old = old_doc.get("files", {})
    for meta in old.values():  # manifests written before per-file timestamps existed
        meta.setdefault("fetched_at", old_doc.get("fetched_at", "unknown"))
    files: dict[str, dict[str, str]] = {}

    def now() -> str:
        return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")

    def keep_existing(rel: str) -> bool:
        p = out / rel
        if force or rel not in old or not p.exists():
            return False
        if hashlib.sha256(p.read_bytes()).hexdigest() != old[rel]["sha256"]:
            return False
        files[rel] = old[rel]
        return True

    def save(rel: str, data: bytes, url: str) -> None:
        path = out / rel
        path.write_bytes(data)
        files[rel] = {"sha256": hashlib.sha256(data).hexdigest(), "url": url, "bytes": str(len(data)), "fetched_at": now()}

    url = f"{SERVER}/{version}/export/v2/schema"
    if not keep_existing("export_v2_schema.json"):
        export = _get(url)
        if json.loads(export).get("version") != version:
            raise RuntimeError("export version mismatch")
        save("export_v2_schema.json", export, url)

    for cls, profiles in COMBINATIONS:
        rel = f"jsonschema/{schema_file_name(cls, profiles)}"
        if keep_existing(rel):
            continue
        url = f"{SERVER}/schema/classes/{cls}?profiles={','.join(profiles)}"
        data = _get(url)
        doc = json.loads(data)  # must be JSON (the HTML UI route would fail here)
        if doc.get("$schema") != "http://json-schema.org/draft-07/schema#":
            raise RuntimeError(f"unexpected $schema for {cls}: {doc.get('$schema')}")
        save(rel, data, url)
        print(f"fetched {rel}", flush=True)

    manifest = {
        "ocsf_version": version,
        "server": SERVER,
        "server_default_version_at_fetch": default,
        "manifest_written_at": now(),
        "combinations": [{"class": c, "profiles": list(p), "file": f"jsonschema/{schema_file_name(c, p)}"} for c, p in COMBINATIONS],
        "files": files,
    }
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"vendored OCSF {version}: {len(files)} files -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "1.9.0"))
