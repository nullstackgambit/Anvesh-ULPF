"""`ulpf doctor`: verify the installation without network access."""
from __future__ import annotations

import hashlib
import importlib.metadata as md
import json
import shutil
import socket
import sys
from dataclasses import dataclass

from . import paths

# Exact pins the control plane was verified with (verification/DEPENDENCIES.md).
PINS = {
    "PyYAML": "6.0.3", "jsonschema": "4.26.0", "cryptography": "50.0.2", "click": "8.5.0",
    "drain3": "0.9.11", "pyarrow": "25.0.1", "scikit-learn": "1.9.1", "streamlit": "1.65.0",
    "pySigma": "1.5.1", "pySigma-backend-opensearch": "2.0.3",
}
CORE = {"PyYAML", "jsonschema", "cryptography", "click"}
VECTOR_VERSION = "0.58.0"
OPENSEARCH_VERSION = "3.8.0"


@dataclass
class Check:
    name: str
    status: str  # OK | WARN | FAIL
    detail: str


def run_checks() -> list[Check]:
    out: list[Check] = []
    add = lambda n, ok, d, warn=False: out.append(Check(n, "OK" if ok else ("WARN" if warn else "FAIL"), d))  # noqa: E731

    add("python", sys.version_info >= (3, 12), sys.version.split()[0])
    for pkg, want in PINS.items():
        try:
            have = md.version(pkg)
            add(f"package {pkg}", have == want, f"{have} (pinned {want})", warn=pkg not in CORE)
        except md.PackageNotFoundError:
            add(f"package {pkg}", False, f"not installed (pinned {want})", warn=pkg not in CORE)

    from . import vector

    try:
        v = vector.version()
        add("vector", VECTOR_VERSION in v, v)
    except Exception as e:  # noqa: BLE001
        add("vector", False, str(e))
    osb = paths.RUNTIME / "opensearch" / "bin" / "opensearch"
    if osb.exists():
        jar = paths.RUNTIME / "opensearch" / "lib" / f"opensearch-{OPENSEARCH_VERSION}.jar"
        add("opensearch", jar.exists(), f"{OPENSEARCH_VERSION} at {osb.parent.parent}" if jar.exists()
            else f"installed, but lib/opensearch-{OPENSEARCH_VERSION}.jar not found (different version?)")
    else:
        add("opensearch", False, "not installed (runtime/opensearch)", warn=True)
    rm = paths.RUNTIME / "MANIFEST.json"
    if rm.exists():
        bad = []
        for rel, sha in json.loads(rm.read_text()).get("binaries", {}).items():
            f = paths.RUNTIME / rel
            if not f.exists() or hashlib.sha256(f.read_bytes()).hexdigest() != sha:
                bad.append(rel)
        add("runtime binaries", not bad, "sha256 match runtime/MANIFEST.json" if not bad else f"mismatch: {bad}")
    else:
        add("runtime binaries", False, "runtime/MANIFEST.json missing (binary hashes not recorded)", warn=True)

    from .ocsf import Ocsf

    try:
        o = Ocsf()
        probs = o.verify_files()
        add("ocsf schema", not probs, f"OCSF {o.version}, {len(o.manifest['files'])} vendored files" + (f"; {probs}" if probs else ""))
    except Exception as e:  # noqa: BLE001
        add("ocsf schema", False, str(e))
    iana = paths.SCHEMA / "iana" / "protocol-numbers-1.csv"
    src = paths.SCHEMA / "iana" / "SOURCE.json"
    if iana.exists() and src.exists():
        ok = hashlib.sha256(iana.read_bytes()).hexdigest() == json.loads(src.read_text())["sha256"]
        add("iana protocol numbers", ok, "sha256 matches SOURCE.json" if ok else "sha256 MISMATCH")
    else:
        add("iana protocol numbers", False, "missing")

    from .spec import discover, lint_all

    res = lint_all(discover())
    nerr = sum(1 for _, iss in res.values() for i in iss if i.level == "error")
    add("specs", nerr == 0, f"{len(res)} approved spec(s), {nerr} lint error(s)")
    from .pipeline import check_generated

    live = paths.PIPELINE_GENERATED / "vector-live.yaml"
    if live.exists():
        ok, msg = check_generated(live)
        add("generated config", ok, msg)
    else:
        add("generated config", False, "not built (ulpf spec compile)", warn=True)
    key = paths.KEYS / "seal.key"
    add("seal key", key.exists(), str(key) if key.exists() else "missing (ulpf keygen)", warn=True)

    free = shutil.disk_usage(paths.HOME).free
    add("disk free", free > 1_000_000_000, f"{free / 1e9:.1f} GB", warn=True)
    from .settings import load

    s = load()
    for name in ("syslog_udp", "syslog_tcp", "http_ndjson"):
        host, _, port = s["listen"][name].rpartition(":")
        add(f"listen {name}", host in ("127.0.0.1", "::1", "localhost"), f"{host}:{port}"
            + ("" if host in ("127.0.0.1", "::1", "localhost") else " (exposed beyond loopback: check permit_origin/TLS)"), warn=True)
    return out


def _port_free(host: str, port: int) -> bool:
    with socket.socket() as so:
        return so.connect_ex((host, port)) != 0
