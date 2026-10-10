"""Runtime artifacts (Vector, OpenSearch, plugins, Dashboards): fetch, verify,
install. Installation works fully offline from a directory of artifacts
(the air-gap bundle); only `fetch` touches the network.

Every artifact is pinned by SHA-256 in deploy/airgap/ARTIFACTS.json. Those
pins were taken from files whose integrity was first checked against the
publisher's own checksum files (and PGP signature for OpenSearch), see
verification/VERSIONS.md.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import tarfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

from . import paths

PINS_FILE = paths.DEPLOY / "airgap" / "ARTIFACTS.json"


@dataclass
class Artifact:
    name: str
    file: str
    url: str
    sha256: str
    kind: str          # vector | opensearch | os-plugin | dashboards | dash-plugin
    required: bool = True


def load_pins() -> list[Artifact]:
    data = json.loads(PINS_FILE.read_text())
    return [Artifact(**a) for a in data["artifacts"]]


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify(dist: Path, *, only_required: bool = False) -> list[str]:
    """Offline check of artifacts in `dist` against the pins. Returns problems."""
    probs = []
    for a in load_pins():
        if only_required and not a.required:
            continue
        f = dist / a.file
        if not f.exists():
            if a.required:
                probs.append(f"missing {a.file}")
            continue
        got = sha256_file(f)
        if got != a.sha256:
            probs.append(f"sha256 mismatch {a.file}: {got} != pinned {a.sha256}")
    return probs


def fetch(dist: Path, *, include_optional: bool = True) -> list[str]:
    """Download pinned artifacts (network!) and verify them against the pins."""
    dist.mkdir(parents=True, exist_ok=True)
    done = []
    for a in load_pins():
        if not a.required and not include_optional:
            continue
        f = dist / a.file
        if f.exists() and sha256_file(f) == a.sha256:
            done.append(f"{a.file}: present")
            continue
        tmp = f.with_suffix(f.suffix + ".part")
        with urllib.request.urlopen(a.url, timeout=600) as r, open(tmp, "wb") as out:  # noqa: S310 (pinned https URLs)
            shutil.copyfileobj(r, out)
        got = sha256_file(tmp)
        if got != a.sha256:
            tmp.unlink()
            raise RuntimeError(f"{a.file}: downloaded sha256 {got} != pinned {a.sha256}")
        tmp.rename(f)
        done.append(f"{a.file}: downloaded, sha256 verified")
    return done


def _extract_tar(tgz: Path, dest: Path, strip: int) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tgz) as tf:
        for m in tf.getmembers():
            parts = Path(m.name).parts[strip:]
            if not parts:
                continue
            m.name = str(Path(*parts))
            if m.issym() or m.islnk():
                target = Path(m.linkname)
                if target.is_absolute() or ".." in target.parts and m.islnk():
                    raise RuntimeError(f"refusing unsafe link {m.name} -> {m.linkname}")
            tf.extract(m, dest, filter="tar")  # Python 3.12 extraction filter: blocks path traversal


def install(dist: Path, *, with_dashboards: bool = False, with_security: bool = False) -> list[str]:
    """Install verified artifacts from `dist` into runtime/ (offline)."""
    probs = verify(dist, only_required=True)
    if probs:
        raise RuntimeError("artifact verification failed: " + "; ".join(probs))
    log = []
    pins = {a.kind: a for a in load_pins()}
    vec = pins["vector"]
    vdir = paths.RUNTIME / "vector"
    if not (vdir / "bin" / "vector").exists():
        # members are "./vector-x86_64-unknown-linux-musl/bin/vector"; pathlib
        # drops the "./", so one component is stripped (found by the air-gap
        # install test: strip=2 put the binary at vector/vector)
        _extract_tar(dist / vec.file, vdir, strip=1)
        log.append("vector installed")
    osd = paths.RUNTIME / "opensearch"
    if not (osd / "bin" / "opensearch").exists():
        _extract_tar(dist / pins["opensearch"].file, osd, strip=1)
        log.append("opensearch installed")
    if with_security and not (osd / "plugins" / "opensearch-security").exists():
        z = dist / pins["os-plugin"].file
        dest = osd / "plugins" / "opensearch-security"
        dest.mkdir(parents=True)
        with zipfile.ZipFile(z) as zf:
            for n in zf.namelist():
                if n.startswith("/") or ".." in Path(n).parts:
                    raise RuntimeError(f"unsafe zip entry {n}")
            zf.extractall(dest)
        for sh in (dest / "tools").glob("*.sh"):
            sh.chmod(0o750)
        log.append("opensearch-security plugin installed")
    if with_dashboards and "dashboards" in pins:
        dd = paths.RUNTIME / "opensearch-dashboards"
        if not (dd / "bin" / "opensearch-dashboards").exists():
            _extract_tar(dist / pins["dashboards"].file, dd, strip=1)
            log.append("opensearch-dashboards installed")
    missing = [rel for rel in ("vector/bin/vector", "opensearch/bin/opensearch") if not (paths.RUNTIME / rel).exists()]
    if missing:
        raise RuntimeError(f"runtime install incomplete, missing: {missing}")
    record()
    return log


KEY_BINARIES = [
    "vector/bin/vector",
    "opensearch/lib/opensearch-3.8.0.jar",
    "opensearch/jdk/bin/java",
]


def record() -> dict:
    """Write runtime/MANIFEST.json with sha256 of key installed binaries."""
    bins = {}
    for rel in KEY_BINARIES:
        f = paths.RUNTIME / rel
        if f.exists():
            bins[rel] = sha256_file(f)
    sec = paths.RUNTIME / "opensearch" / "plugins" / "opensearch-security"
    for jar in sorted(sec.glob("opensearch-security-*.jar")):
        bins[str(jar.relative_to(paths.RUNTIME))] = sha256_file(jar)
    man = {"binaries": bins}
    (paths.RUNTIME / "MANIFEST.json").write_text(json.dumps(man, indent=2, sort_keys=True) + "\n")
    return man
