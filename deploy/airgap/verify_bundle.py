#!/usr/bin/env python3
"""Verify an ULPF offline bundle against its BUNDLE.json (Python stdlib only).

Checks every listed file's SHA-256 and size, and that no unlisted file is
present. Prints the SHA-256 of BUNDLE.json so it can be compared with the
value published out of band. Exit 0 = OK.
Usage: verify_bundle.py BUNDLE_DIR
"""
import hashlib
import json
import sys
from pathlib import Path


def sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    root = Path(sys.argv[1]).resolve()
    body = (root / "BUNDLE.json").read_bytes()
    man = json.loads(body)
    if man.get("format") != "ulpf-bundle/1":
        print("unknown bundle format", file=sys.stderr)
        return 1
    bad = []
    for rel, meta in man["files"].items():
        p = root / rel
        if not p.is_file():
            bad.append(f"missing: {rel}")
        elif p.stat().st_size != meta["bytes"] or sha(p) != meta["sha256"]:
            bad.append(f"MODIFIED: {rel}")
    listed = set(man["files"]) | {"BUNDLE.json", "BUNDLE.json.sig"}
    for p in root.rglob("*"):
        if p.is_file() and str(p.relative_to(root)) not in listed:
            bad.append(f"unlisted: {p.relative_to(root)}")
    print(f"BUNDLE.json sha256: {hashlib.sha256(body).hexdigest()}")
    print(f"release.pub sha256: {sha(root / 'release.pub') if (root / 'release.pub').exists() else '-'}")
    if bad:
        print(f"bundle verification FAILED ({len(bad)} problem(s)):", file=sys.stderr)
        for b in bad[:50]:
            print("  " + b, file=sys.stderr)
        return 1
    print(f"bundle OK: {len(man['files'])} files, {man['total_bytes']} bytes, ulpf {man['ulpf']}, built {man['built_at']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
