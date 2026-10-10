"""Tamper-evident raw archive: Merkle trees, signed hash-chained manifests,
verification and raw retrieval.

Archive files (written by Vector) hold one JSON record per received event.
`seal` takes *closed* files, computes an RFC 6962 Merkle tree over their exact
record lines, and writes a manifest that commits to every file's SHA-256, its
Merkle root, the batch Merkle root and the previous manifest's SHA-256; the
manifest is signed with Ed25519.

This is TAMPER-EVIDENT, not immutable: the files live on writable storage.
Deleting the newest manifest(s) is detectable only against an externally
recorded head (`verify --expect-head`), see README.md, Known limitations.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import os
import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import __version__, paths

MANIFEST_FORMAT = "ulpf-seal-manifest/1"
_BUCKET = re.compile(r"raw-(\d{8}T\d{2}(?:\d{2})?)-")


# ----------------------------------------------------------- RFC 6962 hashing
def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def merkle_root(leaves: list[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Hash over already-computed leaf hashes."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = _split(n)
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    """RFC 6962 audit path for leaf `index`."""
    n = len(leaves)
    if n <= 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(leaves[:k], index) + [merkle_root(leaves[k:])]
    return inclusion_proof(leaves[k:], index - k) + [merkle_root(leaves[:k])]


def verify_inclusion(leaf: bytes, index: int, size: int, proof: list[bytes], root: bytes) -> bool:
    """Recompute the root from a leaf hash and its audit path (RFC 6962 / 9162)."""
    if index >= size:
        return False
    fn, sn = index, size - 1
    r = leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


# -------------------------------------------------------------------- keys
def key_paths() -> tuple[Path, Path]:
    return paths.KEYS / "seal.key", paths.KEYS / "seal.pub"


def keygen(force: bool = False) -> dict:
    priv_p, pub_p = key_paths()
    if priv_p.exists() and not force:
        raise FileExistsError(f"{priv_p} exists; refusing to replace a signing key (use --force deliberately)")
    paths.KEYS.mkdir(parents=True, exist_ok=True)
    k = Ed25519PrivateKey.generate()
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    fd = os.open(priv_p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    pub_p.write_bytes(k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return {"private_key": str(priv_p), "public_key": str(pub_p), "key_id": key_id(k.public_key())}


def key_id(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def load_private() -> Ed25519PrivateKey:
    k = serialization.load_pem_private_key(key_paths()[0].read_bytes(), password=None)
    if not isinstance(k, Ed25519PrivateKey):
        raise TypeError("seal key is not Ed25519")
    return k


def load_public(path: Path | None = None) -> Ed25519PublicKey:
    k = serialization.load_pem_public_key((path or key_paths()[1]).read_bytes())
    if not isinstance(k, Ed25519PublicKey):
        raise TypeError("seal public key is not Ed25519")
    return k


# ----------------------------------------------------------------- archive
def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def read_lines(path: Path) -> list[bytes]:
    """Exact record lines (without the trailing newline)."""
    data = path.read_bytes()
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    return lines


def bucket_end(path: Path) -> _dt.datetime | None:
    m = _BUCKET.search(path.name)
    if not m:
        return None
    s = m.group(1)
    if len(s) == 13:  # YYYYMMDDTHHMM
        start = _dt.datetime.strptime(s, "%Y%m%dT%H%M").replace(tzinfo=_dt.timezone.utc)
        return start + _dt.timedelta(minutes=1)
    start = _dt.datetime.strptime(s, "%Y%m%dT%H").replace(tzinfo=_dt.timezone.utc)
    return start + _dt.timedelta(hours=1)


def archive_files(root: Path = paths.ARCHIVE_RAW) -> list[Path]:
    return sorted(root.glob("*/raw-*.ndjson"))


def manifests(mdir: Path = paths.ARCHIVE_MANIFESTS) -> list[Path]:
    return sorted(mdir.glob("[0-9]" * 8 + ".json"))


def sealed_paths(mdir: Path = paths.ARCHIVE_MANIFESTS) -> set[str]:
    out = set()
    for m in manifests(mdir):
        out.update(f["path"] for f in json.loads(m.read_bytes())["files"])
    return out


@dataclass
class SealResult:
    sealed: bool
    seq: int | None = None
    files: int = 0
    records: int = 0
    merkle_root: str | None = None
    manifest_sha256: str | None = None
    problems: list[str] = field(default_factory=list)
    skipped_open: list[str] = field(default_factory=list)
    gaps: dict[str, int] = field(default_factory=dict)       # path -> blank lines (sealed as declared gaps)
    held_gaps: dict[str, int] = field(default_factory=dict)  # path -> blank lines (not sealed: --accept-gaps)


def gap_ranges(lines: list[bytes]) -> list[list[int]]:
    """1-based [first, last] runs of empty lines.

    An empty line is a *gap*: the archive sink wrote an event without its
    record (verified cause: a hot reload that changed a file sink's codec
    re-encoded the events still in its reused buffer, see VERIFICATION_REPORT
    finding P6-4). It carries no data and no event UID.
    """
    out: list[list[int]] = []
    for i, line in enumerate(lines, start=1):
        if line == b"":
            if out and out[-1][1] == i - 1:
                out[-1][1] = i
            else:
                out.append([i, i])
    return out


def _in_ranges(n: int, ranges: list[list[int]]) -> bool:
    return any(a <= n <= b for a, b in ranges)


def _check_record(line: bytes, where: str) -> str | None:
    try:
        r = json.loads(line)
        raw = base64.b64decode(r["raw_b64"], validate=True)
    except Exception as e:  # noqa: BLE001
        return f"{where}: unreadable record ({e})"
    if hashlib.sha256(raw).hexdigest() != r.get("raw_sha256") or len(raw) != r.get("raw_len"):
        return f"{where}: raw_b64 does not match raw_sha256/raw_len"
    return None


def seal(*, grace_s: int = 120, root: Path = paths.ARCHIVE_RAW, mdir: Path = paths.ARCHIVE_MANIFESTS,
         now: float | None = None, index: bool = True, accept_gaps: bool = False) -> SealResult:
    """Seal every closed, not-yet-sealed archive file into one signed batch.

    A file with an unreadable or inconsistent record is never sealed (it is
    reported and the other files are sealed). A file with gaps (empty lines)
    is held back until an operator has investigated (`ulpf account`,
    `ulpf repair`) and seals it with `accept_gaps`: the gaps are then declared
    in the signed manifest, and their leaves (hash of the empty line) are part
    of the Merkle tree, so filling a gap later is detected like any other edit.
    """
    now = now or time.time()
    done = sealed_paths(mdir)
    todo, skipped = [], []
    for f in archive_files(root):
        rel = str(f.relative_to(root))
        if rel in done:
            continue
        end = bucket_end(f)
        if end is None or end.timestamp() + grace_s > now or f.stat().st_mtime + grace_s > now:
            skipped.append(rel)
            continue
        todo.append((rel, f))
    res = SealResult(sealed=False, skipped_open=skipped)
    if not todo:
        return res
    priv = load_private()
    entries, all_leaves, idx_rows = [], [], []
    for rel, f in todo:
        data = f.read_bytes()
        lines = read_lines(f)
        gaps = gap_ranges(lines)
        probs = [p for i, line in enumerate(lines) if line != b"" and (p := _check_record(line, f"{rel}:{i + 1}"))]
        if probs:
            res.problems.extend(probs)  # never seal records that are already inconsistent
            continue
        n_gap = sum(b - a + 1 for a, b in gaps)
        if gaps and not accept_gaps:
            res.held_gaps[rel] = n_gap
            continue
        leaves = [leaf_hash(line) for line in lines]
        recs = [json.loads(line) for line in lines if line != b""]
        first, last = (recs[0], recs[-1]) if recs else ({}, {})
        entry = {
            "path": rel, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "records": len(lines),
            "merkle_root": merkle_root(leaves).hex(), "first_event_uid": first.get("event_uid"),
            "last_event_uid": last.get("event_uid"), "first_ingest_time": first.get("ingest_time"),
            "last_ingest_time": last.get("ingest_time"),
        }
        if gaps:
            entry["gaps"] = gaps          # "records" counts physical lines (leaves), gaps included
            res.gaps[rel] = n_gap
        entries.append(entry)
        offset = 0
        for i, line in enumerate(lines):
            if line != b"":
                idx_rows.append((json.loads(line).get("event_uid"), rel, i, offset, len(line), len(all_leaves) + i))
            offset += len(line) + 1
        all_leaves.extend(leaves)
    if not entries:
        return res
    mdir.mkdir(parents=True, exist_ok=True)
    prev = manifests(mdir)
    seq = len(prev) + 1
    prev_sha = hashlib.sha256(prev[-1].read_bytes()).hexdigest() if prev else None
    man = {
        "format": MANIFEST_FORMAT, "seq": seq, "created_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "ulpf_version": __version__, "prev_manifest_sha256": prev_sha, "key_id": key_id(priv.public_key()),
        "algorithms": {"leaf": "sha256(0x00 || record_line)", "node": "sha256(0x01 || left || right)",
                       "tree": "RFC 6962 Merkle Tree Hash", "signature": "Ed25519 over the canonical manifest bytes"},
        "files": entries, "records": len(all_leaves), "merkle_root": merkle_root(all_leaves).hex(),
    }
    body = canonical(man)
    mpath = mdir / f"{seq:08d}.json"
    tmp = mpath.with_suffix(".tmp")
    tmp.write_bytes(body)
    (mdir / f"{seq:08d}.sig").write_text(base64.b64encode(priv.sign(body)).decode() + "\n")
    os.replace(tmp, mpath)
    head = hashlib.sha256(body).hexdigest()
    (mdir / "HEAD").write_text(f"{seq} {head}\n")
    if index:
        _index_rows(idx_rows, seq)
    res.sealed, res.seq, res.files = True, seq, len(entries)
    res.records = len(all_leaves) - sum(res.gaps.values())   # gap lines are leaves, not records
    res.merkle_root, res.manifest_sha256 = man["merkle_root"], head
    return res


def _db() -> sqlite3.Connection:
    paths.ARCHIVE.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(paths.ARCHIVE_INDEX)
    con.execute("CREATE TABLE IF NOT EXISTS records (event_uid TEXT PRIMARY KEY, path TEXT NOT NULL, line INTEGER NOT NULL,"
                " offset INTEGER NOT NULL, length INTEGER NOT NULL, seq INTEGER, leaf_index INTEGER)")
    return con


def _index_rows(rows: list[tuple], seq: int) -> None:
    con = _db()
    with con:
        con.executemany("INSERT OR REPLACE INTO records VALUES (?,?,?,?,?,?,?)",
                        [(u, p, ln, off, length, seq, li) for (u, p, ln, off, length, li) in rows])
    con.close()


# ------------------------------------------------------------------ verify
@dataclass
class Check:
    name: str
    ok: bool
    details: list[str] = field(default_factory=list)


@dataclass
class VerifyReport:
    checks: list[Check]
    manifests: int
    records: int
    head: str | None
    gap_lines: int = 0

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)


def verify(*, root: Path = paths.ARCHIVE_RAW, mdir: Path = paths.ARCHIVE_MANIFESTS, pubkey: Path | None = None,
           expect_head: str | None = None, deep: bool = True, grace_s: int = 120, now: float | None = None) -> VerifyReport:
    now = now or time.time()
    pub = load_public(pubkey)
    kid = key_id(pub)
    sig, chain, fhash, merkle, rec, cover, head_c, gap_c = (Check(n, True) for n in (
        "Signatures", "Manifest chain", "File hashes", "Merkle roots", "Record hashes", "Archive coverage", "Head",
        "Declared gaps"))
    mlist = manifests(mdir)
    prev_sha, nrec, ngap, head = None, 0, 0, None
    expected_seq = 1
    covered: set[str] = set()
    for m in mlist:
        body = m.read_bytes()
        try:
            man = json.loads(body)
        except json.JSONDecodeError as e:
            chain.ok = False
            chain.details.append(f"{m.name}: not valid JSON ({e})")
            continue
        seq = man.get("seq")
        if seq != expected_seq:
            chain.ok = False
            chain.details.append(f"{m.name}: seq {seq}, expected {expected_seq} (missing or reordered manifest)")
        expected_seq = (seq or expected_seq) + 1
        if canonical(man) != body:
            chain.ok = False
            chain.details.append(f"{m.name}: not in canonical form (edited?)")
        if man.get("prev_manifest_sha256") != prev_sha:
            chain.ok = False
            chain.details.append(f"{m.name}: prev_manifest_sha256 does not match the preceding manifest")
        sp = m.with_suffix(".sig")
        try:
            pub.verify(base64.b64decode(sp.read_text().strip()), body)
            if man.get("key_id") != kid:
                raise InvalidSignature("key id mismatch")
        except (OSError, ValueError, InvalidSignature) as e:
            sig.ok = False
            sig.details.append(f"{m.name}: signature invalid ({type(e).__name__}: {e})")
        all_leaves: list[bytes] = []
        for fe in man.get("files", []):
            covered.add(fe["path"])
            f = root / fe["path"]
            if not f.exists():
                fhash.ok = False
                fhash.details.append(f"{fe['path']}: missing (deleted archive file)")
                continue
            data = f.read_bytes()
            if hashlib.sha256(data).hexdigest() != fe["sha256"] or len(data) != fe["bytes"]:
                fhash.ok = False
                fhash.details.append(f"{fe['path']}: sha256/size differs from manifest {m.name}")
            lines = read_lines(f)
            leaves = [leaf_hash(l) for l in lines]
            if len(lines) != fe["records"]:
                merkle.ok = False
                merkle.details.append(f"{fe['path']}: {len(lines)} records, manifest says {fe['records']} (deleted/inserted records)")
            if merkle_root(leaves).hex() != fe["merkle_root"]:
                merkle.ok = False
                merkle.details.append(f"{fe['path']}: Merkle root differs (modified or reordered records)")
            declared = fe.get("gaps") or []
            ngap += sum(b - a + 1 for a, b in declared)
            if declared:
                gap_c.details.append(f"{fe['path']}: {sum(b - a + 1 for a, b in declared)} empty line(s) declared "
                                     f"at seal time (no record; see `ulpf account`/`ulpf repair`)")
            if deep:
                for i, line in enumerate(lines):
                    if line == b"" and _in_ranges(i + 1, declared):
                        continue
                    p = _check_record(line, f"{fe['path']}:{i + 1}")
                    if p:
                        rec.ok = False
                        rec.details.append(p)
            all_leaves.extend(leaves)
            nrec += sum(1 for line in lines if line != b"")
        if merkle_root(all_leaves).hex() != man.get("merkle_root"):
            merkle.ok = False
            merkle.details.append(f"{m.name}: batch Merkle root differs")
        prev_sha = hashlib.sha256(body).hexdigest()
        head = f"{seq} {prev_sha}"
    for f in archive_files(root):
        rel = str(f.relative_to(root))
        if rel in covered:
            continue
        end = bucket_end(f)
        if end is not None and end.timestamp() + grace_s <= now:
            cover.ok = False
            cover.details.append(f"{rel}: closed but not sealed (run `ulpf seal`), or removed from its manifest")
    hf = mdir / "HEAD"
    if hf.exists() and head and hf.read_text().strip() != head:
        head_c.ok = False
        head_c.details.append(f"HEAD file says {hf.read_text().strip()!r}, chain ends at {head!r}")
    if expect_head:
        want = expect_head.split()[-1]
        if not head or head.split()[-1] != want:
            head_c.ok = False
            head_c.details.append(f"externally recorded head {want[:16]}... does not match chain end "
                                  f"{head.split()[-1][:16] + '...' if head else 'none'} (truncated or replaced chain)")
    if not mlist:
        chain.details.append("no manifests yet")
    return VerifyReport([sig, chain, fhash, merkle, rec, cover, head_c, gap_c], len(mlist), nrec, head, ngap)


# --------------------------------------------------------------- retrieval
@dataclass
class RawRecord:
    event_uid: str
    raw: bytes
    record: dict
    path: str
    line: int
    sealed_seq: int | None
    proof: dict | None = None


def _scan(event_uid: str, root: Path) -> tuple[str, int, bytes] | None:
    needle = f'"event_uid":"{event_uid}"'.encode()
    for f in archive_files(root):
        for i, line in enumerate(read_lines(f)):
            if needle in line:
                return str(f.relative_to(root)), i, line
    return None


def get_raw(event_uid: str, *, root: Path = paths.ARCHIVE_RAW, mdir: Path = paths.ARCHIVE_MANIFESTS,
            with_proof: bool = False) -> RawRecord:
    found = None
    seq = None
    if paths.ARCHIVE_INDEX.exists():
        con = _db()
        row = con.execute("SELECT path, line, offset, length, seq FROM records WHERE event_uid=?", (event_uid,)).fetchone()
        con.close()
        if row:
            rel, line_no, off, length, seq = row
            with open(root / rel, "rb") as fh:
                fh.seek(off)
                found = (rel, line_no, fh.read(length))
    if found is None:
        found = _scan(event_uid, root)
    if found is None:
        raise KeyError(f"event {event_uid} not found in the raw archive")
    rel, line_no, line = found
    rec = json.loads(line)
    if rec.get("event_uid") != event_uid:
        raise ValueError("index points at a different record (archive modified after indexing?)")
    raw = base64.b64decode(rec["raw_b64"])
    if hashlib.sha256(raw).hexdigest() != rec["raw_sha256"]:
        raise ValueError(f"record {rel}:{line_no + 1} is corrupt: raw bytes do not match raw_sha256")
    out = RawRecord(event_uid, raw, rec, rel, line_no, seq)
    if with_proof:
        out.proof = _proof_for(rel, line_no, root, mdir)
        out.sealed_seq = out.proof["seq"] if out.proof else None
    return out


def _proof_for(rel: str, line_no: int, root: Path, mdir: Path) -> dict | None:
    for m in manifests(mdir):
        man = json.loads(m.read_bytes())
        offset = 0
        leaves: list[bytes] = []
        target = None
        for fe in man["files"]:
            lines = read_lines(root / fe["path"])
            if fe["path"] == rel:
                target = offset + line_no
            leaves.extend(leaf_hash(l) for l in lines)
            offset += len(lines)
        if target is not None:
            proof = inclusion_proof(leaves, target)
            ok = verify_inclusion(leaves[target], target, len(leaves), proof, bytes.fromhex(man["merkle_root"]))
            return {"seq": man["seq"], "manifest": m.name, "leaf_index": target, "tree_size": len(leaves),
                    "merkle_root": man["merkle_root"], "audit_path": [p.hex() for p in proof], "verified": ok}
    return None
