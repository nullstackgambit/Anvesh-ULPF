"""Integrity: RFC 6962 vectors, inclusion proofs, seal/verify, tamper detection."""
import base64
import hashlib
import json
import time

import pytest

from ulpf import integrity as I
from ulpf import paths

# RFC 6962 test vectors from transparency-dev/merkle (Apache-2.0),
# testonly/constants.go @ 77f1b57d7aa25fcd2e51273166b6b2b0e74923b1
LEAF_INPUTS = [bytes.fromhex(h) for h in ["", "00", "10", "2021", "3031", "40414243", "5051525354555657",
                                          "606162636465666768696a6b6c6d6e6f"]]
ROOTS = ["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
         "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
         "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
         "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
         "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
         "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
         "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
         "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"]


def test_empty_tree_root():
    assert I.merkle_root([]).hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.mark.parametrize("n", range(1, 9))
def test_rfc6962_root_vectors(n):
    assert I.merkle_root([I.leaf_hash(x) for x in LEAF_INPUTS[:n]]).hex() == ROOTS[n - 1]


@pytest.mark.parametrize("size", [1, 2, 3, 5, 8, 13, 21])
def test_inclusion_proofs(size):
    leaves = [I.leaf_hash(f"leaf-{i}".encode()) for i in range(size)]
    root = I.merkle_root(leaves)
    for i in range(size):
        proof = I.inclusion_proof(leaves, i)
        assert I.verify_inclusion(leaves[i], i, size, proof, root)
        assert not I.verify_inclusion(I.leaf_hash(b"other"), i, size, proof, root)
        if proof:
            bad = [bytes(32)] + proof[1:]
            assert not I.verify_inclusion(leaves[i], i, size, bad, root)


# ------------------------------------------------------------------ archive
def _record(uid: str, raw: bytes) -> bytes:
    rec = {"v": 1, "event_uid": uid, "ingest_time": "2026-10-07T10:00:00.000000000Z", "collector_id": "t",
           "transport": "test", "peer": {}, "raw_len": len(raw), "raw_sha256": hashlib.sha256(raw).hexdigest(),
           "raw_b64": base64.b64encode(raw).decode()}
    return json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()


@pytest.fixture
def arch(tmp_path, monkeypatch):
    root, mdir, keys = tmp_path / "raw", tmp_path / "manifests", tmp_path / "keys"
    monkeypatch.setattr(paths, "KEYS", keys)
    monkeypatch.setattr(paths, "ARCHIVE", tmp_path)
    monkeypatch.setattr(paths, "ARCHIVE_INDEX", tmp_path / "index.sqlite")
    I.keygen()
    uids = []

    def write(day: str, bucket: str, n: int, start: int = 0):
        f = root / day / f"raw-{bucket}-t.ndjson"
        f.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        for i in range(start, start + n):
            uid = f"00000000-0000-7000-8000-{i:012d}"
            uids.append(uid)
            raw = f"<13>event {i} café".encode() if i % 3 else b"bin\xff\xfe" + bytes([i % 256])
            lines.append(_record(uid, raw))
        f.write_bytes(b"\n".join(lines) + b"\n")
        old = time.time() - 3600
        import os
        os.utime(f, (old, old))
        return f

    class A:
        pass

    a = A()
    a.root, a.mdir, a.write, a.uids, a.tmp = root, mdir, write, uids, tmp_path
    return a


def _seal(a, now=None):
    return I.seal(root=a.root, mdir=a.mdir, grace_s=60, now=now)


def _verify(a, **kw):
    return I.verify(root=a.root, mdir=a.mdir, grace_s=60, **kw)


def _failed(rep):
    return {c.name for c in rep.checks if not c.ok}


def test_seal_then_verify_passes(arch):
    arch.write("2026-10-06", "20261006T1000", 5)
    arch.write("2026-10-06", "20261006T1001", 4, start=5)
    r = _seal(arch)
    assert r.sealed and r.files == 2 and r.records == 9 and not r.problems
    rep = _verify(arch)
    assert rep.ok, [(c.name, c.details) for c in rep.checks]
    assert rep.records == 9 and rep.manifests == 1


def test_open_file_is_not_sealed(arch):
    now_bucket = time.strftime("%Y%m%dT%H%M", time.gmtime())
    arch.write("2026-10-07", now_bucket, 3)
    r = _seal(arch)
    assert not r.sealed and r.skipped_open


def test_one_flipped_byte_is_detected(arch):
    f = arch.write("2026-10-06", "20261006T1000", 5)
    _seal(arch)
    data = bytearray(f.read_bytes())
    i = data.index(b'"raw_b64":"') + 12
    data[i] = ord("A") if data[i] != ord("A") else ord("B")
    f.write_bytes(bytes(data))
    rep = _verify(arch)
    assert {"File hashes", "Merkle roots", "Record hashes"} <= _failed(rep)


def test_deleted_record_is_detected(arch):
    f = arch.write("2026-10-06", "20261006T1000", 5)
    _seal(arch)
    lines = f.read_bytes().split(b"\n")
    del lines[2]
    f.write_bytes(b"\n".join(lines))
    rep = _verify(arch)
    assert "Merkle roots" in _failed(rep) and "File hashes" in _failed(rep)


def test_reordered_records_are_detected(arch):
    f = arch.write("2026-10-06", "20261006T1000", 5)
    _seal(arch)
    lines = f.read_bytes().rstrip(b"\n").split(b"\n")
    lines[0], lines[1] = lines[1], lines[0]
    f.write_bytes(b"\n".join(lines) + b"\n")
    rep = _verify(arch)
    assert "Merkle roots" in _failed(rep)
    assert "Record hashes" not in _failed(rep)  # every record is intact, only the order changed


def test_deleted_archive_file_is_detected(arch):
    f = arch.write("2026-10-06", "20261006T1000", 5)
    _seal(arch)
    f.unlink()
    assert "File hashes" in _failed(_verify(arch))


def test_deleted_middle_manifest_breaks_the_chain(arch):
    for k, b in enumerate(["20261006T1000", "20261006T1001", "20261006T1002"]):
        arch.write("2026-10-06", b, 2, start=10 * k)
        assert _seal(arch).sealed
    (arch.mdir / "00000002.json").unlink()
    (arch.mdir / "00000002.sig").unlink()
    failed = _failed(_verify(arch))
    assert "Manifest chain" in failed
    assert "Archive coverage" in failed  # the batch-2 file is no longer covered


def test_edited_manifest_fails_signature(arch):
    arch.write("2026-10-06", "20261006T1000", 3)
    _seal(arch)
    m = arch.mdir / "00000001.json"
    doc = json.loads(m.read_bytes())
    doc["records"] = 2
    m.write_bytes(I.canonical(doc))
    assert "Signatures" in _failed(_verify(arch))


def test_wrong_public_key_fails(arch, tmp_path):
    arch.write("2026-10-06", "20261006T1000", 3)
    _seal(arch)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    other = tmp_path / "other.pub"
    other.write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    assert "Signatures" in _failed(_verify(arch, pubkey=other))


def test_tail_truncation_needs_external_head(arch):
    for k, b in enumerate(["20261006T1000", "20261006T1001"]):
        arch.write("2026-10-06", b, 2, start=10 * k)
        _seal(arch)
    head = (arch.mdir / "HEAD").read_text().strip()
    # attacker deletes the newest batch: its file, manifest, signature and HEAD
    (arch.root / "2026-10-06" / "raw-20261006T1001-t.ndjson").unlink()
    for ext in (".json", ".sig"):
        (arch.mdir / f"00000002{ext}").unlink()
    (arch.mdir / "HEAD").unlink()
    assert _verify(arch).ok                       # documented limitation: undetectable on its own
    assert "Head" in _failed(_verify(arch, expect_head=head))


def test_unsealed_closed_file_is_reported(arch):
    arch.write("2026-10-06", "20261006T1000", 2)
    _seal(arch)
    arch.write("2026-10-06", "20261006T1001", 2, start=50)
    assert "Archive coverage" in _failed(_verify(arch))


def test_seal_refuses_inconsistent_records(arch):
    f = arch.write("2026-10-06", "20261006T1000", 2)
    lines = f.read_bytes().split(b"\n")
    rec = json.loads(lines[0])
    rec["raw_sha256"] = "0" * 64
    lines[0] = json.dumps(rec).encode()
    f.write_bytes(b"\n".join(lines))
    import os
    old = time.time() - 3600
    os.utime(f, (old, old))  # a freshly modified file would (correctly) count as still open
    r = _seal(arch)
    assert not r.sealed and r.problems


def test_raw_get_returns_exact_bytes_with_proof(arch):
    arch.write("2026-10-06", "20261006T1000", 6)
    _seal(arch)
    for uid in arch.uids:
        got = I.get_raw(uid, root=arch.root, mdir=arch.mdir, with_proof=True)
        rec = got.record
        assert got.raw == base64.b64decode(rec["raw_b64"])
        assert hashlib.sha256(got.raw).hexdigest() == rec["raw_sha256"]
        assert got.proof and got.proof["verified"]
    with pytest.raises(KeyError):
        I.get_raw("ffffffff-0000-7000-8000-000000000000", root=arch.root, mdir=arch.mdir)


def test_keygen_refuses_to_overwrite(arch):
    with pytest.raises(FileExistsError):
        I.keygen()
    assert oct((paths.KEYS / "seal.key").stat().st_mode & 0o777) == "0o600"


# ------------------------------------------------------------ declared gaps
def _gapped(arch, bucket="20261006T1000", n=4, at=2, k=2):
    """n records with k empty lines after record `at` (what Vector wrote when a
    hot reload re-encoded buffered events with a changed codec, finding P6-4)."""
    f = arch.write("2026-10-06", bucket, n, start=100 * int(bucket[-2:]))
    lines = f.read_bytes().split(b"\n")[:-1]
    f.write_bytes(b"\n".join(lines[:at] + [b""] * k + lines[at:]) + b"\n")
    import os
    old = time.time() - 3600
    os.utime(f, (old, old))
    return f


def test_gapped_file_is_held_back_and_clean_files_are_still_sealed(arch):
    _gapped(arch)
    arch.write("2026-10-06", "20261006T1001", 3, start=500)
    r = _seal(arch)
    assert r.sealed and r.files == 1 and not r.problems
    assert r.held_gaps == {"2026-10-06/raw-20261006T1000-t.ndjson": 2}
    assert "Archive coverage" in _failed(_verify(arch))   # the held file is closed but unsealed


def test_accepted_gaps_are_declared_signed_and_verified(arch):
    _gapped(arch)
    r = I.seal(root=arch.root, mdir=arch.mdir, grace_s=60, accept_gaps=True)
    assert r.sealed and r.gaps == {"2026-10-06/raw-20261006T1000-t.ndjson": 2}
    man = json.loads(sorted(arch.mdir.glob("0*.json"))[0].read_bytes())
    assert man["files"][0]["gaps"] == [[3, 4]] and man["files"][0]["records"] == 6
    rep = _verify(arch)
    assert rep.ok and rep.records == 4 and rep.gap_lines == 2, _failed(rep)
    assert any("2 empty line(s) declared" in d for c in rep.checks for d in c.details)
    for uid in arch.uids:                                  # offsets account for the empty lines
        got = I.get_raw(uid, root=arch.root, mdir=arch.mdir, with_proof=True)
        assert got.record["event_uid"] == uid and got.proof["verified"]


def test_filling_a_declared_gap_is_detected(arch):
    f = _gapped(arch)
    I.seal(root=arch.root, mdir=arch.mdir, grace_s=60, accept_gaps=True)
    lines = f.read_bytes().split(b"\n")
    lines[2] = _record("00000000-0000-7000-8000-999999999999", b"forged")
    f.write_bytes(b"\n".join(lines))
    assert {"File hashes", "Merkle roots"} <= _failed(_verify(arch))


def test_blanking_a_sealed_record_is_detected(arch):
    f = arch.write("2026-10-06", "20261006T1000", 4)
    _seal(arch)
    lines = f.read_bytes().split(b"\n")
    lines[1] = b""                                          # undeclared gap
    f.write_bytes(b"\n".join(lines))
    assert {"File hashes", "Merkle roots", "Record hashes"} <= _failed(_verify(arch))
