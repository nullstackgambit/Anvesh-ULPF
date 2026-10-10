"""Scenario 4 (losslessness) and 5 (tampering) against the RUNNING stack.

Every payload is sent, then retrieved by event UID from the raw archive
(`ulpf raw get` API) and from the normalized event, and compared byte-for-byte.
"""
import hashlib
import os
import subprocess
import time
from pathlib import Path

import pytest

from ulpf import gen, paths
from ulpf.integrity import get_raw
from ulpf.opensearch import Client
from ulpf.provenance import raw_bytes_of
from ulpf.settings import load

pytestmark = [pytest.mark.vector, pytest.mark.opensearch]

TRICKY = [
    b"<134>Oct  7 10:15:30 host app: plain",
    b"invalid utf8 \xff\xfe\x80 inside",
    b"nul\x00byte and \x01 control",
    "café 漢字 \U0001F600 multibyte".encode(),
    b"trailing CR\r",
    b"tab\tseparated\tvalues",
    b"x" * 3000,
    b"   leading spaces",
]


@pytest.fixture(scope="module")
def delivered():
    import urllib.request

    s = load()
    try:
        urllib.request.urlopen(f"http://{s['vector']['api_address']}/health", timeout=2)
    except Exception:  # noqa: BLE001
        pytest.skip("live Vector not running")
    nonce = os.urandom(4).hex().encode()
    payloads = []
    for transport, addr in (("udp", s["listen"]["syslog_udp"]), ("tcp", s["listen"]["syslog_tcp"]),
                            ("http", s["listen"]["http_ndjson"])):
        snd = gen.Sender(transport, addr)
        for i, p in enumerate(TRICKY):
            payload = p + b" #" + nonce + transport.encode() + str(i).encode()
            snd.send(payload, kind="tricky")
            payloads.append(payload)
        if transport == "udp":  # only datagrams can carry embedded newlines
            payload = b"multi\nline\ndatagram #" + nonce
            snd.send(payload, kind="tricky")
            payloads.append(payload)
        snd.close()
    time.sleep(6)
    c = Client.from_settings()
    c.refresh(s["opensearch"]["read_alias"])
    return payloads, c


def test_every_payload_round_trips_byte_for_byte(delivered):
    payloads, c = delivered
    for p in payloads:
        sha = hashlib.sha256(p).hexdigest()
        hits = c.search("ulpf-events", {"query": {"term": {"raw_data_hash.value": sha}}})["hits"]["hits"]
        assert len(hits) == 1, f"payload {p[:30]!r} indexed {len(hits)} times"
        doc = hits[0]["_source"]
        uid = doc["metadata"]["uid"]
        assert get_raw(uid).raw == p                 # from the raw archive
        assert raw_bytes_of(doc) == p                # from the normalized event itself
        assert doc["ulpf"]["raw"]["utf8"] == (p.decode("utf-8", "strict") is not None if _utf8(p) else False)


def _utf8(b: bytes) -> bool:
    try:
        b.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def test_tamper_demo_detects_a_single_flipped_byte():
    script = paths.HOME / "scripts" / "demo_tamper.sh"
    p = subprocess.run([str(script)], capture_output=True, text=True, timeout=300,
                       env=dict(os.environ, ULPF=str(Path(paths.HOME / ".venv" / "bin" / "ulpf"))))
    assert p.returncode == 0, p.stdout + p.stderr
    assert "VERIFY: PASS" in p.stdout and "VERIFY: FAIL" in p.stdout
    assert "Record hashes" in p.stdout
