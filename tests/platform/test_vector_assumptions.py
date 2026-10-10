"""Regression tests for every Vector behaviour ULPF relies on (P0_REPORT.md).

If a Vector upgrade changes one of these, the corresponding design decision
must be revisited. Each test names the P0 finding it pins.
"""
import base64
import hashlib
import json
import socket
import time

import pytest

from ulpf import vector

pytestmark = pytest.mark.vector

SAMPLES = [b"plain ascii", b"bad utf8 \xff\xfe\x80 end", b"nul\x00byte", "café 漢字".encode(), b"cr\r", b"t\tab", b"x" * 5000]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run(tmp_path, sources: dict, transform_src: str, feed, wait: float = 2.0) -> list[dict]:
    out = tmp_path / "out.ndjson"
    cfg = tmp_path / "v.yaml"
    import yaml

    cfg.write_text(yaml.safe_dump({
        "data_dir": str(tmp_path),
        "sources": sources,
        "transforms": {"t": {"type": "remap", "inputs": list(sources), "source": transform_src}},
        "sinks": {"o": {"type": "file", "inputs": ["t"], "path": str(out), "encoding": {"codec": "json"}}},
    }))
    run = vector.start(cfg, tmp_path / "v.log")
    try:
        ports = [int(s["address"].rsplit(":", 1)[1]) for s in sources.values() if s.get("mode") == "tcp"]
        for p in ports:
            assert vector.wait_tcp("127.0.0.1", p, 30), run.log()
        if not ports:
            time.sleep(1.5)
        feed()
        time.sleep(wait)
    finally:
        run.stop()
    return [json.loads(l) for l in out.read_text().splitlines()] if out.exists() else []


B64 = '.b64 = encode_base64(string!(.message))\n.sha = sha2(string!(.message), variant: "SHA-256")\n.len = length(string!(.message))\n'


def test_V1_bytes_codec_preserves_exact_bytes_tcp_udp(tmp_path):
    tp, up = _free_port(), _free_port()
    sources = {
        "tcp": {"type": "socket", "mode": "tcp", "address": f"127.0.0.1:{tp}", "decoding": {"codec": "bytes"},
                "framing": {"method": "newline_delimited"}},
        "udp": {"type": "socket", "mode": "udp", "address": f"127.0.0.1:{up}", "decoding": {"codec": "bytes"}},
    }

    def feed():
        s = socket.create_connection(("127.0.0.1", tp))
        s.sendall(b"\n".join(SAMPLES) + b"\n")
        s.close()
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for x in SAMPLES:
            u.sendto(x, ("127.0.0.1", up))

    rows = _run(tmp_path, sources, B64, feed)
    assert len(rows) == 2 * len(SAMPLES)
    for r in rows:
        raw = base64.b64decode(r["b64"])
        assert raw in SAMPLES
        assert hashlib.sha256(raw).hexdigest() == r["sha"]
        assert r["len"] == len(raw)          # V3: length() counts bytes


def test_V2_json_encoding_of_message_is_lossy_for_invalid_utf8(tmp_path):
    up = _free_port()
    sources = {"udp": {"type": "socket", "mode": "udp", "address": f"127.0.0.1:{up}", "decoding": {"codec": "bytes"}}}
    rows = _run(tmp_path, sources, ".x = 1", lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"a\xffb", ("127.0.0.1", up)))
    assert rows and rows[0]["message"] == "a�b"


def test_V4_udp_datagram_with_newlines_is_one_event(tmp_path):
    up = _free_port()
    sources = {"udp": {"type": "socket", "mode": "udp", "address": f"127.0.0.1:{up}", "decoding": {"codec": "bytes"}}}
    rows = _run(tmp_path, sources, B64, lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"a\nb\n", ("127.0.0.1", up)))
    assert [base64.b64decode(r["b64"]) for r in rows] == [b"a\nb\n"]
    assert rows[0]["host"] == "127.0.0.1" and isinstance(rows[0]["port"], int)   # V4: host/port separate


def test_V20_octet_counting_is_not_byte_transparent(tmp_path):
    tp = _free_port()
    sources = {"oc": {"type": "socket", "mode": "tcp", "address": f"127.0.0.1:{tp}", "decoding": {"codec": "bytes"},
                      "framing": {"method": "octet_counting"}}}

    def feed():
        s = socket.create_connection(("127.0.0.1", tp))
        for f in [b"before", b"bad \xff\xfe", b"after"]:
            s.sendall(str(len(f)).encode() + b" " + f)
        time.sleep(0.3)
        s.close()

    got = [base64.b64decode(r["b64"]) for r in _run(tmp_path, sources, B64, feed)]
    # Documented limitation: the invalid frame AND later frames are lost. If a
    # Vector upgrade fixes this, the octet-counting listener can be re-enabled.
    assert got == [b"before"]


def test_V15_oversize_frame_is_discarded(tmp_path):
    tp = _free_port()
    sources = {"tcp": {"type": "socket", "mode": "tcp", "address": f"127.0.0.1:{tp}", "decoding": {"codec": "bytes"},
                       "framing": {"method": "newline_delimited", "newline_delimited": {"max_length": 100}}}}

    def feed():
        s = socket.create_connection(("127.0.0.1", tp))
        s.sendall(b"Y" * 150 + b"\nok\n")
        s.close()

    got = [base64.b64decode(r["b64"]) for r in _run(tmp_path, sources, B64, feed)]
    assert got == [b"ok"]


@pytest.mark.parametrize("program,expect", [
    ('x, e = to_int("abc")\n. = {"x": x, "err": e != null}', {"x": 0, "err": True}),                       # V6
    ('. = {"j": parse_json!("{\\"a\\":1,\\"a\\":2}")}', {"j": {"a": 2}}),                                   # V7
    ('. = {"kv": parse_key_value!("d=1 d=2")}', {"kv": {"d": ["1", "2"]}}),                                 # V7
    ('t = parse_timestamp!("2026/10/07 10:15:30", format: "%Y/%m/%d %H:%M:%S", timezone: "Asia/Kolkata")\n'
     '. = {"ms": to_unix_timestamp(t, unit: "milliseconds")}', {"ms": 1791368130000 - 19800000}),           # V8: 10:15:30 IST = 04:45:30Z
    ('s = parse_syslog!("<166>Oct 07 2026 10:15:30: %ASA-6-302013: Built inbound TCP connection 1")\n'
     '. = {"host": s.hostname}', {"host": "%ASA-6-302013"}),                                               # V9
    ('x, e = parse_syslog("<189>date=2026-10-07 type=traffic")\n. = {"failed": e != null}', {"failed": True}),  # V10
    # V17: UTF-8 validity probe; "Yf8=" is base64 of the bytes 0x61 0xFF (invalid UTF-8)
    ('bad = decode_base64!("Yf8=")\ngood = "ok"\n'
     '. = {"bad": (parse_json(encode_json(bad)) ?? null) == bad, "good": (parse_json(encode_json(good)) ?? null) == good}',
     {"bad": False, "good": True}),
    ('. = {"len": length("café"), "strlen": strlen("café")}', {"len": 5, "strlen": 4}),                    # V3
])
def test_vrl_semantics(program, expect):
    assert vector.run_vrl(program) == expect


def test_V5_missing_vrl_functions():
    for fn in ("parse_leef", "is_valid_utf8"):
        with pytest.raises(vector.VectorError, match="E105"):
            vector.run_vrl(f'. = {{"x": {fn}("a")}}')


def test_V16_unnecessary_coalescing_is_a_compile_error():
    with pytest.raises(vector.VectorError, match="E651"):
        vector.run_vrl('. = {"x": downcase("A") ?? "b"}')


def test_vrl_string_literals_interpolate_templates():
    with pytest.raises(vector.VectorError, match="E701"):
        vector.run_vrl('. = {"x": "{{ a }}"}')
    assert vector.run_vrl('. = {"x": "\\{{ a }}"}') == {"x": "{{ a }}"}
