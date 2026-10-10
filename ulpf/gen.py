"""SYNTHETIC TEST DATA generator and senders.

Every renderer produces events in a vendor format whose *field names and
layout* come from the vendor's official documentation (references in each
renderer's docstring and in samples/README.md). The *values* are synthetic:
public addresses come from the RFC 5737 documentation ranges and private ones
from RFC 1918, so no real network is described.

A canonical :class:`Flow` can be rendered by several vendors; this is what the
cross-vendor equivalence acceptance test is built on.

Senders record every payload they send (sha256 + length) in a send log so the
end-to-end accounting can prove sent == received == archived == indexed.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import random
import socket
import time
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterable

SYNTHETIC_MARK = "SYNTHETIC TEST DATA"


@dataclass
class Flow:
    """Vendor-neutral description of one network session (ground truth)."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str              # tcp | udp | icmp
    action: str             # allow | deny
    bytes_out: int = 0      # source -> destination
    bytes_in: int = 0       # destination -> source
    packets_out: int = 0
    packets_in: int = 0
    time: _dt.datetime = field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc))
    session_id: int = 0
    rule: str = "1"
    src_intf: str = "port1"
    dst_intf: str = "wan1"

    @property
    def proto_num(self) -> int:
        return {"icmp": 1, "tcp": 6, "udp": 17}[self.proto]

    def truth(self) -> dict:
        d = asdict(self)
        d["time_ms"] = int(self.time.timestamp() * 1000)
        d["time"] = self.time.isoformat()
        return d


def random_flow(rng: random.Random, *, when: _dt.datetime | None = None, action: str | None = None) -> Flow:
    proto = rng.choice(["tcp", "tcp", "tcp", "udp"])
    dport = rng.choice([443, 80, 22, 53, 3389, 8443]) if proto == "tcp" else rng.choice([53, 123, 514])
    when = when or _dt.datetime.now(_dt.timezone.utc)
    return Flow(
        src_ip=f"10.{rng.randint(0, 3)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
        src_port=rng.randint(1024, 65535),
        dst_ip=f"203.0.113.{rng.randint(1, 254)}",
        dst_port=dport,
        proto=proto,
        action=action or rng.choice(["allow", "allow", "allow", "deny"]),
        bytes_out=rng.randint(60, 20000),
        bytes_in=rng.randint(0, 200000),
        packets_out=rng.randint(1, 50),
        packets_in=rng.randint(0, 80),
        time=when.replace(microsecond=(when.microsecond // 1000) * 1000),
        session_id=rng.randint(1, 4_000_000),
        rule=str(rng.randint(1, 40)),
    )


# ---------------------------------------------------------------- renderers
def fortigate_traffic(f: Flow, *, devname: str = "FGT-HQ-01", devid: str = "FGT60FTK00000001") -> bytes:
    """FortiOS 7.6 traffic log, LOG_ID_TRAFFIC_END_FORWARD (logid 0000000013).

    Field names/types: FortiOS 7.6.0 Log Message Reference
    (verification/vendor_refs/fortios-7.6.0-0000000013-traffic-end-forward.json).
    Transport: syslog `<PRI>` followed by space-separated key=value pairs.
    The exact header layout of FortiOS' *default* syslog format is UNVERIFIED;
    the spec accepts PRI-only, RFC 3164 and RFC 5424 headers.
    """
    action = {"allow": "close", "deny": "deny"}[f.action]
    ns = int(f.time.timestamp() * 1000) * 1_000_000 + 123_456
    kv = [
        ("date", f.time.strftime("%Y-%m-%d")), ("time", f.time.strftime("%H:%M:%S")),
        ("devname", f'"{devname}"'), ("devid", f'"{devid}"'), ("eventtime", str(ns)), ("tz", '"+0000"'),
        ("logid", '"0000000013"'), ("type", '"traffic"'), ("subtype", '"forward"'), ("level", '"notice"'),
        ("vd", '"root"'), ("srcip", f.src_ip), ("srcport", str(f.src_port)), ("srcintf", f'"{f.src_intf}"'),
        ("srcintfrole", '"lan"'), ("dstip", f.dst_ip), ("dstport", str(f.dst_port)), ("dstintf", f'"{f.dst_intf}"'),
        ("dstintfrole", '"wan"'), ("sessionid", str(f.session_id)), ("proto", str(f.proto_num)),
        ("action", f'"{action}"'), ("policyid", f.rule), ("policytype", '"policy"'), ("service", '"HTTPS"'),
        ("trandisp", '"snat"'), ("duration", "12"), ("sentbyte", str(f.bytes_out)), ("rcvdbyte", str(f.bytes_in)),
        ("sentpkt", str(f.packets_out)), ("rcvdpkt", str(f.packets_in)), ("appcat", '"unscanned"'),
    ]
    return b"<189>" + " ".join(f"{k}={v}" for k, v in kv).encode()


_PANOS_COLS: list[str] | None = None


def _panos_cols() -> list[str]:
    global _PANOS_COLS
    if _PANOS_COLS is None:
        # a source-tree asset next to the code (not deployment state under ULPF_HOME)
        src = Path(__file__).resolve().parent.parent
        ref = json.loads((src / "verification" / "vendor_refs" / "panos-11.1-traffic-log-format.json").read_text())
        _PANOS_COLS = ref["column_names"]
    return _PANOS_COLS


def panos_traffic(f: Flow, *, device: str = "PA-VM-01", serial: str = "007200001056") -> bytes:
    """PAN-OS 11.1 TRAFFIC log: RFC 3164 header + documented 130-column CSV.

    Column order: PAN-OS 11.1 "Traffic Log Fields" (verification/vendor_refs/
    panos-11.1-traffic-log-format.json). Unused columns are left empty.
    ASSUMPTION: `proto` carries the protocol name (the docs say only "IP
    protocol associated with the session").
    """
    allow = f.action == "allow"
    ts = f.time.strftime("%Y/%m/%d %H:%M:%S")
    v = {c: "" for c in _panos_cols()}
    v.update({
        "future_use_1": "1", "receive_time": ts, "serial": serial, "type": "TRAFFIC",
        "subtype": "end" if allow else "deny", "time_generated": ts, "src": f.src_ip, "dst": f.dst_ip,
        "rule": "allow-outbound" if allow else "default-deny", "app": {"tcp": "ssl", "udp": "dns", "icmp": "ping"}[f.proto],
        "vsys": "vsys1", "from": "trust", "to": "untrust", "inbound_if": "ethernet1/1", "outbound_if": "ethernet1/2",
        "logset": "default", "sessionid": str(f.session_id), "repeatcnt": "1", "sport": str(f.src_port),
        "dport": str(f.dst_port), "natsport": "0", "natdport": "0", "flags": "0x400000", "proto": f.proto,
        "action": "allow" if allow else "deny", "bytes": str(f.bytes_out + f.bytes_in), "bytes_sent": str(f.bytes_out),
        "bytes_received": str(f.bytes_in), "packets": str(f.packets_out + f.packets_in), "start": ts, "elapsed": "12",
        "category": "any", "seqno": str(7000000 + f.session_id), "actionflags": "0x8000000000000000",
        "srcloc": "10.0.0.0-10.255.255.255", "dstloc": "US", "pkts_sent": str(f.packets_out),
        "pkts_received": str(f.packets_in), "session_end_reason": "tcp-fin" if allow else "policy-deny",
        "vsys_name": "", "device_name": device,
        "high_res_timestamp": f.time.strftime("%Y-%m-%dT%H:%M:%S.") + f"{f.time.microsecond // 1000:03d}+00:00",
    })
    header = f"<14>{f.time.strftime('%b')} {f.time.day:2d} {f.time.strftime('%H:%M:%S')} {device} "
    return (header + ",".join(v[c] for c in _panos_cols())).encode()


def asa_connection(f: Flow, *, phase: str = "teardown") -> bytes:
    """Cisco ASA 302013/302014 (TCP) and 302015/302016 (UDP).

    Templates: Cisco Secure Firewall ASA syslog guide, messages 302003-342008
    (verification/vendor_refs/cisco-asa-302013-302016.json).
    ASSUMPTIONS (synthetic): header "<PRI>MMM dd yyyy HH:MM:SS: " and that the
    "for" socket is the initiator. The docs do not define which socket is the
    initiator, so the ULPF spec sets is_src_dst_assignment_known=false.
    """
    tcp = f.proto == "tcp"
    mid = ("302013" if tcp else "302015") if phase == "build" else ("302014" if tcp else "302016")
    proto = "TCP" if tcp else "UDP"
    ts = f.time.strftime("%b %d %Y %H:%M:%S")
    a = f"inside:{f.src_ip}/{f.src_port} ({f.src_ip}/{f.src_port})"
    b = f"outside:{f.dst_ip}/{f.dst_port} ({f.dst_ip}/{f.dst_port})"
    if phase == "build":
        body = f"Built outbound {proto} connection {f.session_id} for {a} to {b}"
    else:
        a = f"inside:{f.src_ip}/{f.src_port}"
        b = f"outside:{f.dst_ip}/{f.dst_port}"
        body = f"Teardown {proto} connection {f.session_id} for {a} to {b} duration 0:00:12 bytes {f.bytes_out + f.bytes_in}"
        if tcp:
            body += " TCP FINs"
    return f"<166>{ts}: %ASA-6-{mid}: {body}".encode()


def pfsense_filterlog(f: Flow) -> bytes:
    """pfSense filterlog over syslog (default BSD format: no hostname).

    Field order: Netgate "Raw Filter Log Format" BNF (IPv4 + TCP/UDP).
    """
    action = {"allow": "pass", "deny": "block"}[f.action]
    v4 = ["0x0", "", "64", str(f.session_id % 65535), "0", "DF", str(f.proto_num), f.proto]
    common = ["5", "", "", "1000000103", "em0", "match", action, "in", "4"]
    ipd = [str(60 + (f.bytes_out % 1400)), f.src_ip, f.dst_ip]
    if f.proto == "tcp":
        pd = [str(f.src_port), str(f.dst_port), "0", "S", str(1000 + f.session_id), "", "64240", "", "mss;sackOK;TS;nop;wscale"]
    elif f.proto == "udp":
        pd = [str(f.src_port), str(f.dst_port), str(f.bytes_out % 512)]
    else:
        pd = ["request", "1234", "1"]
    hdr = f"<134>{f.time.strftime('%b')} {f.time.day:2d} {f.time.strftime('%H:%M:%S')} filterlog[{30000 + f.session_id % 9999}]: "
    return (hdr + ",".join(common + v4 + ipd + pd)).encode()


def zeek_conn(f: Flow) -> bytes:
    """Zeek conn.log, JSON writer. Fields: Zeek manual "conn.log" + Conn::Info."""
    state = "SF" if f.action == "allow" else "REJ"
    uid = "C" + format(f.session_id * 2654435761 % (1 << 64), "x").rjust(17, "0")[:17]
    rec = {"ts": round(f.time.timestamp(), 6), "uid": uid, "id.orig_h": f.src_ip, "id.orig_p": f.src_port,
           "id.resp_h": f.dst_ip, "id.resp_p": f.dst_port, "proto": f.proto,
           "service": {"tcp": "ssl", "udp": "dns", "icmp": None}[f.proto], "duration": 12.5,
           "orig_bytes": max(0, f.bytes_out - 40 * f.packets_out), "resp_bytes": max(0, f.bytes_in - 40 * f.packets_in),
           "conn_state": state, "missed_bytes": 0, "history": "ShADadFf" if state == "SF" else "Sr",
           "orig_pkts": f.packets_out, "orig_ip_bytes": f.bytes_out, "resp_pkts": f.packets_in,
           "resp_ip_bytes": f.bytes_in, "ip_proto": f.proto_num}
    rec = {k: v for k, v in rec.items() if v is not None}
    return json.dumps(rec, separators=(",", ":")).encode()


def _suricata_ts(t: _dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond:06d}+0000"


def suricata_flow(f: Flow) -> bytes:
    """Suricata EVE JSON, event_type flow (docs.suricata.io, Eve JSON Format)."""
    rec = {"timestamp": _suricata_ts(f.time), "flow_id": 1000000000000 + f.session_id, "in_iface": "eth0",
           "event_type": "flow", "src_ip": f.src_ip, "src_port": f.src_port, "dest_ip": f.dst_ip,
           "dest_port": f.dst_port, "proto": f.proto.upper(), "app_proto": {"tcp": "tls", "udp": "dns", "icmp": "failed"}[f.proto],
           "flow": {"pkts_toserver": f.packets_out, "pkts_toclient": f.packets_in, "bytes_toserver": f.bytes_out,
                    "bytes_toclient": f.bytes_in, "start": _suricata_ts(f.time), "end": _suricata_ts(f.time), "age": 12,
                    "state": "closed", "reason": "timeout", "alerted": False,
                    "action": "pass" if f.action == "allow" else "drop"}}
    return json.dumps(rec, separators=(",", ":")).encode()


def suricata_alert(f: Flow, *, sid: int = 9000001, signature: str = "ULPF SYNTHETIC test signature") -> bytes:
    """Suricata EVE JSON, event_type alert. The signature is fictional (synthetic)."""
    rec = {"timestamp": _suricata_ts(f.time), "flow_id": 1000000000000 + f.session_id, "in_iface": "eth0",
           "event_type": "alert", "src_ip": f.src_ip, "src_port": f.src_port, "dest_ip": f.dst_ip,
           "dest_port": f.dst_port, "proto": f.proto.upper(),
           "alert": {"action": "allowed" if f.action == "allow" else "blocked", "gid": 1, "signature_id": sid, "rev": 1,
                     "signature": signature, "category": "Attempted Information Leak", "severity": 2}}
    return json.dumps(rec, separators=(",", ":")).encode()


def squid_access(f: Flow) -> bytes:
    """Squid native access.log ("squid" format, wiki.squid-cache.org/Features/LogFormat).

    Print format: "%9d.%03d %6d %s %s/%03d %d %s %s %s %s%s/%s %s"; hosts use
    RFC 2606 example domains.
    """
    ts = f"{int(f.time.timestamp()):9d}.{f.time.microsecond // 1000:03d}"
    if f.action == "deny":
        code, status, method, url, hier, ctype = "TCP_DENIED", 403, "GET", "http://blocked.example.net/", "HIER_NONE/-", "text/html"
    elif f.dst_port == 443:
        code, status, method, url, hier, ctype = "TCP_TUNNEL", 200, "CONNECT", f"www.example.com:443", f"HIER_DIRECT/{f.dst_ip}", "-"
    else:
        code, status, method, url, hier, ctype = "TCP_MISS", 200, "GET", f"http://www.example.org/p/{f.session_id}", f"HIER_DIRECT/{f.dst_ip}", "text/html"
    return f"{ts} {120:6d} {f.src_ip} {code}/{status:03d} {f.bytes_in} {method} {url} - {hier} {ctype}".encode()


def unknown_blackbox(f: Flow) -> bytes:
    """A fictional vendor ("Blackbox Gateway") used for live onboarding demos.

    Clearly fictional; it imitates no real product. Pipe-separated header +
    semicolon-separated key:value body, so no generic parser recognises it.
    """
    verdict = {"allow": "PERMIT", "deny": "DROP"}[f.action]
    ts = f.time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return (f"BBX1|{ts}|gw-07|FLOW|{verdict}|src:{f.src_ip};sport:{f.src_port};dst:{f.dst_ip};"
            f"dport:{f.dst_port};proto:{f.proto.upper()};tx:{f.bytes_out};rx:{f.bytes_in};rule:R{f.rule}").encode()


MALFORMED: list[bytes] = [
    b"",                                            # empty frame
    b"   ",                                         # whitespace only
    b"{\"broken\": json",                           # malformed JSON
    b"\xff\xfe\x00 binary \x80\x81 garbage",        # invalid UTF-8 + NUL
    b"<999>not really syslog",                      # out-of-range PRI
    b"CEF:0|truncated",                             # malformed CEF
]

RENDERERS: dict[str, Callable[[Flow], bytes]] = {
    "fortigate": fortigate_traffic,
    "panos": panos_traffic,
    "asa": asa_connection,
    "pfsense": pfsense_filterlog,
    "zeek": zeek_conn,
    "suricata": suricata_flow,
    "suricata_alert": suricata_alert,
    "squid": squid_access,
    "blackbox": unknown_blackbox,
}


# ------------------------------------------------------------------ sending
@dataclass
class SendLog:
    path: Path
    # line-buffered for rate-limited runs (live demo: the file is read while
    # sending, and a stopped generator must not lose its buffered tail);
    # block-buffered at full speed, where a write per event would cost throughput
    line_buffered: bool = False

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a", encoding="utf-8", buffering=1 if self.line_buffered else -1)  # noqa: SIM115

    def record(self, payload: bytes, *, transport: str, kind: str, truth: dict | None = None) -> None:
        rec = {"sha256": hashlib.sha256(payload).hexdigest(), "len": len(payload), "transport": transport,
               "kind": kind, "sent_at": time.time()}
        if truth is not None:
            rec["truth"] = truth
        self._fh.write(json.dumps(rec) + "\n")

    def close(self) -> None:
        self._fh.close()


def _addr(a: str) -> tuple[str, int]:
    h, _, p = a.rpartition(":")
    return h, int(p)


class Sender:
    """Sends payloads with one transport. TCP framing: newline or RFC 6587 octet counting."""

    def __init__(self, transport: str, address: str, log: SendLog | None = None):
        self.transport, self.address, self.log = transport, address, log
        self._sock: socket.socket | None = None
        if transport == "udp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif transport in ("tcp", "tcp-octet"):
            self._sock = socket.create_connection(_addr(address), timeout=10)
        elif transport != "http":
            raise ValueError(f"unknown transport {transport}")
        self._http_buf: list[bytes] = []

    def send(self, payload: bytes, *, kind: str, truth: dict | None = None) -> None:
        if self.transport == "udp":
            assert self._sock
            self._sock.sendto(payload, _addr(self.address))
        elif self.transport == "tcp":
            if b"\n" in payload:
                raise ValueError("newline-framed TCP cannot carry payloads containing \\n; use tcp-octet")
            assert self._sock
            self._sock.sendall(payload + b"\n")
        elif self.transport == "tcp-octet":
            assert self._sock
            self._sock.sendall(str(len(payload)).encode() + b" " + payload)
        else:
            self._http_buf.append(payload)
        if self.log:
            self.log.record(payload, transport=self.transport, kind=kind, truth=truth)

    def close(self) -> None:
        if self.transport == "http" and self._http_buf:
            body = b"\n".join(self._http_buf) + b"\n"
            req = urllib.request.Request(f"http://{self.address}/", data=body, method="POST",
                                         headers={"Content-Type": "application/x-ndjson"})
            with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 (local collector)
                r.read()
        if self._sock:
            self._sock.close()


def rate_limited(items: Iterable, eps: float | None) -> Iterable:
    """Yield items at roughly `eps` per second (None = as fast as possible)."""
    if not eps:
        yield from items
        return
    interval = 1.0 / eps
    start = time.perf_counter()
    for i, it in enumerate(items):
        target = start + i * interval
        delay = target - time.perf_counter()
        if delay > 0:
            time.sleep(delay)
        yield it


def send_scenario(scenario: str, *, vendors: list[str], count: int, transport: str, addr: str,
                  eps: float | None = None, seed: int = 1, log: SendLog | None = None) -> int:
    """Send `count` events. Returns the number sent.

    mixed     random flows rendered round-robin by the given vendors
    portscan  one internal host probing many ports of one target (anomaly
              scenario), interleaved 1:3 with normal mixed traffic
    malformed the MALFORMED corpus (cycled)
    """
    rng = random.Random(seed)
    for v in vendors:
        if v not in RENDERERS:
            raise ValueError(f"unknown vendor renderer {v!r}; known: {sorted(RENDERERS)}")
    snd = Sender(transport, addr, log)
    sent = 0

    def items():
        scanner, target = "10.66.6.6", "10.1.50.20"
        base = _dt.datetime.now(_dt.timezone.utc)
        for i in range(count):
            vendor = vendors[i % len(vendors)]
            if scenario == "malformed":
                p = MALFORMED[i % len(MALFORMED)]
                if transport in ("tcp", "http") and p == b"":
                    p = b"(empty-frame-replaced)"
                yield p, "malformed", None
                continue
            if scenario == "portscan" and i % 4 == 0:
                f = Flow(src_ip=scanner, src_port=rng.randint(40000, 60000), dst_ip=target,
                         dst_port=1 + (i // 4) % 1024, proto="tcp", action="deny",
                         time=base + _dt.timedelta(milliseconds=i), session_id=rng.randint(1, 4_000_000))
            else:
                f = random_flow(rng, when=base + _dt.timedelta(milliseconds=i))
            yield RENDERERS[vendor](f), vendor, f.truth()

    try:
        for payload, kind, truth in rate_limited(items(), eps):
            snd.send(payload, kind=kind, truth=truth)
            sent += 1
    finally:
        snd.close()
    return sent
