"""Scenario 2 - cross-vendor equivalence against the RUNNING stack.

The same ground-truth flows are rendered in six vendor formats (FortiGate,
PAN-OS, pfSense, Cisco ASA, Suricata, Zeek), sent through Vector, and must
produce equivalent normalized OCSF semantics. One vendor-neutral OpenSearch
query must find every vendor's rendering.

Vendor-specific limits that the comparison respects (documented in the specs):
* ASA: initiator/responder not asserted (is_src_dst_assignment_known=false),
  so endpoints are compared as an unordered pair; header time has seconds only.
* pfSense: packet-level log; time has seconds only; no session byte counts.
* Zeek: passive sensor -> no firewall action.
"""
import datetime as dt
import json
import random
import time

import pytest

from ulpf import gen
from ulpf.opensearch import Client
from ulpf.settings import load

pytestmark = [pytest.mark.vector, pytest.mark.opensearch]

VENDORS = {
    "fortigate": "fortinet.fortigate.traffic",
    "panos": "paloalto.panos.traffic",
    "pfsense": "netgate.pfsense.filterlog",
    "asa": "cisco.asa.connection",
    "suricata": "oisf.suricata.flow",
    "zeek": "zeek.zeek.conn",
}
SECOND_PRECISION = {"asa", "pfsense"}
NO_ACTION = {"zeek", "asa"}          # ASA 302014 is a teardown of a permitted connection only


def _flows(n: int, seed: int) -> list[gen.Flow]:
    rng = random.Random(seed)
    base = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(seconds=30)
    out = []
    for i in range(n):
        f = gen.random_flow(rng, when=base + dt.timedelta(seconds=i, milliseconds=rng.randint(0, 999)),
                            action="allow" if i % 3 else "deny")
        if f.proto == "icmp":
            f.proto = "tcp"
        out.append(f)
    return out


@pytest.fixture(scope="module")
def delivered():
    import urllib.request

    s = load()
    try:
        urllib.request.urlopen(f"http://{s['vector']['api_address']}/health", timeout=2)
    except Exception:  # noqa: BLE001
        pytest.skip("live Vector not running")
    flows = _flows(12, seed=int(time.time()) % 100000)
    sent = []   # (vendor, flow, sha256)
    snd = gen.Sender("tcp", s["listen"]["syslog_tcp"])
    import hashlib

    for f in flows:
        for v in VENDORS:
            if v == "asa" and f.action == "deny":
                continue  # 106023 (deny) is not supported: its format is UNVERIFIED
            p = gen.RENDERERS[v](f)
            snd.send(p, kind=v)
            sent.append((v, f, hashlib.sha256(p).hexdigest()))
    snd.close()
    time.sleep(8)
    c = Client.from_settings()
    c.refresh(s["opensearch"]["read_alias"])
    docs = {}
    for v, f, sha in sent:
        hits = c.search("ulpf-events", {"query": {"term": {"raw_data_hash.value": sha}}})["hits"]["hits"]
        docs[(v, f.session_id)] = hits[0]["_source"] if hits else None
    return flows, sent, docs, c


def test_every_rendering_was_parsed_by_its_vendor_spec(delivered):
    flows, sent, docs, _ = delivered
    bad = {}
    for v, f, _ in sent:
        d = docs[(v, f.session_id)]
        if d is None or d["ulpf"]["status"] != "parsed" or d["ulpf"]["parser"]["id"] != VENDORS[v]:
            bad[f"{v}/{f.session_id}"] = None if d is None else (d["ulpf"]["status"], d["ulpf"].get("parser"), d["ulpf"].get("errors"))
    assert not bad, bad


def test_equivalent_semantics_across_vendors(delivered):
    flows, sent, docs, _ = delivered
    mismatches = []
    for v, f, _ in sent:
        d = docs[(v, f.session_id)]
        got_pair = {(d["src_endpoint"]["ip"], d["src_endpoint"].get("port")), (d["dst_endpoint"]["ip"], d["dst_endpoint"].get("port"))}
        want_pair = {(f.src_ip, f.src_port), (f.dst_ip, f.dst_port)}
        if v == "asa":
            ok_ep = got_pair == want_pair and d["is_src_dst_assignment_known"] is False
        else:
            ok_ep = (d["src_endpoint"]["ip"], d["src_endpoint"].get("port"), d["dst_endpoint"]["ip"], d["dst_endpoint"].get("port")) == \
                    (f.src_ip, f.src_port, f.dst_ip, f.dst_port)
        ok_proto = (d["connection_info"]["protocol_name"], d["connection_info"]["protocol_num"]) == (f.proto, f.proto_num)
        want_ms = int(f.time.timestamp() * 1000)
        ok_time = (d["time"] // 1000 == want_ms // 1000) if v in SECOND_PRECISION else d["time"] == want_ms
        ok_action = True
        if v not in NO_ACTION:
            ok_action = d["action_id"] == {"allow": 1, "deny": 2}[f.action]
        if not (ok_ep and ok_proto and ok_time and ok_action):
            mismatches.append((v, f.session_id, ok_ep, ok_proto, ok_time, ok_action))
    assert not mismatches, mismatches


def test_one_vendor_neutral_query_finds_all_vendors(delivered):
    flows, sent, docs, c = delivered
    f = next(x for x in flows if x.action == "allow")
    q = {"bool": {"filter": [
        {"term": {"dst_endpoint.port": f.dst_port}},
        {"term": {"connection_info.protocol_name": f.proto}},
        {"bool": {"should": [{"term": {"src_endpoint.ip": f.src_ip}}, {"term": {"dst_endpoint.ip": f.src_ip}}],
                  "minimum_should_match": 1}},
    ]}}
    hits = c.search("ulpf-events", {"size": 50, "query": q})["hits"]["hits"]
    products = {h["_source"]["metadata"]["product"]["name"] for h in hits}
    assert products >= {"FortiGate", "PAN-OS", "pfSense", "Secure Firewall ASA", "Suricata", "Zeek"}, products


def test_denied_traffic_is_denied_for_every_firewall(delivered):
    flows, sent, docs, c = delivered
    for f in (x for x in flows if x.action == "deny"):
        for v in ("fortigate", "panos", "pfsense", "suricata"):
            d = docs[(v, f.session_id)]
            assert d["action_id"] == 2, (v, d["action"], d.get("disposition"))
