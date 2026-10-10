"""Scenario 7 - Sigma rules over the normalized index, cross-checked.

Every rule's OpenSearch hit count (pySigma -> Lucene through the ULPF
pipeline) must equal an independent Python evaluation of the same logic over
the documents themselves; one rule must match several vendors.
"""
import ipaddress

import pytest

from ulpf.detect import run_sigma
from ulpf.opensearch import Client
from ulpf.settings import load

pytestmark = [pytest.mark.opensearch]
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _private(ip):
    try:
        return any(ipaddress.ip_address(ip) in n for n in PRIVATE)
    except (TypeError, ValueError):
        return False


def _g(d, *path):
    for k in path:
        d = (d or {}).get(k)
    return d


ORACLE = {
    "Denied RDP connection attempt (any firewall vendor)":
        lambda d: d.get("class_uid") == 4001 and _g(d, "dst_endpoint", "port") == 3389 and d.get("action_id") == 2,
    "Allowed SSH to a non-private address":
        lambda d: d.get("class_uid") == 4001 and _g(d, "dst_endpoint", "port") == 22 and d.get("action_id") == 1
        and not _private(_g(d, "dst_endpoint", "ip")),
    "Cleartext syslog sent outside the network":
        lambda d: d.get("class_uid") == 4001 and _g(d, "dst_endpoint", "port") == 514
        and _g(d, "connection_info", "protocol_name") == "udp" and d.get("action_id") == 1 and not _private(_g(d, "dst_endpoint", "ip")),
    "IDS alert observed in network traffic": lambda d: d.get("class_uid") == 4001 and d.get("is_alert") is True,
    "Events from an unknown source (no approved parser)": lambda d: _g(d, "ulpf", "status") == "fallback",
}


def test_sigma_hits_equal_independent_evaluation():
    s = load()
    c = Client.from_settings(s)
    idx = s["opensearch"]["read_alias"]
    c.refresh(idx)
    docs = [h["_source"] for h in c.scroll_all(idx, None, source=["class_uid", "dst_endpoint", "action_id",
                                                                   "connection_info.protocol_name", "is_alert", "ulpf.status",
                                                                   "metadata.product.name"])]
    if not docs:
        pytest.skip("empty index")
    res = {r["title"]: r for r in run_sigma(c, idx)}
    assert set(res) == set(ORACLE)
    for title, pred in ORACLE.items():
        want = sum(1 for d in docs if pred(d))
        assert res[title]["hits"] == want, (title, res[title]["hits"], want)
    multi = [t for t, r in res.items() if len(r["products"]) >= 2]
    assert multi, "no rule matched more than one vendor (send mixed traffic first: ulpf gen --vendor fortigate --vendor panos)"
