"""Phase 1 vertical slice against the RUNNING stack (`ulpf stack up opensearch vector`).

generator -> UDP/TCP/HTTP -> Vector -> raw archive -> parse -> OCSF ->
normalized NDJSON + OpenSearch, then event accounting by UID and SHA-256.
"""
import json
import time

import pytest

from ulpf import gen, paths
from ulpf.accounting import reconcile
from ulpf.opensearch import Client
from ulpf.settings import load

pytestmark = [pytest.mark.vector, pytest.mark.opensearch]


def _vector_up() -> bool:
    import urllib.request

    try:
        with urllib.request.urlopen(f"http://{load()['vector']['api_address']}/health", timeout=2):
            return True
    except Exception:  # noqa: BLE001
        return False


@pytest.fixture(scope="module")
def sent(tmp_path_factory):
    if not _vector_up():
        pytest.skip("live Vector not running (ulpf stack up vector)")
    s = load()
    log_path = tmp_path_factory.mktemp("e2e") / "sendlog.ndjson"
    log = gen.SendLog(log_path)
    n = 0
    n += gen.send_scenario("mixed", vendors=["fortigate"], count=150, transport="udp", addr=s["listen"]["syslog_udp"], seed=101, log=log)
    n += gen.send_scenario("mixed", vendors=["fortigate", "blackbox"], count=100, transport="tcp", addr=s["listen"]["syslog_tcp"], seed=102, log=log)
    n += gen.send_scenario("malformed", vendors=["fortigate"], count=6, transport="udp", addr=s["listen"]["syslog_udp"], seed=103, log=log)
    n += gen.send_scenario("mixed", vendors=["fortigate"], count=50, transport="http", addr=s["listen"]["http_ndjson"], seed=104, log=log)
    log.close()
    time.sleep(6)
    return log_path, n


def test_accounting_sent_equals_archived_normalized_indexed(sent):
    log_path, n = sent
    rep = reconcile(log_path)
    assert rep["sent"] == n
    assert rep["verdict"] == "PASS", json.dumps(rep, indent=1)


def test_fortigate_semantics_match_ground_truth(sent):
    log_path, _ = sent
    truth = {}
    for line in open(log_path):
        r = json.loads(line)
        if r["kind"] == "fortigate":
            truth[r["sha256"]] = r["truth"]
    c = Client.from_settings()
    c.refresh(load()["opensearch"]["read_alias"])
    checked = 0
    for sha, t in list(truth.items())[:60]:
        hits = c.search("ulpf-events", {"query": {"term": {"raw_data_hash.value": sha}}})["hits"]["hits"]
        assert hits, f"event with raw sha256 {sha} not indexed"
        e = hits[0]["_source"]
        assert e["class_uid"] == 4001 and e["ulpf"]["status"] == "parsed"
        assert (e["src_endpoint"]["ip"], e["src_endpoint"]["port"], e["dst_endpoint"]["ip"], e["dst_endpoint"]["port"]) == \
               (t["src_ip"], t["src_port"], t["dst_ip"], t["dst_port"])
        assert e["connection_info"]["protocol_name"] == t["proto"]
        assert e["action_id"] == {"allow": 1, "deny": 2}[t["action"]]
        assert e["traffic"]["bytes_out"] == t["bytes_out"] and e["time"] == t["time_ms"]
        checked += 1
    assert checked >= 50


def test_unknown_and_malformed_are_visible_as_fallback(sent):
    c = Client.from_settings()
    n = c.count("ulpf-events", {"term": {"ulpf.status": "fallback"}})
    assert n > 0
    dlq = sum(1 for f in paths.DLQ.glob("*/dlq-*.ndjson") for _ in open(f))
    assert dlq >= n
