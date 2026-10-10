"""Detections without OpenSearch: Sigma conversion and anomaly ranking.

Events are SYNTHETIC TEST DATA built from ulpf.gen flows.
"""
import datetime as dt
import random

from ulpf import gen
from ulpf.detect import detect_anomalies, evaluate, sigma_queries


def test_every_sigma_rule_converts_to_ocsf_fields():
    qs = sigma_queries()
    assert len(qs) == 5 and all(len(q["queries"]) == 1 for q in qs)
    by = {q["title"]: q["queries"][0] for q in qs}
    rdp = by["Denied RDP connection attempt (any firewall vendor)"]
    assert rdp == "class_uid:4001 AND (dst_endpoint.port:3389 AND action_id:2)"
    for q in by.values():
        assert "dst_port" not in q and "src_ip" not in q    # rule names mapped to OCSF paths


def _ev(f, t_ms):
    return {"time": t_ms, "src_endpoint": {"ip": f.src_ip}, "dst_endpoint": {"ip": f.dst_ip, "port": f.dst_port},
            "action_id": 2 if f.action == "deny" else 1, "metadata": {"uid": f"u{t_ms}"}}


def test_isolation_forest_ranks_port_scanner_first():
    rng = random.Random(5)
    base = dt.datetime(2026, 10, 7, 12, 0, tzinfo=dt.timezone.utc)
    events = []
    for i in range(3000):
        t = int((base + dt.timedelta(milliseconds=40 * i)).timestamp() * 1000)
        if i % 4 == 0:
            f = gen.Flow(src_ip="10.66.6.6", src_port=50000, dst_ip="10.1.50.20", dst_port=1 + (i // 4) % 1024, proto="tcp",
                         action="deny", time=base, session_id=i)
        else:
            f = gen.random_flow(rng, when=base)
        events.append(_ev(f, t))
    rep = detect_anomalies(events, window_s=60)
    ev = evaluate(rep, "10.66.6.6")
    assert ev["scanner_rank"] == 1, rep["flagged"][:3]
    assert ev["other_windows_flagged"] / rep["windows"] < 0.05
    top = rep["flagged"][0]
    assert top["src_ip"] == "10.66.6.6" and "distinct_dst_ports" in top["explanation"]


def test_anomaly_needs_enough_windows():
    assert detect_anomalies([], window_s=60)["flagged"] == []
