"""Onboarding: inference, mining, suggestions (incl. LLM validation), drafts.

All samples are SYNTHETIC TEST DATA (ulpf.gen renderers, RFC 5737/1918
addresses, a fictional vendor).
"""
import datetime as dt
import http.server
import json
import random
import re
import threading

import pytest

from ulpf import gen
from ulpf.onboard import suggest
from ulpf.onboard.draft import OnboardError, minimal_profiles, propose, write
from ulpf.onboard.infer import infer_structure, infer_type, stats_for
from ulpf.onboard.mining import mine, template_pattern
from ulpf.onboard.promote import PromoteError, approved_text, promote
from ulpf.onboard.store import Cluster, RawSample, clusters, spread
from ulpf.ocsf import default as default_ocsf
from ulpf.spec import lint_file, load
from ulpf.yamlsafe import load_text


def _flows(n, seed=3):
    rng = random.Random(seed)
    base = dt.datetime(2026, 10, 7, 12, 0, 0, tzinfo=dt.timezone.utc)
    return [gen.random_flow(rng, when=base + dt.timedelta(seconds=i, milliseconds=rng.randint(0, 999)),
                            action="allow" if i % 3 else "deny") for i in range(n)]


def _blackbox(n=40, seed=3):
    flows = _flows(n, seed)
    return flows, [gen.unknown_blackbox(f) for f in flows]


def _pres(raws):
    samples, pres = [], {}
    for i, raw in enumerate(raws):
        uid = f"00000000-0000-7000-8000-{i:012d}"
        samples.append(RawSample(uid, raw, {"event_uid": uid}))
        pres[uid] = {"event_uid": uid, "format": "text", "fingerprint": "f" * 16, "oversized": False,
                     "integrity_error": None, "pre": {"body": raw.decode()}}
    return samples, pres


# ------------------------------------------------------------------ infer
@pytest.mark.parametrize("values,want", [
    (["10.0.0.1", "2001:db8::1"], ("ip", None)),
    (["22", "443", "65535"], ("int_small", None)),
    (["70000", "1"], ("long", None)),
    (["2026-10-07T03:11:27.690Z", "2026-10-07T03:11:28Z"], ("timestamp", "rfc3339")),
    (["1791342687", "1791342688123"], ("timestamp", "epoch_auto")),
    (["00:11:22:33:44:55"], ("mac", None)),
    (["PERMIT", "DROP"], ("string", None)),
    (["", "-"], ("string", None)),
])
def test_infer_type(values, want):
    assert infer_type(values) == want


def test_infer_structure_finds_header_plus_kv_payload():
    _, raws = _blackbox()
    lines = [r.decode() for r in raws]
    st = infer_structure(lines)
    assert (st.kind, st.delimiter, st.kv_field_delim, st.kv_value_delim) == ("delimited_kv", "|", ";", ":")
    assert all(re.match(st.extract, ln) for ln in lines)
    recs = st.records(lines)
    assert {"h0", "h1", "h4", "src", "sport", "dst", "dport", "proto", "tx", "rx", "rule"} <= set(recs[0])


def test_template_pattern_matches_and_captures():
    msgs = [f"Connection from 10.0.0.{i} port {1000 + i} user=u{i} ok" for i in range(20)]
    tpl = mine(msgs)
    assert tpl[0].count == 20
    pat, groups = template_pattern(tpl[0].text)
    for i, m in enumerate(msgs):
        mm = re.match(pat, m)
        assert mm, (pat, m)
        assert f"10.0.0.{i}" in mm.groupdict().values()
    assert "(?=" not in pat and "(?!" not in pat  # VRL (Rust regex) compatible


# ------------------------------------------------------------- suggestions
def test_suggestions_require_compatible_value_types():
    recs = [{"src": "not-an-ip", "dport": "70000", "dst": "203.0.113.5", "sport": "1234"}] * 5
    s = {x.source: x for x in suggest.deterministic(stats_for(recs), "network_activity", [])}
    assert "src" not in s            # name matches, values are not IPs
    assert "dport" not in s          # out of port range -> not a port
    assert s["dst"].to == "dst_endpoint.ip" and s["sport"].to == "src_endpoint.port"


def test_action_enum_detected_by_values_not_names():
    st = stats_for([{"h4": v} for v in ("PERMIT", "DROP", "PERMIT")])
    e = suggest.action_enum(st, "network_activity")
    assert e["enum"]["source"] == "h4"
    assert e["enum"]["map"]["PERMIT"] == {"action_id": 1, "disposition_id": 1, "activity_id": 6}
    assert e["enum"]["map"]["DROP"]["action_id"] == 2
    assert "no name evidence" in e["reasons"][0]
    assert suggest.action_enum(stats_for([{"h4": v} for v in ("alpha", "beta")]), "network_activity") is None


class _Stub(http.server.BaseHTTPRequestHandler):
    reply: dict = {}
    seen: list = []

    def do_POST(self):  # noqa: N802
        n = int(self.headers["Content-Length"])
        _Stub.seen.append(json.loads(self.rfile.read(n)))
        body = json.dumps(_Stub.reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def llm_stub(monkeypatch):
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Stub)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    monkeypatch.setenv("ULPF_LLM_URL", f"http://127.0.0.1:{srv.server_port}/v1/chat/completions")
    _Stub.seen = []
    yield _Stub
    srv.shutdown()


def _llm_reply(items):
    return {"choices": [{"message": {"content": "Sure! Here is the mapping:\n" + json.dumps(items)}}]}


def test_llm_suggestions_are_validated_and_capped(llm_stub):
    llm_stub.reply = _llm_reply([
        {"source": "h2", "to": "device.hostname", "confidence": 0.99, "reason": "gateway name"},   # valid
        {"source": "h2", "to": "device.host_name", "confidence": 0.9},                            # invented path
        {"source": "tx", "to": "src_endpoint.ip", "confidence": 0.9},                             # type mismatch
        {"source": "nosuch", "to": "message", "confidence": 0.9},                                 # unknown field
        {"source": "h4", "to": "action_id", "confidence": 0.9},                                   # enum: never direct
        {"source": "h3", "to": "src_endpoint.ip.addr", "confidence": 0.9},                        # descends into scalar
    ])
    st = stats_for([{"h2": "gw-07", "tx": "1200", "h4": "PERMIT", "h3": "FLOW"}] * 4)
    out = suggest.llm_suggestions(st, "network_activity", ["host", "security_control"])
    assert [(s.source, s.to, s.origin) for s in out] == [("h2", "device.hostname", "llm")]
    assert out[0].confidence == 0.8                # never above deterministic evidence
    assert llm_stub.seen and llm_stub.seen[0]["temperature"] == 0


def test_llm_must_be_local(monkeypatch):
    monkeypatch.setenv("ULPF_LLM_URL", "https://api.example.com/v1/chat/completions")
    with pytest.raises(ValueError, match="local endpoint"):
        suggest.llm_suggestions(stats_for([{"a": "b"}]), "network_activity", [])


def test_llm_off_without_url(monkeypatch):
    monkeypatch.delenv("ULPF_LLM_URL", raising=False)
    assert not suggest.llm_enabled()
    assert suggest.llm_suggestions(stats_for([{"a": "b"}]), "network_activity", []) == []


# ------------------------------------------------------------------- drafts
def test_minimal_profiles():
    o = default_ocsf()
    assert minimal_profiles(o, "network_activity", ["src_endpoint.ip"]) == []
    assert minimal_profiles(o, "network_activity", ["src_endpoint.ip", "action_id"]) == ["security_control"]
    assert minimal_profiles(o, "network_activity", ["device.hostname"]) == ["host", "security_control"]


def test_propose_blackbox_draft_offline(tmp_path):
    flows, raws = _blackbox(40)
    samples, pres = _pres(raws)
    prop = propose(samples, pres, spec_id="acme.blackbox.flow", vendor="Blackbox (fictional)", product="Blackbox Gateway",
                   samples_kind="synthetic")
    d = prop.data
    assert d["status"] == "draft" and d["parse"]["kind"] == "kv" and d["parse"]["kv"] == {"field_delimiter": ";", "value_delimiter": ":"}
    assert d["fields"]["src"] == {"to": "src_endpoint.ip", "type": "ip"}
    assert d["fields"]["proto"] == {"to": "connection_info.protocol_name", "type": "string", "transform": "lower"}
    assert d["time"] == [{"field": "h1", "format": "rfc3339"}]
    assert d["enums"][0]["source"] == "h4"
    assert d["ocsf"]["profiles"] == ["security_control"]
    assert "h2" not in d["fields"]               # no evidence -> stays unmapped, reviewer decides
    # expectations are computed independently and agree with the generator's ground truth
    by_raw = {r.decode(): f for f, r in zip(flows, raws)}
    for t in d["tests"]:
        f, e = by_raw[t["raw"]], t["expect"]
        assert (e["src_endpoint.ip"], e["src_endpoint.port"], e["dst_endpoint.ip"], e["dst_endpoint.port"]) == \
               (f.src_ip, f.src_port, f.dst_ip, f.dst_port)
        assert e["connection_info.protocol_num"] == f.proto_num and e["traffic.bytes_out"] == f.bytes_out
        assert e["action_id"] == {"allow": 1, "deny": 2}[f.action]
        assert e["time"] == int(f.time.timestamp() * 1000)
    assert {t["expect"]["action_id"] for t in d["tests"]} == {1, 2}   # both verdicts covered
    path = write(prop, drafts_dir=tmp_path)
    assert load_text(path.read_text()) == json.loads(json.dumps(d))
    sp, issues = lint_file(path)
    assert [str(i) for i in issues if i.level == "error"] == []
    with pytest.raises(OnboardError, match="exists"):
        write(prop, drafts_dir=tmp_path)


def test_llm_suggestions_stay_inactive_in_draft(llm_stub, tmp_path):
    llm_stub.reply = _llm_reply([{"source": "h2", "to": "device.hostname", "confidence": 0.95, "reason": "looks like a host"}])
    _, raws = _blackbox(12)
    samples, pres = _pres(raws)
    prop = propose(samples, pres, spec_id="acme.blackbox.flow", vendor="V", product="P", samples_kind="synthetic", use_llm=True)
    assert "h2" not in prop.data["fields"]
    assert "# LLM SUGGESTION (unverified): h2: {to: device.hostname, type: string}" in prop.text
    assert prop.report["llm"]["used"] is True
    assert any(s["origin"] == "llm" and not s["active"] for s in prop.report["suggestions"])


def test_propose_rejects_bad_ids_and_tiny_clusters():
    _, raws = _blackbox(5)
    samples, pres = _pres(raws)
    with pytest.raises(OnboardError, match="vendor.product.logtype"):
        propose(samples, pres, spec_id="Bad Id", vendor="V", product="P", samples_kind="synthetic")
    with pytest.raises(OnboardError, match="at least 3"):
        propose(samples[:2], pres, spec_id="a.b.c", vendor="V", product="P", samples_kind="synthetic")


def test_clusters_and_spread():
    docs = [{"ulpf": {"fingerprint": fp, "format": "text", "event_uid": f"u{i}", "ingest": {"time_ms": i, "transport": "tcp"}},
             "metadata": {"uid": f"u{i}"}, "raw_data": "x"} for i, fp in enumerate("aabab")]
    cl = clusters(docs)
    assert [(c.fingerprint, c.count) for c in cl] == [("a", 3), ("b", 2)]
    assert cl[0].first_seen == 0 and cl[0].last_seen == 3
    assert spread(list(range(100)), 4) == [0, 25, 50, 75]


# ------------------------------------------------------------------ promote
def test_promote_requires_named_human(tmp_path):
    for who in ("", "llm", "auto", "AI", "x"):
        with pytest.raises(PromoteError, match="human approver"):
            promote(tmp_path / "nope.yaml", approver=who)


def test_approved_text_keeps_content_hash(tmp_path):
    _, raws = _blackbox(12)
    samples, pres = _pres(raws)
    prop = propose(samples, pres, spec_id="acme.blackbox.flow", vendor="V", product="P", samples_kind="synthetic")
    draft = write(prop, drafts_dir=tmp_path)
    text = approved_text(draft.read_text(), {"approved_by": "Jane Doe", "approved_at": "2026-10-07T12:00:00+00:00",
                                             "fingerprint": "f" * 16, "content_sha256": "x"})
    out = tmp_path / "approved.yaml"
    out.write_text(text)
    a, b = load(draft), load(out)
    assert b.data["status"] == "approved" and b.data["approval"]["approved_by"] == "Jane Doe"
    assert a.content_sha256 == b.content_sha256 and a.sha256 != b.sha256
    assert "NOT APPROVED" not in text
