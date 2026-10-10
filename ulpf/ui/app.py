"""ULPF operator UI (Streamlit; bound to 127.0.0.1 by `ulpf stack up ui`).

Pages: Overview · Live feed · Event explorer (OCSF + provenance + original
bytes with a Merkle proof) · Unknown sources & onboarding · Archive integrity ·
Replay · Detections. Styling: ulpf/ui/theme.py and .streamlit/config.toml.

The page and text size live in the URL (?page=explorer&ts=lg), so every view
is a shareable link and the A-/A/A+ controls are plain links.

Reads OpenSearch (read alias), the raw archive and runtime state. The only
writes are explicit human actions: run a gate, promote a draft (named
approver + confirmation), verify the archive.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import time
import urllib.request

import streamlit as st

from ulpf import __version__, paths
from ulpf.opensearch import Client, OpenSearchError
from ulpf.settings import load
from ulpf.ui import theme

st.set_page_config(page_title="ULPF · Log pre-processing console", page_icon=":material/shield:", layout="wide",
                   initial_sidebar_state="collapsed")
S = load()
READ = S["opensearch"]["read_alias"]
WINDOWS = {"15 minutes": 15, "1 hour": 60, "24 hours": 1440, "all": None}
# Demo mode (ULPF_DEMO=1, e.g. `make demo-live`): the Live feed page gets controls that send
# SYNTHETIC TEST DATA through the live pipeline. Never set in a real deployment.
DEMO = os.environ.get("ULPF_DEMO") == "1"
LIVE_FIELDS = ["metadata.uid", "metadata.product.name", "class_name", "class_uid", "activity_name", "src_endpoint",
               "dst_endpoint", "connection_info.protocol_name", "action", "disposition", "device.hostname",
               "http_request.http_method", "raw_data", "ulpf.status", "ulpf.reasons", "ulpf.format", "ulpf.fingerprint",
               "ulpf.parser", "ulpf.coverage", "ulpf.lineage", "ulpf.ingest", "ulpf.raw.len", "ulpf.raw.sha256"]


@st.cache_resource
def client() -> Client:
    # least privilege: the UI only reads the index (ulpf-reader when secured)
    reader = paths.SECRETS / "opensearch-ulpf-reader.password"
    return Client.from_settings(S, role="ulpf-reader" if reader.exists() and S["opensearch"].get("security") else "admin")


def _since(minutes):
    if minutes is None:
        return []
    start = int((dt.datetime.now(dt.timezone.utc).timestamp() - minutes * 60) * 1000)
    return [{"range": {"time": {"gte": start}}}]


def _ts(ms):
    return dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if ms else ""


def _g(d, path):
    for k in path.split("."):
        d = d.get(k) if isinstance(d, dict) else None
    return d


def _health() -> dict:
    out = {}
    try:
        # a read the UI's own least-privilege role may make: `GET /` needs
        # cluster:monitor/main, which ulpf-reader does not have
        client().count(S["opensearch"]["read_alias"])
        out["opensearch"] = "healthy"
    except OpenSearchError as e:
        out["opensearch"] = f"HTTP {e.status}"
    except Exception as e:  # noqa: BLE001
        out["opensearch"] = f"down ({type(e).__name__})"
    try:
        with urllib.request.urlopen(f"http://{S['vector']['api_address']}/health", timeout=2) as r:  # noqa: S310 (loopback)
            out["vector"] = "healthy" if r.status == 200 else f"HTTP {r.status}"
    except Exception:  # noqa: BLE001
        out["vector"] = "down"
    return out


# ------------------------------------------------------------------ pages
def page_overview() -> None:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("OpenSearch", H["opensearch"], border=True)
    c2.metric("Vector", H["vector"], border=True)
    try:
        res = client().search(READ, {"size": 0, "track_total_hits": True, "aggs": {
            "status": {"terms": {"field": "ulpf.status"}},
            "product": {"terms": {"field": "metadata.product.name", "size": 30}}}})
    except Exception as e:  # noqa: BLE001
        st.error(f"OpenSearch query failed: {e}")
        return
    total = res["hits"]["total"]["value"]
    status = {b["key"]: b["doc_count"] for b in res["aggregations"]["status"]["buckets"]}
    c3.metric("Events indexed", f"{total:,}", border=True)
    c4.metric("Unknown (fallback)", f"{status.get('fallback', 0):,}", border=True)
    left, right = st.columns([3, 2], gap="medium")
    with left.container(border=True, key="card_products"):
        st.subheader("Events by product")
        products = {b["key"]: b["doc_count"] for b in res["aggregations"]["product"]["buckets"]}
        if products:
            st.altair_chart(theme.bar_chart(products, category="product", measure="events", text_size=TS), theme=None,
                            width="stretch")
        else:
            st.info("No events indexed yet.")
    with right.container(border=True, key="card_status"):
        st.subheader("Processing status")
        st.html(theme.status_rows([
            ("success", "Parsed", "Normalized by an approved spec", status.get("parsed", 0)),
            ("warning", "Partial", "Parsed with field errors; the values are kept in unmapped", status.get("partial", 0)),
            ("info", "Fallback", "Unknown source: kept as an OCSF Base Event and queued for onboarding",
             status.get("fallback", 0)),
            ("error", "Failed", "Not parsed (runtime error, oversized, integrity); the raw bytes are archived",
             status.get("failed", 0)),
        ], total))
    from ulpf.scorecard import build

    with st.container(border=True, key="card_scorecard"):
        st.subheader("Parser scorecard")
        with st.spinner("Computing the scorecard (schema-validates sample events per spec) ..."):
            sc = build()
        st.dataframe([{"spec": r["spec"], "version": r["version"], "class": r["class"], "overall": r["overall"],
                       **{k: (f"{v['value']:.1%}" if isinstance(v["value"], float) else str(v["value"]))
                          for k, v in r["metrics"].items()}}
                      for r in sc["specs"]], hide_index=True, width="stretch")
    dl = paths.STATE / "drift-last.json"
    if dl.exists():
        d = json.loads(dl.read_text())
        with st.container(border=True, key="card_drift"):
            st.subheader(f"Drift (last check {d['checked_at']}: {d['verdict']})")
            if d["signals"]:
                st.dataframe([{k: s[k] for k in ("severity", "spec_id", "kind", "message")} for s in d["signals"]],
                             hide_index=True, width="stretch")
            else:
                st.success("No drift signals at the last check.")


def page_live() -> None:
    if DEMO:
        _demo_card()
    _live_section()


def _hms(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, theme.IST).strftime("%H:%M:%S")


@st.fragment(run_every=2)
def _demo_card() -> None:
    from ulpf import demo

    stt = demo.status()
    running = stt["running"]
    with st.container(border=True, key="card_demo"):
        st.subheader("Demo traffic · synthetic test data")
        c1, c2, c3, c4 = st.columns([2.2, 1.3, 1.3, 1], vertical_alignment="bottom")
        eps = c1.slider("Events per second", 1, 20, 3, disabled=running, key="demo_eps")
        unknown = c2.toggle("Unknown-source logs", value=True, disabled=running, key="demo_unknown")
        malformed = c3.toggle("Malformed lines", value=True, disabled=running, key="demo_malformed")
        if running:
            if c4.button("Stop", type="primary", icon=":material/stop_circle:", width="stretch", key="demo_stop"):
                demo.stop()
                st.rerun(scope="fragment")
        elif c4.button("Start", type="primary", icon=":material/play_circle:", width="stretch", key="demo_start"):
            demo.start(eps, unknown=unknown, malformed=malformed)
            st.rerun(scope="fragment")
        if running:
            mix = (" + an unknown source" if stt.get("unknown") else "") + (" + malformed lines" if stt.get("malformed") else "")
            st.caption(f"Sending {stt['eps']:g} events/s from {len(demo.VENDORS)} vendors{mix} · started "
                       f"{_hms(stt['started_at'])} IST · {stt['sent']:,} sent · stops automatically at "
                       f"{_hms(stt['ends_at'])} IST")
        elif stt.get("started_at"):
            st.caption(f"Last demo started {_hms(stt['started_at'])} IST and sent {stt['sent']:,} events. "
                       "Press Start to run it again.")
        else:
            st.caption(f"Streams synthetic logs from the {len(demo.VENDORS)} supported vendors through the live pipeline, "
                       f"optionally with an unknown source and malformed lines. Stops automatically after "
                       f"{demo.MAX_MINUTES} minutes.")


def _live_query(since_ts: float) -> dict:
    since = dt.datetime.fromtimestamp(since_ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    feed = client().search(READ, {"size": 12, "sort": [{"ulpf.ingest.time": {"order": "desc"}}], "_source": LIVE_FIELDS,
                                  "query": {"match_all": {}}})
    # rate over the 10 s that ended 2 s ago: events become searchable 1-3 s after they are received
    agg = client().search(READ, {"size": 0, "track_total_hits": True,
                                 "query": {"range": {"ulpf.ingest.time": {"gte": since}}},
                                 "aggs": {"status": {"terms": {"field": "ulpf.status"}},
                                          "rate": {"filter": {"range": {"ulpf.ingest.time": {"gte": "now-12s", "lt": "now-2s"}}}}}})
    return {"events": [h["_source"] for h in feed["hits"]["hits"]], "total": agg["hits"]["total"]["value"],
            "status": {b["key"]: b["doc_count"] for b in agg["aggregations"]["status"]["buckets"]},
            "rate": agg["aggregations"]["rate"]["doc_count"] / 10, "updated": _hms(time.time())}


def _event_label(d: dict) -> str:
    return (f"{theme.ist_time(_g(d, 'ulpf.ingest.time'))} · {_g(d, 'metadata.product.name') or 'unknown'} · "
            f"{theme.status_view(_g(d, 'ulpf.status'))[1]}")


@st.fragment(run_every=1)
def _live_section() -> None:
    from ulpf import demo

    head = st.columns([5, 1], vertical_alignment="center")
    paused = head[1].toggle("Pause", key="live_paused", help="Freeze the page to talk through one event")
    cache = st.session_state.get("live_cache")
    if not paused or cache is None:
        stt = demo.status() if DEMO else {}
        started = stt.get("started_at")
        try:
            cache = _live_query(started or time.time() - 300)
        except Exception as e:  # noqa: BLE001
            st.error(f"OpenSearch query failed: {e}")
            return
        cache["window"] = "since the demo started" if started else "in the last 5 minutes"
        st.session_state["live_cache"] = cache
    head[0].caption(f"{'PAUSED' if paused else 'LIVE'} · updated {cache['updated']} IST · counts {cache['window']} · "
                    "refreshes every second")
    total, status = cache["total"], cache["status"]
    c = st.columns(5)
    c[0].metric("Events / second", f"{cache['rate']:.1f}", border=True)
    c[1].metric("Received", f"{total:,}", border=True)
    c[2].metric("Parsed", f"{status.get('parsed', 0) / total:.0%}" if total else "–", border=True)
    c[3].metric("Unrecognised · kept", f"{status.get('fallback', 0):,}", border=True)
    c[4].metric("Failed · kept", f"{status.get('failed', 0):,}", border=True)
    events = cache["events"]
    ages: dict[str, float] = {}
    if not paused:
        first = st.session_state.setdefault("live_first_seen", {})
        now, initial = time.time(), not first
        for d in events:      # on the first render nothing counts as new
            first.setdefault(_g(d, "metadata.uid"), now - (theme.FLASH_S if initial else 0))
        uids = {_g(d, "metadata.uid") for d in events}
        for uid in [u for u in first if u not in uids]:
            del first[uid]
        ages = {u: now - t for u, t in first.items()}
    with st.container(border=True, key="card_feed"):
        st.subheader("Latest events")
        st.html(theme.feed_rows(events, ages))
    if events:
        with st.container(border=True, key="card_steps"):
            st.subheader("Parsing, step by step")
            pick = 0
            if paused:
                pick = st.selectbox("Event", range(len(events)), format_func=lambda i: _event_label(events[i]),
                                    key="live_pick")
            else:
                st.caption("The newest event. Pause to pick another one from the feed.")
            st.html(theme.pipeline_steps(events[pick], ocsf=paths.OCSF_VERSION))


def page_explorer() -> None:
    with st.container(border=True, key="card_search"):
        q = st.text_input("Search query (Lucene syntax, OCSF field names)", value="*",
                          help="e.g. dst_endpoint.port:3389 AND action_id:2")
        c1, c2 = st.columns([1, 1])
        win = c1.selectbox("Time window", list(WINDOWS), index=3)
        size = c2.number_input("Max rows", 10, 2000, 200, step=50)
    body = {"size": int(size), "track_total_hits": True, "sort": [{"time": "desc"}],
            "query": {"bool": {"must": [{"query_string": {"query": q or "*", "analyze_wildcard": True}}],
                               "filter": _since(WINDOWS[win])}}}
    try:
        res = client().search(READ, body)
    except Exception as e:  # noqa: BLE001
        st.error(f"query failed: {e}")
        return
    hits = [h["_source"] for h in res["hits"]["hits"]]
    with st.container(border=True, key="card_results"):
        st.subheader("Results")
        st.caption(f"{res['hits']['total']['value']:,} matching event(s); showing {len(hits)}. Times are UTC.")
        rows = [{"time": _ts(d.get("time")), "product": _g(d, "metadata.product.name"), "class": d.get("class_name"),
                 "src": _g(d, "src_endpoint.ip"), "sport": _g(d, "src_endpoint.port"), "dst": _g(d, "dst_endpoint.ip"),
                 "dport": _g(d, "dst_endpoint.port"), "action": d.get("action"), "status": _g(d, "ulpf.status"),
                 "parser": _g(d, "ulpf.parser.id"), "event_uid": _g(d, "metadata.uid")} for d in hits]
        ev = st.dataframe(rows, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row")
    sel = ev.selection.rows if ev and ev.selection else []
    if not sel:
        st.info("Select a row to see its normalized event, provenance and original bytes.")
        return
    with st.container(border=True, key="card_event"):
        show_event(hits[sel[0]])


def show_event(doc: dict) -> None:
    from ulpf.integrity import get_raw
    from ulpf.provenance import explain

    u = doc.get("ulpf") or {}
    uid = _g(doc, "metadata.uid")
    st.subheader(f"Event {uid}")
    t1, t2, t3, t4 = st.tabs(["Normalized (OCSF)", "Provenance", "Original bytes", "Explain a field"])
    with t1:
        st.json({k: v for k, v in doc.items() if k != "ulpf"}, expanded=2)
    with t2:
        p = u.get("parser") or {}
        c1, c2, c3 = st.columns(3)
        c1.metric("Status", u.get("status"), border=True)
        c2.metric("Parser version", p.get("version") or "-", border=True)
        cov = u.get("coverage") or {}
        c3.metric("Fields mapped / total", f"{cov.get('mapped', 0)} / {cov.get('fields', 0)}", border=True)
        st.caption(f"parser **{p.get('id', '-')}** · spec sha256 {p.get('spec_sha256', '-')} · compiler {p.get('compiler', '-')} · "
                   f"fingerprint {u.get('fingerprint')} · format {u.get('format')}")
        st.write("**Field lineage** (OCSF attribute ← source field)")
        st.dataframe([{"ocsf_attribute": k, "from": v} for k, v in sorted((u.get("lineage") or {}).items())],
                     hide_index=True, width="stretch")
        if u.get("errors"):
            st.write("**Errors**")
            st.json(u["errors"])
        st.write("**Time**", u.get("time"))
        st.write("**Ingest**", u.get("ingest"))
        if doc.get("unmapped"):
            st.write("**Unmapped (kept verbatim)**")
            st.json(doc["unmapped"], expanded=False)
    with t3:
        try:
            r = get_raw(uid, with_proof=True)
        except (KeyError, ValueError) as e:
            st.error(str(e))
        else:
            import hashlib

            ok = hashlib.sha256(r.raw).hexdigest() == r.record["raw_sha256"]
            st.write(f"Archive file `{r.path}` line {r.line + 1}; {len(r.raw)} bytes; "
                     f"sha256 {'matches' if ok else 'DOES NOT MATCH'} the archived digest "
                     f"and {'matches' if r.record['raw_sha256'] == _g(doc, 'raw_data_hash.value') else 'DIFFERS FROM'} the indexed raw_data_hash.")
            try:
                st.code(r.raw.decode("utf-8"), language=None, wrap_lines=True)
            except UnicodeDecodeError:
                st.code(r.raw[:2048].hex(" "), language=None, wrap_lines=True)
            if r.proof:
                st.success(f"Merkle inclusion proof against sealed manifest #{r.proof['seq']}: "
                           f"{'VERIFIED' if r.proof['verified'] else 'FAILED'} (leaf {r.proof['leaf_index']} of {r.proof['tree_size']})")
                st.json(r.proof, expanded=False)
            else:
                st.warning("Not sealed yet (no manifest covers this archive file): run `ulpf seal` after the bucket closes.")
            st.download_button("Download original bytes", r.raw, file_name=f"{uid}.raw")
    with t4:
        paths_ = sorted((u.get("lineage") or {}).keys())
        if paths_:
            pick = st.selectbox("OCSF attribute", paths_)
            st.json(explain(doc, pick))


def page_onboarding() -> None:
    from ulpf.onboard.store import clusters, fallback_events

    with st.spinner("Grouping unknown events by fingerprint ..."):
        cl = clusters(fallback_events())
    with st.container(border=True, key="card_clusters"):
        st.subheader(f"Unknown clusters ({len(cl)})")
        st.dataframe([{"fingerprint": c.fingerprint, "events": c.count, "format": c.format, "last_seen": _ts(c.last_seen),
                       "example": c.example[:160]} for c in cl], hide_index=True, width="stretch")
        st.caption("Propose a draft: `ulpf onboard <fingerprint> --id vendor.product.type --vendor V --product P "
                   "--samples synthetic|real`")
        with st.expander("Upload a sample file (one event per line)"):
            st.caption("The file is dropped into the inbox the file source watches, so the lines go through the normal "
                       "raw-first path (archive -> parse -> fallback/DLQ) and show up above as a cluster.")
            up = st.file_uploader("Sample file", type=None, key="sample_upload")
            if up is not None and st.button("Ingest via inbox", type="primary"):
                inbox = paths.HOME / S["listen"]["inbox_glob"]
                inbox_dir = inbox.parent if "*" in inbox.name else inbox
                inbox_dir.mkdir(parents=True, exist_ok=True)
                data = up.getvalue()
                if not data.endswith(b"\n"):
                    data += b"\n"
                name = f"upload-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S')}.log"
                tmp = inbox_dir / (name + ".part")
                tmp.write_bytes(data)
                tmp.rename(inbox_dir / name)       # atomic: Vector never reads a partial file
                st.success(f"{data.count(b'\n')} line(s) written to {name}; refresh in a few seconds")
    drafts = sorted(paths.DRAFTS.glob("*.yaml")) if paths.DRAFTS.exists() else []
    with st.container(border=True, key="card_drafts"):
        st.subheader(f"Drafts ({len(drafts)})")
        if not drafts:
            st.caption("No drafts. `ulpf onboard` writes them to specs/_drafts/.")
        else:
            pick = st.selectbox("Draft", drafts, format_func=lambda p: p.name)
            from ulpf.onboard.gate import load_report, run_gate
            from ulpf.spec import load as load_spec

            sp = load_spec(pick)
            st.code(pick.read_text().split("\nonboarding:")[0], language="yaml")
            rep = load_report(sp.id)
            if rep:
                r, sha = rep
                fresh = r.get("content_sha256") == sp.content_sha256
                st.write(f"Latest gate: **{r['verdict']}** at {r['created_at']}"
                         + ("" if fresh else " — the draft changed since; re-run the gate"))
                st.dataframe([{"gate": g["name"], "ok": g["ok"], "detail": g["detail"]} for g in r["gates"]],
                             hide_index=True, width="stretch")
            if st.button("Run gate (lint, compile, tests, regression, samples)", type="primary"):
                with st.spinner("running real Vector batch pipelines ..."):
                    g = run_gate(pick)
                st.write(f"GATE: **{g.verdict}**")
                st.rerun()
            with st.form("promote"):
                st.write("**Promote** (human approval)")
                who = st.text_input("Approver (your name)")
                note = st.text_input("Note")
                sure = st.checkbox("I reviewed every mapping, the policy choices and the embedded samples")
                go = st.form_submit_button("Promote to approved", type="primary")
            if go:
                if not sure:
                    st.error("confirm the review first")
                else:
                    from ulpf.onboard.promote import PromoteError, promote

                    try:
                        with st.spinner("writing goldens, baseline and the live configuration ..."):
                            st.json(promote(pick, approver=who, note=note))
                    except PromoteError as e:
                        st.error(str(e))
    pl = paths.STATE / "promotions.ndjson"
    if pl.exists():
        with st.container(border=True, key="card_audit"):
            st.subheader("Promotion audit log")
            st.dataframe([json.loads(x) for x in pl.read_text().splitlines() if x.strip()], hide_index=True, width="stretch")


def page_integrity() -> None:
    from ulpf.integrity import manifests, verify

    ms = manifests()
    rows = []
    for m in ms:
        d = json.loads(m.read_text())
        gaps = sum(b - a + 1 for f in d["files"] for a, b in f.get("gaps") or [])
        rows.append({"seq": d["seq"], "created_at": d["created_at"], "files": len(d["files"]), "records": d["records"] - gaps,
                     "declared gaps": gaps, "merkle_root": d["merkle_root"][:16] + "…",
                     "prev_manifest": (d.get("prev_manifest_sha256") or "")[:16]})
    with st.container(border=True, key="card_manifests"):
        st.subheader(f"Sealed batches ({len(rows)})")
        st.dataframe(rows, hide_index=True, width="stretch")
        head = paths.ARCHIVE_MANIFESTS / "HEAD"
        if head.exists():
            st.caption(f"HEAD: {head.read_text().strip()} — record it outside this host to detect tail truncation "
                       "(`ulpf verify --expect-head`)")
    with st.container(border=True, key="card_verify"):
        st.subheader("Verification")
        if st.button("Verify signatures, chain, file hashes, Merkle roots and records", type="primary"):
            with st.spinner("verifying ..."):
                rep = verify()
            gaps = f", {rep.gap_lines} declared gap line(s)" if rep.gap_lines else ""
            (st.success if rep.ok else st.error)(
                f"VERIFY: {'PASS' if rep.ok else 'FAIL'} — {rep.manifests} manifest(s), {rep.records:,} record(s){gaps}")
            st.html(theme.check_list([(c.ok, c.name, c.details) for c in rep.checks]))
        else:
            st.caption("Re-reads every sealed file and checks it against its signed manifest.")


def page_detections() -> None:
    from ulpf.detect import detect_anomalies, network_events, run_sigma

    win = st.selectbox("Time window", list(WINDOWS), index=3)
    with st.container(border=True, key="card_sigma"):
        st.subheader("Sigma rules (pySigma → OpenSearch Lucene, OCSF field names)")
        try:
            res = run_sigma(client(), READ, since_minutes=WINDOWS[win])
        except Exception as e:  # noqa: BLE001
            st.error(str(e))
            return
        st.dataframe([{"level": r["level"], "title": r["title"], "hits": r["hits"],
                       "vendors": ", ".join(f"{k}={v}" for k, v in sorted(r["products"].items()))} for r in res],
                     hide_index=True, width="stretch")
        with st.expander("Generated queries"):
            for r in res:
                st.code(r["query"], language=None, wrap_lines=True)
    with st.container(border=True, key="card_anomaly"):
        st.subheader("Port-scan style anomalies (IsolationForest over per-source windows)")
        if st.button("Rank sources", type="primary"):
            with st.spinner("scoring ..."):
                rep = detect_anomalies(network_events(client(), READ, since_minutes=WINDOWS[win]))
            st.caption(f"{rep['windows']} window(s); {rep.get('flagged_count', 0)} flagged; {rep.get('model', '')}")
            st.dataframe([{"score": f["score"], "src_ip": f["src_ip"], "window": f["window_start"], **f["features"]}
                          for f in rep["flagged"]], hide_index=True, width="stretch")
        else:
            st.caption("Scores every source's traffic windows; the highest-ranked sources are listed.")


def page_replay() -> None:
    from ulpf.replay import _status_counts, index_versions

    osc = S["opensearch"]
    admin = Client.from_settings(S)          # alias/index metadata needs the control-plane role
    try:
        read_t, write_t = admin.alias_targets(osc["read_alias"]), admin.alias_targets(osc["write_alias"])
        rows = [{"index": name, "documents": admin.count(name), "status": json.dumps(_status_counts(admin, name)),
                 "read alias": name in read_t, "write alias": name in write_t}
                for _, name in index_versions(admin, osc["index_prefix"])]
    except Exception as e:  # noqa: BLE001
        st.error(f"OpenSearch: {e}")
        return
    with st.container(border=True, key="card_indices"):
        st.subheader("Backing indices")
        st.dataframe(rows, hide_index=True, width="stretch")
        st.caption("`ulpf replay new-index` rebuilds into a new index and switches both aliases in one request; "
                   "`ulpf replay rollback --to <index>` moves them back.")
    log = paths.STATE / "replays.ndjson"
    if log.exists():
        with st.container(border=True, key="card_history"):
            st.subheader("Replay, backfill and rollback history")
            hist = [json.loads(x) for x in log.read_text().splitlines() if x.strip()]
            st.dataframe([{k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in h.items()
                           if k in ("at", "run", "event", "new_index", "archive_records", "new_count", "switched", "missing",
                                    "missing_after_catch_up", "to", "selected", "after")} for h in hist[::-1]],
                         hide_index=True, width="stretch")
    st.info("Replays run real Vector batch pipelines and can take minutes; start them from the CLI.")


# (slug, menu label, page, one-line description)
NAV = [
    ("overview", "Overview", page_overview,
     "Pipeline health and what has been normalized: volume by product, processing status, parser quality and drift."),
    ("live", "Live feed", page_live,
     "Logs as they arrive: each line as received, how it was recognised, and the OCSF event it became. "
     "Refreshes every second."),
    ("explorer", "Event explorer", page_explorer,
     "Search normalized events on OCSF field names; open one to see its field lineage and the exact bytes received, "
     "with a Merkle proof."),
    ("onboarding", "Unknown sources & onboarding", page_onboarding,
     "Sources no approved spec recognises, grouped by fingerprint, and the review path for a draft spec: the gate, "
     "then promotion by a named approver."),
    ("integrity", "Archive integrity", page_integrity,
     "Sealed raw-archive batches (Merkle roots, Ed25519 signatures, hash chain) and on-demand verification."),
    ("replay", "Replay", page_replay,
     "Backing indices and aliases, and the history of rebuilds, backfills and rollbacks from the raw archive."),
    ("detections", "Detections", page_detections,
     "Sigma rules run as OpenSearch queries on OCSF fields, and IsolationForest ranking of port-scan style behaviour."),
]
LABELS = [n[1] for n in NAV]
BY_SLUG = {n[0]: n for n in NAV}
SLUG_OF = {n[1]: n[0] for n in NAV}

TS = st.query_params.get("ts", "md")
TS = TS if TS in theme.TEXT_SIZES else "md"
if st.session_state.get("page") not in LABELS:
    st.session_state["page"] = BY_SLUG.get(st.query_params.get("page", ""), NAV[0])[1]


def _on_nav() -> None:
    st.query_params["page"] = SLUG_OF[st.session_state["page"]]


SLUG, LABEL, PAGE, LEDE = BY_SLUG[SLUG_OF[st.session_state["page"]]]
NOW = dt.datetime.now(dt.timezone.utc)
H = _health()
st.html(theme.css(TS))
with st.container(key="ulpf_top", gap=None):
    st.html(theme.header(page=SLUG, ts=TS, collector=S["collector_id"], ocsf=paths.OCSF_VERSION, now=NOW,
                         health={"OpenSearch": H["opensearch"], "Vector": H["vector"]}))
    with st.container(key="ulpf_nav"):
        st.radio("Main menu", LABELS, key="page", horizontal=True, label_visibility="collapsed", on_change=_on_nav)
st.html(theme.page_head(title=LABEL, lede=LEDE, page=SLUG, ts=TS))
with st.container(key="ulpf_page"):
    PAGE()
st.html(theme.footer(pages=[(n[0], n[1]) for n in NAV], page=SLUG, ts=TS, version=__version__, ocsf=paths.OCSF_VERSION,
                     collector=S["collector_id"], alias=READ, now=NOW))
