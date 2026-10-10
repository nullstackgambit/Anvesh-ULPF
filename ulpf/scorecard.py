"""Per-spec quality scorecard (`ulpf scorecard`).

Facts only -- no opaque composite score. Each metric has a documented
threshold and a PASS/WARN/FAIL/N/A state:

  tests        last `ulpf test` result for the spec's vectors        FAIL if any failed / N/A if never run
  golden       every vector has a golden file                        WARN if missing
  parsed_rate  parsed / events claimed by the spec (normalized data)  WARN < 99%, FAIL < 95%
  mapped_ratio mean mapped/(fields-empty) over claimed events         WARN < 50%
  drift        signals of the last `ulpf drift check`                 WARN on warn, FAIL on high
  provenance   approved specs need samples:, references (vendor docs) or an approval record
  partial/failed share of claimed events                            WARN > 1% / FAIL > 5%
  schema       OCSF JSON Schema + semantic + envelope validation of a
               sample of claimed events (--validate N)                FAIL < 100%
  unknown_fields distinct source keys landing in `unmapped`            informational
  new_templates  fingerprints not in the drift baseline                WARN > 0
  clock_skew   p95 |receipt - event time|                             WARN > 5 min
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from . import paths
from .drift import profile_events, recent_events
from .spec import discover, load
from .testing import GOLDEN

LAST_TEST = "last-test.json"


def record_test_results(results) -> Path:
    paths.STATE.mkdir(parents=True, exist_ok=True)
    p = paths.STATE / LAST_TEST
    body = {"results": [{"spec": r.spec_id, "case": r.name, "ok": r.ok,
                         "failed_checks": {k: v for k, v in r.checks.items() if v != "ok" and not v.startswith("skipped")}}
                        for r in results]}
    import datetime as dt

    body["ran_at"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    p.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
    return p


def _state(cond_fail: bool, cond_warn: bool) -> str:
    return "FAIL" if cond_fail else ("WARN" if cond_warn else "PASS")


def _pct(xs: list[int], q: float) -> int | None:
    if not xs:
        return None
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))]


def build(*, since_minutes: float | None = None, validate: int = 50) -> dict:
    import datetime as dt

    from .drift import load_baseline
    from .ocsf import default as default_ocsf
    from .provenance import validate_envelope

    since_ms = None if since_minutes is None else int((dt.datetime.now(dt.timezone.utc).timestamp() - since_minutes * 60) * 1000)
    events = list(recent_events(since_ms))
    profs = profile_events(events)
    o = default_ocsf()
    by_spec: dict[str, list] = {}
    for e in events:
        pid = ((e.get("ulpf") or {}).get("parser") or {}).get("id")
        if pid and len(by_spec.setdefault(pid, [])) < validate:
            by_spec[pid].append(e)
    lt_path = paths.STATE / LAST_TEST
    last = json.loads(lt_path.read_text()) if lt_path.exists() else None
    tests_by = {}
    for r in (last or {}).get("results", []):
        tests_by.setdefault(r["spec"], []).append(r)
    dl = paths.STATE / "drift-last.json"
    drift = json.loads(dl.read_text()) if dl.exists() else None
    sig_by: dict[str, list] = {}
    for s in (drift or {}).get("signals", []):
        sig_by.setdefault(s["spec_id"], []).append(s)
    rows = []
    for p in discover(include_drafts=False):
        sp = load(p)
        d = sp.data
        prof = profs.get(sp.id)
        tr = tests_by.get(sp.id)
        n_tests = len(d["tests"])
        goldens = sum(1 for t in d["tests"] if t.get("golden", True) and (GOLDEN / sp.id / f"{t['name']}.expected.json").exists())
        need_golden = sum(1 for t in d["tests"] if t.get("golden", True))
        m: dict[str, dict] = {}
        m["tests"] = ({"state": "N/A", "value": "never run"} if tr is None else
                      {"state": _state(any(not r["ok"] for r in tr), False), "value": f"{sum(r['ok'] for r in tr)}/{len(tr)}"})
        m["golden"] = {"state": _state(False, goldens < need_golden), "value": f"{goldens}/{need_golden}"}
        if prof and prof.n:
            # generic specs structure an event but emit status=fallback by design
            # (no vendor semantics); their success outcome is "fallback"
            good = "fallback" if d.get("generic") else "parsed"
            pr = prof.status.get(good, 0) / prof.n
            m["parsed_rate"] = {"state": _state(pr < 0.95, pr < 0.99), "value": round(pr, 4), "events": prof.n,
                                "status": dict(prof.status), "success_status": good}
            m["mapped_ratio"] = {"state": _state(False, prof.mapped_ratio < 0.5), "value": round(prof.mapped_ratio, 4)}
        else:
            m["parsed_rate"] = {"state": "N/A", "value": "no events"}
            m["mapped_ratio"] = {"state": "N/A", "value": "no events"}
        sigs = [s for s in sig_by.get(sp.id, []) if s["kind"] not in ("LOW_VOLUME",)]
        if drift is None:
            m["drift"] = {"state": "N/A", "value": "never checked"}
        elif sp.id not in (drift.get("compared") or []):
            m["drift"] = {"state": "N/A", "value": "no baseline"}
        else:
            m["drift"] = {"state": _state(any(s["severity"] == "high" for s in sigs), any(s["severity"] == "warn" for s in sigs)),
                          "value": [s["kind"] for s in sigs] or "no signals"}
        # vendor specs cite vendor documentation or carry an onboarding approval;
        # generic specs (no vendor) only need declared sample provenance
        prov_ok = bool(d.get("samples")) and (bool(d.get("references")) or bool(d.get("approval")) or bool(d.get("generic")))
        m["provenance"] = {"state": _state(False, not prov_ok), "value": {
            "samples": d.get("samples"), "references": len(d.get("references") or []),
            "approved_by": (d.get("approval") or {}).get("approved_by"), "generic": bool(d.get("generic"))}}
        if prof and prof.n:
            part = prof.status.get("partial", 0) / prof.n
            fail = prof.status.get("failed", 0) / prof.n
            m["partial_failed"] = {"state": _state(part + fail > 0.05, part + fail > 0.01),
                                   "value": f"{part:.1%}/{fail:.1%}"}
            sample = by_spec.get(sp.id, [])
            ok_n = sum(1 for e in sample if o.validate(e).ok and not validate_envelope(e))
            m["schema"] = {"state": _state(ok_n < len(sample), False), "value": f"{ok_n}/{len(sample)}"}
            m["unknown_fields"] = {"state": "PASS", "value": len(prof.unmapped),
                                   "top": [k for k, _ in prof.unmapped.most_common(5)]}
            base = load_baseline(sp.id)
            if base:
                new_fp = sorted(set(prof.fingerprints) - set((base["profile"].get("fingerprints") or {})))
                m["new_templates"] = {"state": _state(False, bool(new_fp)), "value": len(new_fp), "fingerprints": new_fp[:5]}
            else:
                m["new_templates"] = {"state": "N/A", "value": "no baseline"}
            p95 = _pct(prof.skews, 0.95)
            m["clock_skew"] = ({"state": "N/A", "value": "no source time"} if p95 is None else
                               {"state": _state(False, p95 > 300_000), "value": f"p50 {_pct(prof.skews, 0.5)} ms, p95 {p95} ms"})
        else:
            for k in ("partial_failed", "schema", "unknown_fields", "new_templates", "clock_skew"):
                m[k] = {"state": "N/A", "value": "no events"}
        unm = sum(1 for f in (d.get("fields") or {}).values() if f.get("unmapped"))
        states = Counter(v["state"] for v in m.values())
        rows.append({"spec": sp.id, "version": sp.version, "class": sp.class_name, "path": str(p.relative_to(paths.HOME)),
                     "tests": n_tests, "mapped_fields": sum(1 for f in (d.get("fields") or {}).values() if f.get("to")),
                     "documented_unmapped": unm, "metrics": m,
                     "overall": "FAIL" if states["FAIL"] else ("WARN" if states["WARN"] else "PASS")})
    fallback = Counter(((e.get("ulpf") or {}).get("fingerprint") or "?") for e in events if (e.get("ulpf") or {}).get("status") == "fallback")
    status = Counter((e.get("ulpf") or {}).get("status") for e in events)
    return {"window_minutes": since_minutes, "events": len(events), "status": dict(status),
            "unknown": {"events": sum(fallback.values()), "fingerprints": len(fallback), "top": fallback.most_common(5)},
            "last_test_run": (last or {}).get("ran_at"), "last_drift_check": (drift or {}).get("checked_at"), "specs": rows}
