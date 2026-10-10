"""`ulpf gate`: the checks a draft must pass before a human may promote it.

Gates (all must pass):
  lint         no lint errors in the draft or in any approved spec
  compile      approved specs + draft compile; real `vector validate` of the
               batch configuration; no VRL compiler warnings
  draft_tests  the draft's own vectors: delivered, routed to the draft,
               expectations, OCSF schema + envelope, completeness, round-trip
               (golden files do not exist yet; `ulpf promote` writes them)
  regression   every approved spec's vectors still pass unchanged (golden
               equality) with the draft in the pipeline -- a greedy `match`
               that steals another source's events fails here
  samples      the captured samples of the cluster, replayed through approved
               specs + draft: share claimed by the draft >= min_claim, no
               failed events, partial share <= max_partial, every output
               schema-valid, every raw payload reproduced byte-for-byte

The report binds to the draft's content hash and to the set of approved specs
it was run against; `ulpf promote` refuses a stale report.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .. import __version__, paths, pipeline, settings, vector
from ..compile import CompileError, compile_specs
from ..ocsf import default as default_ocsf
from ..provenance import validate_envelope
from ..spec import discover, lint_all, load
from ..testing import check_roundtrip, run_records, run_spec_tests
from .store import read_samples


@dataclass
class Gate:
    name: str
    ok: bool
    detail: str
    data: dict = field(default_factory=dict)


@dataclass
class GateReport:
    spec_id: str
    draft: str
    content_sha256: str
    approved_set_sha256: str
    created_at: str
    tool: str
    vector: str
    gates: list[Gate] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        return "PASS" if self.gates and all(g.ok for g in self.gates) else "FAIL"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict
        return d


def approved_set_sha256(spec_paths: list[Path]) -> str:
    items = sorted(f"{s.id}@{s.sha256}" for s in (load(p) for p in spec_paths))
    return hashlib.sha256("\n".join(items).encode()).hexdigest()


def report_dir(spec_id: str) -> Path:
    return paths.ONBOARDING / spec_id


def run_gate(draft: Path, *, min_claim: float = 0.95, max_partial: float = 0.05, write: bool = True) -> GateReport:
    draft = draft.resolve()
    sp = load(draft)
    approved = discover(include_drafts=False)
    rep = GateReport(sp.id, str(draft.relative_to(paths.HOME)) if paths.HOME in draft.parents else str(draft),
                     sp.content_sha256, approved_set_sha256(approved),
                     dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), f"ulpf {__version__}", vector.version())
    all_paths = approved + [draft]

    # ---- lint
    res = lint_all(all_paths)
    errs = {str(p): [str(i) for i in iss if i.level == "error"] for p, (_, iss) in res.items()}
    errs = {k: v for k, v in errs.items() if v}
    warns = [str(i) for i in res[draft][1] if i.level == "warning"]
    if not sp.is_draft:
        errs.setdefault(str(draft), []).append("status must be draft (approved specs are not re-gated)")
    if any(s.id == sp.id for s in (load(p) for p in approved)):
        errs.setdefault(str(draft), []).append(f"an approved spec with id {sp.id!r} already exists")
    rep.gates.append(Gate("lint", not errs, "no lint errors" if not errs else f"{sum(map(len, errs.values()))} error(s)",
                          {"errors": errs, "draft_warnings": warns}))
    if errs:
        return _finish(rep, write)

    # ---- compile (+ real vector validate of the batch config)
    try:
        pl, _ = compile_specs(all_paths)
        cfg = paths.RUNTIME / "tmp" / f"vector-gate-{sp.transform_id}.yaml"
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text(pipeline.dump(pipeline.batch_config(settings.load(), pl, replay_run="gate"), specs=pl.parsers, purpose="gate"))
        ok, log = vector.validate(cfg)
        mine = next(p for p in pl.parsers if p.spec_id == sp.id)
        w = vector.vrl_warnings(mine.vrl) + vector.vrl_warnings(pipeline.match_program(pl.parsers))
        detail = "compiled; vector validate OK; no VRL warnings" if ok and not w else \
            ("vector validate failed" if not ok else f"VRL warnings: {w[:3]}")
        rep.gates.append(Gate("compile", ok and not w, detail, {"vector_log_tail": log[-2000:] if not ok else "",
                                                                "vrl_warnings": w, "vrl_lines": mine.vrl.count("\n")}))
    except CompileError as e:
        rep.gates.append(Gate("compile", False, f"compile error: {str(e)[:500]}"))
    if not rep.gates[-1].ok:
        return _finish(rep, write)

    # ---- draft tests + regression (one batch run, every spec in the pipeline)
    results = run_spec_tests(all_paths)
    mine_r = [r for r in results if r.spec_id == sp.id]
    for r in mine_r:
        g = r.checks.get("golden", "")
        if g.startswith("missing golden file"):
            r.checks["golden"] = "skipped (draft: golden files are written by ulpf promote)"
    bad = {f"{r.name}": {k: v for k, v in r.checks.items() if v != "ok" and not v.startswith("skipped")}
           for r in mine_r if not r.ok}
    rep.gates.append(Gate("draft_tests", bool(mine_r) and not bad,
                          f"{len(mine_r) - len(bad)}/{len(mine_r)} draft vector(s) passed", {"failures": bad}))
    other = [r for r in results if r.spec_id != sp.id]
    reg = {f"{r.spec_id}::{r.name}": {k: v for k, v in r.checks.items() if v != "ok" and not v.startswith("skipped")}
           for r in other if not r.ok}
    rep.gates.append(Gate("regression", not reg, f"{len(other) - len(reg)}/{len(other)} approved vector(s) unchanged",
                          {"failures": reg}))

    # ---- captured samples
    sfile = report_dir(sp.id) / "samples.ndjson"
    records = read_samples(sfile)
    if not records:
        rep.gates.append(Gate("samples", False, f"no captured samples at {sfile} (run ulpf onboard)"))
        return _finish(rep, write)
    st = sample_stats(all_paths, records, sp.id)
    claim = st["claimed"] / st["records"]
    partial = st["status"].get("partial", 0) / max(st["claimed"], 1)
    ok = (st["delivered"] == st["records"] and claim >= min_claim and st["status"].get("failed", 0) == 0
          and partial <= max_partial and not st["schema_invalid"] and not st["roundtrip_failures"])
    rep.gates.append(Gate("samples", ok,
                          f"{st['claimed']}/{st['records']} claimed ({claim:.1%}, need >= {min_claim:.0%}); "
                          f"partial {partial:.1%} (max {max_partial:.0%}); schema-invalid {len(st['schema_invalid'])}; "
                          f"round-trip failures {len(st['roundtrip_failures'])}",
                          {k: (dict(v) if isinstance(v, Counter) else v) for k, v in st.items()}))
    return _finish(rep, write)


def sample_stats(spec_paths: list[Path], records: list[dict], spec_id: str) -> dict:
    o = default_ocsf()
    events = run_records(spec_paths, records, replay_run="gate")
    by_uid = {e["metadata"]["uid"]: e for e in events}
    st = {"records": len(records), "delivered": len(by_uid), "claimed": 0, "status": Counter(), "claimed_by": Counter(),
          "errors": Counter(), "mapped_ratio_avg": 0.0, "schema_invalid": [], "roundtrip_failures": []}
    ratios = []
    for rec in records:
        ev = by_uid.get(rec["event_uid"])
        if ev is None:
            continue
        u = ev.get("ulpf") or {}
        pid = (u.get("parser") or {}).get("id")
        st["claimed_by"][pid or "<none>"] += 1
        raw = base64.b64decode(rec["raw_b64"])
        if check_roundtrip(raw, ev) != "ok":
            st["roundtrip_failures"].append(rec["event_uid"])
        vr = o.validate(ev)
        if not vr.ok or validate_envelope(ev):
            st["schema_invalid"].append({"uid": rec["event_uid"], "issues": [str(i) for i in vr.issues][:3] + validate_envelope(ev)[:2]})
        if pid != spec_id:
            continue
        st["claimed"] += 1
        st["status"][u.get("status")] += 1
        for e in u.get("errors") or []:
            st["errors"][f"{e.get('code')}:{e.get('field', '')}"] += 1
        cov = u.get("coverage") or {}
        if cov.get("fields"):
            ratios.append(cov.get("mapped", 0) / max(cov["fields"] - cov.get("empty", 0), 1))
    st["mapped_ratio_avg"] = round(sum(ratios) / len(ratios), 4) if ratios else 0.0
    st["schema_invalid"] = st["schema_invalid"][:20]
    st["roundtrip_failures"] = st["roundtrip_failures"][:20]
    st["events"] = [e for e in events if ((e.get("ulpf") or {}).get("parser") or {}).get("id") == spec_id]
    return st


def _finish(rep: GateReport, write: bool) -> GateReport:
    if write:
        d = report_dir(rep.spec_id)
        d.mkdir(parents=True, exist_ok=True)
        body = rep.to_dict()
        for g in body["gates"]:
            g["data"].pop("events", None)
        text = json.dumps(body, indent=2, sort_keys=True, default=str) + "\n"
        stamp = rep.created_at.replace(":", "").replace("-", "")
        (d / f"gate-{stamp}.json").write_text(text)
        tmp = d / "gate.json.tmp"
        tmp.write_text(text)
        tmp.replace(d / "gate.json")
    return rep


def load_report(spec_id: str) -> tuple[dict, str] | None:
    p = report_dir(spec_id) / "gate.json"
    if not p.exists():
        return None
    raw = p.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()
