"""Parser drift detection.

A *profile* summarises what a parser produced for a set of events: status
mix, error codes, which OCSF attributes were populated (from field lineage),
which source keys ended up in `unmapped`, the structural fingerprints seen and
the mapped-field ratio. A *baseline* is a stored profile (written by
`ulpf promote` from the onboarding samples, or by `ulpf drift baseline` from
live traffic). `ulpf drift check` compares recent traffic with the baseline
and reports signals with explicit thresholds -- no learned model, so every
signal can be explained and reproduced.

Signals
  NEW_UNMAPPED_FIELD   a source key absent from the baseline now lands in
                       `unmapped` in >= new_field_share of events (vendor
                       added or renamed a field)
  MAPPED_FIELD_MISSING an attribute populated in >= 90% of baseline events
                       dropped by more than missing_drop (vendor removed or
                       renamed a field; mapping silently empty)
  STATUS_SHIFT         partial+failed share rose by more than status_rise
  NEW_ERROR            an error code not seen in the baseline, >= 1% of events
  MAPPED_RATIO_DROP    average mapped/(fields-empty) fell by > ratio_drop
  NEW_FINGERPRINT      a structural fingerprint not in the baseline carries
                       >= 10% of events (informational)
  PARSER_CHANGED       events come from a spec version the baseline was not
                       built with (informational: re-baseline after review)
  UNKNOWN_SOURCE       fallback events of one fingerprint in the window
                       (candidate for `ulpf onboard`)
  FALLBACK_RATE_UP     overall fallback share rose by > status_rise over the
                       global baseline (`ulpf drift baseline --global`)
  LOW_VOLUME           fewer than min_events events: not compared
"""
from __future__ import annotations

import datetime as dt
import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from . import paths

THRESHOLDS = {"min_events": 20, "new_field_share": 0.05, "missing_drop": 0.2, "status_rise": 0.05,
              "error_share": 0.01, "ratio_drop": 0.1, "fingerprint_share": 0.10, "unknown_min": 5}


@dataclass
class Profile:
    n: int = 0
    status: Counter = field(default_factory=Counter)
    errors: Counter = field(default_factory=Counter)
    dests: Counter = field(default_factory=Counter)
    unmapped: Counter = field(default_factory=Counter)
    fingerprints: Counter = field(default_factory=Counter)
    ratio_sum: float = 0.0
    ratio_n: int = 0
    parser_versions: Counter = field(default_factory=Counter)
    skews: list = field(default_factory=list)      # |ingest - event time| ms, capped sample

    def add(self, ev: dict) -> None:
        u = ev.get("ulpf") or {}
        self.n += 1
        self.status[u.get("status") or "?"] += 1
        for e in u.get("errors") or []:
            self.errors[str(e.get("code"))] += 1
        for d, src in (u.get("lineage") or {}).items():
            if src not in ("const", "default:unknown"):
                self.dests[d] += 1
        for k in (ev.get("unmapped") or {}):
            if not k.startswith("ulpf."):
                self.unmapped[k] += 1
        self.fingerprints[u.get("fingerprint") or "?"] += 1
        p = u.get("parser") or {}
        self.parser_versions[f"{p.get('version')}@{(p.get('spec_sha256') or '')[:12]}"] += 1
        cov = u.get("coverage") or {}
        if cov.get("fields"):
            self.ratio_sum += cov.get("mapped", 0) / max(cov["fields"] - cov.get("empty", 0), 1)
            self.ratio_n += 1
        sk = (u.get("time") or {}).get("skew_ms")
        if isinstance(sk, (int, float)) and len(self.skews) < 5000:
            self.skews.append(abs(int(sk)))

    @property
    def mapped_ratio(self) -> float:
        return self.ratio_sum / self.ratio_n if self.ratio_n else 0.0

    def share(self, c: Counter, key: str) -> float:
        return c.get(key, 0) / self.n if self.n else 0.0

    def to_dict(self) -> dict:
        # not dataclasses.asdict(): it rebuilds Counter fields from (key, value)
        # tuples, which Counter then counts as keys
        d = {k: (dict(v) if isinstance(v, Counter) else v) for k, v in vars(self).items()}
        d["mapped_ratio"] = round(self.mapped_ratio, 4)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Profile":
        p = cls()
        for k in ("status", "errors", "dests", "unmapped", "fingerprints", "parser_versions"):
            setattr(p, k, Counter(d.get(k) or {}))
        p.n, p.ratio_sum, p.ratio_n = d.get("n", 0), d.get("ratio_sum", 0.0), d.get("ratio_n", 0)
        p.skews = list(d.get("skews") or [])
        return p


def profile_events(events: Iterable[dict]) -> dict[str, Profile]:
    out: dict[str, Profile] = {}
    for ev in events:
        pid = ((ev.get("ulpf") or {}).get("parser") or {}).get("id")
        if pid:
            out.setdefault(pid, Profile()).add(ev)
    return out


def baseline_path(spec_id: str) -> Path:
    return paths.STATE / "drift" / f"{spec_id}.baseline.json"


def write_baseline(spec_id: str, prof: Profile, *, source: str) -> Path:
    p = baseline_path(spec_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    body = {"spec_id": spec_id, "created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "source": source, "thresholds": THRESHOLDS, "profile": prof.to_dict()}
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
    tmp.replace(p)
    return p


GLOBAL = "_global"


def write_global_baseline(events: Iterable[dict], *, source: str) -> Path:
    st = Counter((e.get("ulpf") or {}).get("status") for e in events)
    n = sum(st.values())
    p = baseline_path(GLOBAL)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"spec_id": GLOBAL, "created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                             "source": source, "events": n, "status": dict(st),
                             "fallback_share": (st.get("fallback", 0) / n) if n else 0.0}, indent=2, sort_keys=True) + "\n")
    return p


def load_baseline(spec_id: str) -> dict | None:
    p = baseline_path(spec_id)
    return json.loads(p.read_text()) if p.exists() else None


@dataclass
class Signal:
    spec_id: str
    kind: str
    severity: str        # info | warn | high
    message: str
    data: dict = field(default_factory=dict)


def compare(spec_id: str, base: Profile, cur: Profile, th: dict = THRESHOLDS) -> list[Signal]:
    out: list[Signal] = []
    if cur.n < th["min_events"]:
        return [Signal(spec_id, "LOW_VOLUME", "info", f"{cur.n} event(s) in the window (< {th['min_events']}): not compared")]
    for k, c in sorted(cur.unmapped.items()):
        sh = c / cur.n
        if sh >= th["new_field_share"] and k not in base.unmapped:
            out.append(Signal(spec_id, "NEW_UNMAPPED_FIELD", "warn",
                              f"source key {k!r} now lands in unmapped in {sh:.0%} of events (not in baseline)", {"key": k, "share": round(sh, 4)}))
    for d, c in sorted(base.dests.items()):
        bs = c / base.n if base.n else 0
        cs = cur.share(cur.dests, d)
        if bs >= 0.9 and cs < bs - th["missing_drop"]:
            out.append(Signal(spec_id, "MAPPED_FIELD_MISSING", "high",
                              f"{d} populated in {cs:.0%} of events (baseline {bs:.0%})", {"attribute": d, "share": round(cs, 4), "baseline": round(bs, 4)}))
    bad_b = (base.status.get("partial", 0) + base.status.get("failed", 0)) / base.n if base.n else 0
    bad_c = (cur.status.get("partial", 0) + cur.status.get("failed", 0)) / cur.n
    if bad_c > bad_b + th["status_rise"]:
        out.append(Signal(spec_id, "STATUS_SHIFT", "high", f"partial+failed share {bad_c:.1%} (baseline {bad_b:.1%})",
                          {"current": round(bad_c, 4), "baseline": round(bad_b, 4), "status": dict(cur.status)}))
    for code, c in sorted(cur.errors.items()):
        if code not in base.errors and c / cur.n >= th["error_share"]:
            out.append(Signal(spec_id, "NEW_ERROR", "warn", f"error code {code!r} in {c / cur.n:.1%} of events (not in baseline)",
                              {"code": code, "count": c}))
    if base.ratio_n and cur.ratio_n and cur.mapped_ratio < base.mapped_ratio - th["ratio_drop"]:
        out.append(Signal(spec_id, "MAPPED_RATIO_DROP", "warn",
                          f"mapped-field ratio {cur.mapped_ratio:.2f} (baseline {base.mapped_ratio:.2f})"))
    new_versions = sorted(set(cur.parser_versions) - set(base.parser_versions))
    if new_versions:
        out.append(Signal(spec_id, "PARSER_CHANGED", "info",
                          f"events parsed by spec version(s) {new_versions} not in the baseline; re-baseline after review",
                          {"versions": new_versions}))
    for fp, c in sorted(cur.fingerprints.items()):
        if fp not in base.fingerprints and c / cur.n >= th["fingerprint_share"]:
            out.append(Signal(spec_id, "NEW_FINGERPRINT", "info", f"structural fingerprint {fp} carries {c / cur.n:.0%} of events",
                              {"fingerprint": fp, "count": c}))
    return out


def recent_events(since_ms: int | None) -> Iterable[dict]:
    """Normalized events (NDJSON, or Parquet for pruned files) received after since_ms."""
    from .lake import normalized_lines

    for line in normalized_lines():
        ev = json.loads(line)
        t = ((ev.get("ulpf") or {}).get("ingest") or {}).get("time_ms") or 0
        if since_ms is None or t >= since_ms:
            yield ev


def check(*, since_minutes: float | None = 60, spec: str | None = None, events: Iterable[dict] | None = None) -> dict:
    since_ms = None if since_minutes is None else int((dt.datetime.now(dt.timezone.utc).timestamp() - since_minutes * 60) * 1000)
    evs = list(events if events is not None else recent_events(since_ms))
    profs = profile_events(evs)
    signals: list[Signal] = []
    compared, no_baseline = [], []
    from .spec import discover, load

    ids = sorted({load(p).id for p in discover()} | set(profs))
    for sid in ids:
        if spec and sid != spec:
            continue
        cur = profs.get(sid, Profile())
        b = load_baseline(sid)
        if b is None:
            if cur.n:
                no_baseline.append(sid)
            continue
        compared.append(sid)
        signals += compare(sid, Profile.from_dict(b["profile"]), cur, b.get("thresholds") or THRESHOLDS)
    unknown = Counter(((e.get("ulpf") or {}).get("fingerprint") or "?") for e in evs
                      if (e.get("ulpf") or {}).get("status") == "fallback")
    g = load_baseline(GLOBAL)
    share = (sum(unknown.values()) / len(evs)) if evs else 0.0
    if g and not spec and len(evs) >= THRESHOLDS["min_events"] and share > g["fallback_share"] + THRESHOLDS["status_rise"]:
        signals.append(Signal("-", "FALLBACK_RATE_UP", "warn",
                              f"fallback share {share:.1%} (baseline {g['fallback_share']:.1%}): new or changed sources",
                              {"current": round(share, 4), "baseline": round(g["fallback_share"], 4)}))
    if not spec:
        for fp, c in unknown.most_common():
            if c >= THRESHOLDS["unknown_min"]:
                signals.append(Signal("-", "UNKNOWN_SOURCE", "warn", f"{c} fallback event(s) with fingerprint {fp}: run `ulpf onboard {fp}`",
                                      {"fingerprint": fp, "count": c}))
    report = {"checked_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
              "window_minutes": since_minutes, "events": len(evs), "compared": compared, "no_baseline": no_baseline,
              "signals": [asdict(s) for s in signals],
              "fallback_share": round(share, 4),
              "verdict": "DRIFT" if any(s.severity in ("warn", "high") and s.kind != "UNKNOWN_SOURCE" for s in signals) else
                         ("UNKNOWN_SOURCES" if any(s.kind == "UNKNOWN_SOURCE" for s in signals) else "OK")}
    paths.STATE.mkdir(parents=True, exist_ok=True)
    (paths.STATE / "drift-last.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report
