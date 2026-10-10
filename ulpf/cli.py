"""`ulpf` command-line interface (control plane)."""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import click

from . import __version__, paths


def _echo_json(obj) -> None:
    click.echo(json.dumps(obj, indent=2, sort_keys=True, default=str))


@click.group()
@click.version_option(__version__, prog_name="ulpf")
def main() -> None:
    """ULPF - Universal Log Pre-processing Framework (control plane)."""


# ------------------------------------------------------------------ doctor
@main.command()
@click.option("--json", "as_json", is_flag=True, help="machine-readable output")
def doctor(as_json: bool) -> None:
    """Check the installation, vendored schemas, specs and generated files."""
    from .doctor import run_checks

    results = run_checks()
    if as_json:
        _echo_json([r.__dict__ for r in results])
    else:
        for r in results:
            click.echo(f"[{r.status:4s}] {r.name}: {r.detail}")
    sys.exit(1 if any(r.status == "FAIL" for r in results) else 0)


# -------------------------------------------------------------------- spec
@main.group()
def spec() -> None:
    """Lint and compile source specifications."""


def _spec_paths(given: tuple[str, ...], drafts: bool) -> list[Path]:
    from .spec import discover

    return [Path(p).resolve() for p in given] if given else discover(include_drafts=drafts)


@spec.command("lint")
@click.argument("files", nargs=-1)
@click.option("--drafts", is_flag=True, help="include specs/_drafts")
def spec_lint(files: tuple[str, ...], drafts: bool) -> None:
    """Validate specs (YAML, JSON Schema, OCSF semantics). Exit 1 on errors."""
    from .spec import lint_all

    res = lint_all(_spec_paths(files, drafts))
    nerr = 0
    for p, (sp, issues) in res.items():
        errs = [i for i in issues if i.level == "error"]
        nerr += len(errs)
        mark = "FAIL" if errs else "OK"
        click.echo(f"[{mark}] {sp.id if sp else p} ({len(errs)} errors, {len(issues) - len(errs)} warnings)")
        for i in issues:
            click.echo(f"    {i}")
    click.echo(f"{len(res)} spec(s), {nerr} error(s)")
    sys.exit(1 if nerr else 0)


@spec.command("compile")
@click.option("--drafts", is_flag=True, help="also compile drafts (never use for production)")
@click.option("--check", is_flag=True, help="compile and validate, do not write the live config")
@click.option("--restart", is_flag=True,
              help="apply a structural change (sinks, archive branch, sources, global options) by a drained "
                   "Vector restart instead of refusing it; listeners are down during the restart")
def spec_compile(drafts: bool, check: bool, restart: bool) -> None:
    """Compile specs to VRL, validate with Vector, write the live config atomically."""
    from .build import build_live

    try:
        report = build_live(include_drafts=drafts, write=not check, restart=restart)
    except Exception as e:  # noqa: BLE001 - report the compiler/validator message
        click.echo(f"compile FAILED: {e}", err=True)
        sys.exit(1)
    _echo_json(report)


# -------------------------------------------------------------------- test
@main.command("test")
@click.option("--spec", "only", multiple=True, help="only run vectors of these spec ids")
@click.option("--update", is_flag=True, help="rewrite golden files from the current output (review first!)")
@click.option("--drafts", is_flag=True, help="include draft specs")
@click.option("--json", "as_json", is_flag=True)
def test_cmd(only: tuple[str, ...], update: bool, drafts: bool, as_json: bool) -> None:
    """Run golden/expectation/schema/completeness/round-trip tests through Vector."""
    from .spec import discover
    from .testing import run_spec_tests

    results = run_spec_tests(discover(include_drafts=drafts), update_golden=update, only=set(only) or None)
    if not only and not drafts:
        from .scorecard import record_test_results

        record_test_results(results)
    if as_json:
        _echo_json([{"spec": r.spec_id, "case": r.name, "ok": r.ok, "checks": r.checks} for r in results])
    else:
        for r in results:
            click.echo(f"[{'PASS' if r.ok else 'FAIL'}] {r.spec_id} :: {r.name}")
            for k, v in r.checks.items():
                if v != "ok":
                    click.echo(f"        {k}: {v}")
    npass = sum(r.ok for r in results)
    click.echo(f"{npass}/{len(results)} test vectors passed", err=as_json)
    sys.exit(0 if npass == len(results) else 1)


# ------------------------------------------------------------------- stack
@main.group()
def stack() -> None:
    """Start/stop the native stack (OpenSearch, Vector, Dashboards, UI)."""


@stack.command("up")
@click.argument("services", nargs=-1)
def stack_up(services: tuple[str, ...]) -> None:
    from . import stack as st
    from .settings import load

    s = load()
    for name in services or tuple(st.ORDER):
        if name == "vector":
            from .pipeline import check_generated

            ok, msg = check_generated(st.LIVE_CONFIG) if st.LIVE_CONFIG.exists() else (False, "run `ulpf spec compile` first")
            if not ok:
                click.echo(f"vector: refusing to start: {msg}")
                continue
        click.echo(st.start(name, s))
        if name == "opensearch" and st.SERVICES["opensearch"].health(s):
            from .opensearch import Client, bootstrap

            click.echo(f"opensearch bootstrap: {bootstrap(Client.from_settings(s), s)}")


@stack.command("down")
@click.argument("services", nargs=-1)
def stack_down(services: tuple[str, ...]) -> None:
    from . import stack as st

    for name in services or tuple(reversed(st.ORDER)):
        click.echo(st.stop(name))


@stack.command("status")
def stack_status() -> None:
    from . import stack as st

    for name, state in st.status():
        click.echo(f"{name:11s} {state}")


# ---------------------------------------------------------------------- os
@main.group("os")
def os_group() -> None:
    """OpenSearch helpers."""


@os_group.command("secure")
@click.option("--disable", is_flag=True, help="turn the security plugin off again (plain http, no auth)")
def os_secure(disable) -> None:
    """Enable the OpenSearch security plugin: TLS + admin/ulpf-writer/ulpf-reader users."""
    from .os_security import disable as off, enable

    try:
        _echo_json(off() if disable else enable())
    except RuntimeError as e:
        raise click.ClickException(str(e)) from e


@os_group.command("bootstrap")
def os_bootstrap() -> None:
    """Install the generated index template and create index + aliases."""
    from .opensearch import Client, bootstrap

    _echo_json(bootstrap(Client.from_settings()))


# --------------------------------------------------------------------- gen
@main.command()
@click.option("--vendor", "vendors", multiple=True, default=["fortigate"], show_default=True,
              help="renderer(s): " + ", ".join(sorted(["fortigate", "blackbox"])) + " (see `ulpf gen --list`)")
@click.option("--count", default=100, show_default=True)
@click.option("--transport", type=click.Choice(["udp", "tcp", "tcp-octet", "http"]), default="udp", show_default=True)
@click.option("--addr", default=None, help="host:port (default from deploy/ulpf.yaml)")
@click.option("--eps", type=float, default=None, help="target events/second (default: as fast as possible)")
@click.option("--scenario", type=click.Choice(["mixed", "portscan", "malformed"]), default="mixed", show_default=True)
@click.option("--seed", default=1, show_default=True)
@click.option("--sendlog", type=click.Path(dir_okay=False), default=None, help="record every payload (sha256) here")
@click.option("--list", "list_", is_flag=True, help="list renderers and exit")
def gen(vendors, count, transport, addr, eps, scenario, seed, sendlog, list_) -> None:
    """Send SYNTHETIC TEST DATA (documented vendor formats, RFC 5737 addresses)."""
    from . import gen as g
    from .settings import load

    if list_:
        for name, fn in sorted(g.RENDERERS.items()):
            click.echo(f"{name:14s} {(fn.__doc__ or '').strip().splitlines()[0]}")
        return
    s = load()
    addr = addr or {"udp": s["listen"]["syslog_udp"], "tcp": s["listen"]["syslog_tcp"],
                    "tcp-octet": s["listen"]["syslog_tcp_octet"] or "127.0.0.1:5515",
                    "http": s["listen"]["http_ndjson"]}[transport]
    log = g.SendLog(Path(sendlog), line_buffered=eps is not None) if sendlog else None
    n = g.send_scenario(scenario, vendors=list(vendors), count=count, transport=transport, addr=addr, eps=eps,
                        seed=seed, log=log)
    if log:
        log.close()
    click.echo(f"sent {n} event(s) via {transport} to {addr}")


# ----------------------------------------------------------------- account
@main.command()
@click.option("--sendlog", type=click.Path(exists=True, dir_okay=False), default=None,
              help="sender log to reconcile against (sha256 multiset)")
@click.option("--opensearch/--no-opensearch", default=True, show_default=True)
@click.option("--settle", default=30.0, show_default=True,
              help="max seconds to wait for the archive/normalized stores to stop growing first")
@click.option("--json", "as_json", is_flag=True)
def account(sendlog, opensearch, settle, as_json) -> None:
    """Event accounting: sent = received = archived = normalized = indexed."""
    from .accounting import reconcile

    rep = reconcile(Path(sendlog) if sendlog else None, check_opensearch=opensearch, settle_s=settle)
    if as_json:
        _echo_json(rep)
    else:
        for k, v in rep.items():
            click.echo(f"{k:28s} {v}")
    sys.exit(0 if rep.get("verdict") == "PASS" else 1)


# --------------------------------------------------------------- integrity
@main.command()
@click.option("--force", is_flag=True, help="replace an existing key (old manifests stay verifiable only with the old public key)")
def keygen(force: bool) -> None:
    """Generate the Ed25519 archive-sealing key pair (deploy/keys, mode 0600)."""
    from .integrity import keygen as kg

    try:
        _echo_json(kg(force=force))
    except FileExistsError as e:
        click.echo(str(e), err=True)
        sys.exit(1)


@main.command()
@click.option("--grace", default=120, show_default=True, help="seconds after a file's bucket ends before it is sealed")
@click.option("--accept-gaps", is_flag=True,
              help="also seal files with empty lines (events written without a record), declaring the gaps in the "
                   "signed manifest; only after `ulpf account` / `ulpf repair` have accounted for those events")
def seal(grace: int, accept_gaps: bool) -> None:
    """Seal closed raw-archive files into a signed, hash-chained batch."""
    from .integrity import seal as do_seal

    r = do_seal(grace_s=grace, accept_gaps=accept_gaps)
    _echo_json(r.__dict__)
    if r.held_gaps:
        click.echo(f"NOT SEALED (gaps): {sum(r.held_gaps.values())} empty line(s) in {len(r.held_gaps)} file(s). "
                   "Investigate with `ulpf account` (and `ulpf repair`), then `ulpf seal --accept-gaps`.", err=True)
    sys.exit(1 if r.problems or r.held_gaps else 0)


@main.command()
@click.option("--expect-head", default=None, help="externally recorded head ('<seq> <sha256>' or sha256) to detect tail truncation")
@click.option("--pubkey", type=click.Path(exists=True, dir_okay=False), default=None)
@click.option("--shallow", is_flag=True, help="skip per-record raw hash checks")
@click.option("--json", "as_json", is_flag=True)
def verify(expect_head, pubkey, shallow, as_json) -> None:
    """Verify signatures, manifest chain, file hashes, Merkle roots and records."""
    from .integrity import verify as do_verify

    rep = do_verify(expect_head=expect_head, pubkey=Path(pubkey) if pubkey else None, deep=not shallow)
    if as_json:
        _echo_json({"ok": rep.ok, "manifests": rep.manifests, "records": rep.records, "gap_lines": rep.gap_lines, "head": rep.head,
                    "checks": [c.__dict__ for c in rep.checks]})
    else:
        for c in rep.checks:
            click.echo(f"{'✓' if c.ok else '✗'} {c.name}")
            for d in c.details[:20]:
                click.echo(f"    {d}")
        gaps = f", {rep.gap_lines} declared gap line(s)" if rep.gap_lines else ""
        click.echo(f"{rep.manifests} manifest(s), {rep.records} record(s){gaps}, head: {rep.head}")
        click.echo("VERIFY: PASS" if rep.ok else "VERIFY: FAIL")
    sys.exit(0 if rep.ok else 1)


@main.group()
def raw() -> None:
    """Retrieve original raw events from the archive."""


@raw.command("get")
@click.argument("event_uid")
@click.option("--out", type=click.Path(dir_okay=False), default=None, help="write the raw bytes to a file")
@click.option("--proof", is_flag=True, help="include a Merkle inclusion proof against the sealing manifest")
@click.option("--meta", is_flag=True, help="print the archive record metadata (JSON) instead of the bytes")
def raw_get(event_uid, out, proof, meta) -> None:
    """Print the exact received bytes of EVENT_UID (verified against raw_sha256)."""
    from .integrity import get_raw

    try:
        r = get_raw(event_uid, with_proof=proof)
    except (KeyError, ValueError) as e:
        click.echo(str(e), err=True)
        sys.exit(1)
    if meta or proof:
        rec = {k: v for k, v in r.record.items() if k != "raw_b64"}
        _echo_json({"record": rec, "archive_file": r.path, "line": r.line + 1, "sealed_in": r.sealed_seq, "proof": r.proof})
    if out:
        Path(out).write_bytes(r.raw)
    elif not (meta or proof):
        sys.stdout.buffer.write(r.raw)


# -------------------------------------------------------------- onboarding
def _ts(ms) -> str:
    import datetime as dt

    return dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ms else "-"


@main.command()
@click.option("--top", default=20, show_default=True)
@click.option("--json", "as_json", is_flag=True)
def fingerprint(top: int, as_json: bool) -> None:
    """List unknown-source clusters (fallback events in the DLQ, by fingerprint)."""
    from .onboard.store import clusters, fallback_events

    cl = clusters(fallback_events())
    if as_json:
        _echo_json([c.to_dict() for c in cl[:top]])
        return
    if not cl:
        click.echo("no fallback events in the DLQ")
        return
    click.echo(f"{'FINGERPRINT':16s}  {'EVENTS':>6s}  {'FORMAT':14s}  {'LAST SEEN':20s}  EXAMPLE")
    for c in cl[:top]:
        click.echo(f"{c.fingerprint:16s}  {c.count:6d}  {c.format[:14]:14s}  {_ts(c.last_seen):20s}  {c.example[:70]}")
    click.echo(f"{len(cl)} cluster(s), {sum(c.count for c in cl)} fallback event(s)")


def _cluster_samples(fp: str, limit: int):
    from .onboard.store import clusters, fallback_events, fetch_raw, preparse, spread

    cl = next((c for c in clusters(fallback_events()) if c.fingerprint == fp), None)
    if cl is None:
        raise click.ClickException(f"no fallback events with fingerprint {fp!r} (see `ulpf fingerprint`)")
    uids = spread(cl.uids, limit)
    found, problems = fetch_raw(uids)
    samples = [found[u] for u in uids if u in found]
    pres = preparse([s.record for s in samples])
    return cl, samples, pres, problems


@main.command()
@click.argument("fp", metavar="FINGERPRINT")
@click.option("--max", "max_n", default=1000, show_default=True, help="samples to mine")
@click.option("--sim", default=0.4, show_default=True, help="drain3 similarity threshold")
@click.option("--split", default="", help="extra token delimiters, e.g. '|;,' (display only)")
@click.option("--json", "as_json", is_flag=True)
def mine(fp: str, max_n: int, sim: float, split: str, as_json: bool) -> None:
    """Mine message templates (drain3, in memory) for one unknown cluster."""
    from .onboard.mining import mine as do_mine

    cl, samples, pres, problems = _cluster_samples(fp, max_n)
    bodies = [str((pres[s.event_uid].get("pre") or {}).get("body", "")) for s in samples if s.event_uid in pres]
    tpl = do_mine(bodies, sim_th=sim, extra_delimiters=tuple(split))
    if as_json:
        _echo_json({"fingerprint": fp, "samples": len(bodies), "problems": problems, "templates": [t.to_dict() for t in tpl]})
        return
    for p in problems[:5]:
        click.echo(f"WARN {p}", err=True)
    for t in tpl[:20]:
        click.echo(f"{t.count:6d}  {t.text[:150]}")
    click.echo(f"{len(tpl)} template(s) over {len(bodies)} sample(s)")


@main.command()
@click.argument("fp", metavar="FINGERPRINT")
@click.option("--id", "spec_id", required=True, help="new spec id: vendor.product.logtype")
@click.option("--vendor", required=True)
@click.option("--product", required=True)
@click.option("--samples", "samples_kind", type=click.Choice(["synthetic", "real", "mixed"]), required=True,
              help="provenance of the captured samples (they are embedded in the draft's tests)")
@click.option("--class", "cls", default="network_activity", show_default=True, help="OCSF class")
@click.option("--max-samples", default=300, show_default=True)
@click.option("--max-tests", default=5, show_default=True)
@click.option("--llm", "use_llm", is_flag=True, help="also ask a LOCAL LLM (ULPF_LLM_URL); suggestions stay inactive comments")
@click.option("--force", is_flag=True, help="overwrite an existing draft")
def onboard(fp, spec_id, vendor, product, samples_kind, cls, max_samples, max_tests, use_llm, force) -> None:
    """Propose a draft spec for an unknown cluster (specs/_drafts/<id>.yaml)."""
    from .onboard.draft import OnboardError, propose, write
    from .onboard.gate import report_dir
    from .onboard.store import write_samples

    cl, samples, pres, problems = _cluster_samples(fp, max_samples)
    try:
        prop = propose(samples, pres, spec_id=spec_id, vendor=vendor, product=product, cls=cls,
                       samples_kind=samples_kind, cluster=cl, use_llm=use_llm, max_tests=max_tests)
        path = write(prop, force=force)
    except OnboardError as e:
        raise click.ClickException(str(e)) from e
    n = write_samples(report_dir(spec_id) / "samples.ndjson", [s for s in samples if s.event_uid in pres])
    (report_dir(spec_id) / "onboard.json").write_text(json.dumps(prop.report, indent=2, sort_keys=True) + "\n")
    r = prop.report
    click.echo(f"draft written: {path.relative_to(paths.HOME)}")
    click.echo(f"samples: {n} archived event(s) -> {report_dir(spec_id).relative_to(paths.HOME)}/samples.ndjson")
    for p in problems[:5]:
        click.echo(f"WARN {p}")
    click.echo(f"structure: {r['structure']['parse_kind']} -- " + "; ".join(r["structure"]["evidence"]))
    for sg in r["suggestions"]:
        mark = "ACTIVE  " if sg["active"] else "inactive"
        click.echo(f"  {mark} {sg['source']:>18s} -> {sg['to']:32s} {sg['type']:7s} {sg['confidence']:.2f} {sg['origin']}")
    for t in r["time"][:1]:
        click.echo(f"  time     {t['entry']['field']:>18s} -> time ({t['entry']['format']})")
    if r.get("enum"):
        click.echo(f"  enum     {r['enum']['source']:>18s} -> action/disposition (+activity) -- {r['enum']['reasons'][0]}")
    click.echo("review required:")
    for x in r["review_required"]:
        click.echo(f"  - {x}")
    click.echo(f"next: ulpf gate {path.relative_to(paths.HOME)}")


@main.command()
@click.argument("draft", type=click.Path(exists=True, dir_okay=False))
@click.option("--min-claim", default=0.95, show_default=True, help="share of captured samples the draft must claim")
@click.option("--max-partial", default=0.05, show_default=True)
@click.option("--json", "as_json", is_flag=True)
def gate(draft, min_claim, max_partial, as_json) -> None:
    """Run the promotion gates on a draft (lint, compile, tests, regression, samples)."""
    from .onboard.gate import run_gate

    rep = run_gate(Path(draft), min_claim=min_claim, max_partial=max_partial)
    if as_json:
        body = rep.to_dict()
        for g in body["gates"]:
            g["data"].pop("events", None)
        _echo_json(body)
    else:
        for g in rep.gates:
            click.echo(f"[{'PASS' if g.ok else 'FAIL'}] {g.name:12s} {g.detail}")
            if not g.ok:
                for k in ("errors", "failures"):
                    for key, v in list((g.data.get(k) or {}).items())[:6]:
                        click.echo(f"         {key}: {str(v)[:300]}")
        click.echo(f"GATE: {rep.verdict}  (content {rep.content_sha256[:12]}, report runtime/data/onboarding/{rep.spec_id}/gate.json)")
    sys.exit(0 if rep.verdict == "PASS" else 1)


@main.command()
@click.argument("draft", type=click.Path(exists=True, dir_okay=False))
@click.option("--approver", required=True, help="name of the human approving this spec")
@click.option("--note", default=None)
@click.option("--no-rebuild", is_flag=True, help="do not rebuild the live configuration")
def promote(draft, approver, note, no_rebuild) -> None:
    """Approve a gated draft: move it to specs/, write goldens + baseline, rebuild live config."""
    from .onboard.promote import PromoteError, promote as do_promote

    try:
        _echo_json(do_promote(Path(draft), approver=approver, note=note, rebuild=not no_rebuild))
    except PromoteError as e:
        raise click.ClickException(str(e)) from e


@main.group()
def drift() -> None:
    """Parser drift detection against per-spec baselines."""


@drift.command("check")
@click.option("--since-minutes", default=60.0, show_default=True)
@click.option("--all-time", is_flag=True, help="use every normalized event, not a time window")
@click.option("--spec", default=None)
@click.option("--json", "as_json", is_flag=True)
def drift_check(since_minutes, all_time, spec, as_json) -> None:
    """Compare recent traffic per spec with its baseline; exit 3 on drift."""
    from .drift import check

    rep = check(since_minutes=None if all_time else since_minutes, spec=spec)
    if as_json:
        _echo_json(rep)
    else:
        click.echo(f"{rep['events']} event(s); compared: {', '.join(rep['compared']) or '-'}")
        if rep["no_baseline"]:
            click.echo(f"no baseline: {', '.join(rep['no_baseline'])} (ulpf drift baseline --spec ID)")
        for sg in rep["signals"]:
            click.echo(f"[{sg['severity'].upper():4s}] {sg['spec_id']:30s} {sg['kind']:20s} {sg['message']}")
        click.echo(f"DRIFT: {rep['verdict']}")
    sys.exit(3 if rep["verdict"] == "DRIFT" else 0)


@drift.command("baseline")
@click.option("--spec", "specs", multiple=True, help="spec id(s) to baseline")
@click.option("--global", "global_", is_flag=True, help="also baseline the overall fallback share")
@click.option("--since-minutes", default=None, type=float, help="default: every normalized event")
def drift_baseline(specs, global_, since_minutes) -> None:
    """(Re)build baselines from live normalized traffic (after reviewing it)."""
    import datetime as dt

    from .drift import profile_events, recent_events, write_baseline, write_global_baseline

    if not specs and not global_:
        raise click.UsageError("give --spec ID (repeatable) and/or --global")
    since_ms = None if since_minutes is None else int((dt.datetime.now(dt.timezone.utc).timestamp() - since_minutes * 60) * 1000)
    evs = list(recent_events(since_ms))
    if global_:
        gp = write_global_baseline(evs, source=f"live normalized events ({len(evs)})")
        click.echo(f"global: {len(evs)} event(s) -> {gp.relative_to(paths.HOME) if paths.HOME in gp.parents else gp}")
    profs = profile_events(e for e in evs if ((e.get("ulpf") or {}).get("parser") or {}).get("id") in specs)
    for sid in specs:
        if sid not in profs:
            click.echo(f"{sid}: no events, baseline not written")
            continue
        p = write_baseline(sid, profs[sid], source=f"live normalized events ({profs[sid].n})")
        click.echo(f"{sid}: {profs[sid].n} event(s) -> {p.relative_to(paths.HOME) if paths.HOME in p.parents else p}")


@main.command()
@click.option("--since-minutes", default=None, type=float, help="default: every normalized event")
@click.option("--validate", default=50, show_default=True, help="events per spec to schema-validate")
@click.option("--json", "as_json", is_flag=True)
def scorecard(since_minutes, validate, as_json) -> None:
    """Per-spec quality scorecard (tests, golden, parse rate, mapping, schema, drift, skew, provenance)."""
    from .scorecard import build

    sc = build(since_minutes=since_minutes, validate=validate)
    if as_json:
        _echo_json(sc)
        return
    click.echo(f"{sc['events']} event(s) {sc['status']}; unknown: {sc['unknown']['events']} in {sc['unknown']['fingerprints']} cluster(s)")
    click.echo(f"{'SPEC':30s} {'VER':6s} {'TESTS':9s} {'GOLDEN':6s} {'PARSED':9s} {'MAPPED':9s} {'SCHEMA':7s} {'DRIFT':14s} OVERALL")
    for r in sc["specs"]:
        m = r["metrics"]

        def v(k, w):
            x = m[k]["value"]
            txt = f"{x:.1%}" if isinstance(x, float) else (",".join(x) if isinstance(x, list) else str(x))
            return (txt if len(txt) <= w else txt[: w - 1] + "~").ljust(w)

        click.echo(f"{r['spec'][:30]:30s} {r['version']:6s} {v('tests', 9)} {v('golden', 6)} {v('parsed_rate', 9)} "
                   f"{v('mapped_ratio', 9)} {v('schema', 7)} {v('drift', 14)} {r['overall']}")


# --------------------------------------------------------------- detection
@main.group()
def detect() -> None:
    """Detections over the normalized index (Sigma rules, anomaly ranking)."""


@detect.command("sigma")
@click.option("--since-minutes", default=None, type=float, help="only events newer than this")
@click.option("--show-queries", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def detect_sigma(since_minutes, show_queries, as_json) -> None:
    """Convert detections/sigma/rules with pySigma and run them against OpenSearch."""
    from .detect import run_sigma
    from .opensearch import Client
    from .settings import load

    s = load()
    res = run_sigma(Client.from_settings(s), s["opensearch"]["read_alias"], since_minutes=since_minutes)
    if as_json:
        _echo_json(res)
        return
    for r in res:
        prods = ", ".join(f"{k}={v}" for k, v in sorted(r["products"].items())) or "-"
        click.echo(f"[{(r['level'] or '?').upper():13s}] {r['hits']:6d} hit(s)  {r['title']}")
        click.echo(f"{'':16s}vendors: {prods}")
        if show_queries:
            click.echo(f"{'':16s}lucene:  {r['query']}")


@detect.command("anomaly")
@click.option("--since-minutes", default=None, type=float)
@click.option("--window", "window_s", default=60, show_default=True, help="seconds per source window")
@click.option("--top", default=10, show_default=True)
@click.option("--truth-src", default=None, help="known scanner IP (synthetic scenario) to evaluate against")
@click.option("--json", "as_json", is_flag=True)
def detect_anomaly(since_minutes, window_s, top, truth_src, as_json) -> None:
    """Rank per-source windows with an IsolationForest (port-scan style anomalies)."""
    from .detect import detect_anomalies, evaluate, network_events
    from .opensearch import Client
    from .settings import load

    s = load()
    rep = detect_anomalies(network_events(Client.from_settings(s), s["opensearch"]["read_alias"], since_minutes=since_minutes),
                           window_s=window_s, top=top)
    if truth_src:
        rep["evaluation"] = evaluate(rep, truth_src)
    if as_json:
        _echo_json(rep)
        return
    click.echo(f"{rep['windows']} source window(s); {rep.get('flagged_count', 0)} flagged by {rep.get('model', '-')}")
    for f in rep["flagged"]:
        ex = "; ".join(f"{k} {v['value']} (median {v['median']})" for k, v in f["explanation"].items())
        click.echo(f"  score {f['score']:.3f}  {f['src_ip']:15s} {f['window_start']}  {ex}")
    if truth_src:
        click.echo(f"evaluation: {rep['evaluation']}")


@main.command("anomaly")
@click.option("--since-minutes", default=None, type=float)
@click.option("--window", "window_s", default=60, show_default=True, help="seconds per source window")
@click.option("--top", default=10, show_default=True)
@click.option("--truth-src", default=None, help="known scanner IP (synthetic scenario) to evaluate against")
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def anomaly(ctx, since_minutes, window_s, top, truth_src, as_json) -> None:
    """Alias of `ulpf detect anomaly`."""
    ctx.invoke(detect_anomaly, since_minutes=since_minutes, window_s=window_s, top=top, truth_src=truth_src, as_json=as_json)


# -------------------------------------------------------------------- lake
@main.group()
def lake() -> None:
    """Parquet copy of the normalized events (analytics; lossless event_json)."""


@lake.command("compact")
@click.option("--grace", default=120, show_default=True, help="seconds after a file's bucket ends before it is compacted")
@click.option("--force", is_flag=True, help="also compact files whose bucket is still open (tests/demos)")
@click.option("--prune", is_flag=True,
              help="delete each NDJSON file once its Parquet copy re-reads byte-identically (readers switch to Parquet)")
def lake_compact(grace, force, prune) -> None:
    """Write closed normalized NDJSON files as verified Parquet (zstd)."""
    from .lake import compact

    rep = compact(grace_s=grace, force=force, prune=prune)
    _echo_json(rep)
    sys.exit(1 if rep["problems"] else 0)


@lake.command("verify")
@click.option("--repair-layout", is_flag=True,
              help="recover and record the empty-line layout of files compacted before layouts were recorded")
def lake_verify(repair_layout: bool) -> None:
    """Check every Parquet file against the lake manifest (sha256, rows, byte-exact re-assembly)."""
    from .lake import verify as lv

    rep = lv(repair_layout=repair_layout)
    _echo_json(rep)
    sys.exit(0 if rep["ok"] else 1)


@lake.command("restore")
def lake_restore() -> None:
    """Re-create pruned NDJSON files from their Parquet copies (sha256-checked)."""
    from .lake import restore

    _echo_json(restore())


@lake.command("stats")
def lake_stats() -> None:
    from .lake import stats

    _echo_json(stats())


# ------------------------------------------------------------------ replay
@main.group()
def replay() -> None:
    """Re-process archived raw events with the current approved specs."""


def _ms(iso: str | None) -> int | None:
    import datetime as dt

    if not iso:
        return None
    t = dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return int(t.timestamp() * 1000)


@replay.command("new-index")
@click.option("--switch/--no-switch", default=True, show_default=True, help="atomically move the read/write aliases")
@click.option("--since", default=None, help="ISO time (ingest) lower bound")
@click.option("--until", default=None, help="ISO time (ingest) upper bound")
def replay_new_index(switch, since, until) -> None:
    """Rebuild into <prefix>-v<N+1>, verify counts, switch aliases, catch up."""
    from .replay import replay_new_index as do

    rep = do(switch=switch, since_ms=_ms(since), until_ms=_ms(until))
    _echo_json(rep)
    sys.exit(0 if rep.get("verified") and not rep.get("missing_after_catch_up") else 1)


@replay.command("backfill")
@click.option("--status", "statuses", multiple=True, default=["fallback"], show_default=True)
def replay_backfill(statuses) -> None:
    """Re-process indexed events with these statuses in place (same document ids)."""
    from .replay import backfill

    _echo_json(backfill(statuses=statuses))


@replay.command("missing")
def replay_missing() -> None:
    """Re-index archived events missing from the index (after an OpenSearch outage)."""
    from .replay import missing

    rep = missing()
    _echo_json(rep)
    sys.exit(1 if rep.get("still_missing") else 0)


@replay.command("rollback")
@click.option("--to", "to_index", required=True, help="backing index to point the aliases at again")
def replay_rollback(to_index) -> None:
    """Atomically point the read and write aliases back to an earlier index."""
    from .replay import rollback

    _echo_json(rollback(to_index))


@replay.command("status")
def replay_status() -> None:
    """Show backing indices, alias targets and per-index counts."""
    from .opensearch import Client
    from .replay import _status_counts, index_versions
    from .settings import load

    s = load()
    c = Client.from_settings(s)
    osc = s["opensearch"]
    _echo_json({"read_alias": {osc["read_alias"]: c.alias_targets(osc["read_alias"])},
                "write_alias": {osc["write_alias"]: c.alias_targets(osc["write_alias"])},
                "indices": {name: {"count": c.count(name), "status": _status_counts(c, name)}
                            for _, name in index_versions(c, osc["index_prefix"])}})


# ----------------------------------------------------------------- secrets
@main.group("secrets")
def secrets_group() -> None:
    """Install-time secrets (runtime/secrets, mode 0600)."""


@secrets_group.command("init")
@click.option("--force", is_flag=True, help="replace existing secrets (PII pseudonyms and passwords change!)")
def secrets_init(force) -> None:
    """Generate the PII HMAC key and OpenSearch user passwords."""
    from .credentials import init_secrets

    _echo_json(init_secrets(force=force))


@main.group()
def certs() -> None:
    """Local CA and TLS certificates (deploy/certs)."""


@certs.command("init")
@click.option("--force", is_flag=True)
@click.option("--days", default=825, show_default=True)
def certs_init(force, days) -> None:
    """Create a deployment CA and the syslog, OpenSearch node/admin and client certificates."""
    from .credentials import init_certs

    _echo_json(init_certs(force=force, days=days))


@main.command()
@click.option("--dry-run", is_flag=True, help="only report what would be repaired")
def repair(dry_run) -> None:
    """Close accounting gaps: archive<-index (sha256-verified, flagged), normalized<-archive, index<-archive."""
    from .repair import repair as do

    _echo_json(do(dry_run=dry_run))


# ----------------------------------------------------------------- runtime
@main.group("runtime")
def runtime_group() -> None:
    """Pinned third-party runtime (Vector, OpenSearch, security plugin)."""


@runtime_group.command("fetch")
@click.option("--with-optional", is_flag=True, help="also download optional artifacts (e.g. OpenSearch Dashboards)")
def runtime_fetch(with_optional) -> None:
    """Download the pinned artifacts into runtime/dist (NETWORK; each one sha256-checked against its pin)."""
    from . import runtime

    for line in runtime.fetch(paths.RUNTIME / "dist", include_optional=with_optional):
        click.echo(line)


@runtime_group.command("verify")
def runtime_verify() -> None:
    """Check runtime/dist artifacts against the SHA-256 pins (offline)."""
    from .runtime import verify as rv

    probs = rv(paths.RUNTIME / "dist")
    for p in probs:
        click.echo(p)
    click.echo("artifacts OK" if not probs else f"{len(probs)} problem(s)")
    sys.exit(1 if probs else 0)


@runtime_group.command("install")
@click.option("--with-security", is_flag=True, help="also install the OpenSearch security plugin")
def runtime_install(with_security) -> None:
    """Install verified artifacts from runtime/dist into runtime/ (offline)."""
    from .runtime import install

    try:
        for line in install(paths.RUNTIME / "dist", with_security=with_security) or ["already installed"]:
            click.echo(line)
    except RuntimeError as e:
        raise click.ClickException(str(e)) from e


# ------------------------------------------------------------------ bundle
@main.group()
def bundle() -> None:
    """Offline (air-gap) bundle."""


@bundle.command("lock")
def bundle_lock() -> None:
    """Write requirements.lock (exact versions + wheel sha256) from runtime/wheelhouse."""
    from .bundle import lock

    click.echo(str(lock()))


@bundle.command("build")
@click.option("--out", "out_dir", type=click.Path(file_okay=False), default=None, help="default: runtime/bundle")
@click.option("--tar", "as_tar", is_flag=True,
              help="also write the single .tar transfer file (a real ~0.5 GB copy) and remove the directory")
def bundle_build(out_dir, as_tar) -> None:
    """Build and sign the offline bundle (hard-links pinned artifacts; verifies them first)."""
    from .bundle import build

    try:
        _echo_json(build(Path(out_dir) if out_dir else None, tar=as_tar))
    except RuntimeError as e:
        raise click.ClickException(str(e)) from e


if __name__ == "__main__":  # pragma: no cover
    main()
