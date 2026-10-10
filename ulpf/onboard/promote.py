"""`ulpf promote`: human approval of a gated draft.

Refuses unless
  * a named approver is given (an LLM or a script is not an approver),
  * the latest gate report is PASS, was computed for exactly this draft
    content (content hash) and against the current approved spec set.
Then, atomically and with rollback on any failure:
  1. writes specs/<vendor>/<name>.yaml (status: approved + approval record),
  2. writes the golden files of its test vectors and re-runs them,
  3. writes a drift baseline from the captured samples,
  4. rebuilds the live Vector configuration (Vector hot-reloads it),
  5. archives the draft and appends to the promotion audit log.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import shutil
from pathlib import Path

from .. import __version__, paths
from ..spec import discover, lint_file, load
from ..testing import GOLDEN, run_spec_tests
from .gate import approved_set_sha256, load_report, report_dir, sample_stats
from .store import read_samples

FORBIDDEN_APPROVERS = {"", "llm", "ai", "auto", "automatic", "ulpf", "root", "system"}


class PromoteError(Exception):
    pass


def destination(spec_id: str, root: Path | None = None) -> Path:
    vendor, rest = spec_id.split(".", 1)
    return (root or paths.SPECS) / vendor / (rest.replace(".", "_") + ".yaml")


def approved_text(draft_text: str, approval: dict) -> str:
    lines = draft_text.splitlines()
    # drop the DRAFT banner (leading comment block)
    i = 0
    while i < len(lines) and lines[i].startswith("#"):
        i += 1
    body = lines[i:]
    n = sum(1 for ln in body if ln == "status: draft")
    if n != 1:
        raise PromoteError("draft must contain exactly one top-level `status: draft` line")
    body = ["status: approved" if ln == "status: draft" else ln for ln in body]
    banner = [
        f"# Onboarded with `ulpf onboard` (fingerprint {approval['fingerprint']}), gated by `ulpf gate`",
        f"# and approved by {approval['approved_by']} on {approval['approved_at']} (`ulpf promote`).",
        "# Suggestion evidence is kept under `onboarding:`; the approval record under `approval:`.",
    ]
    import yaml

    tail = yaml.safe_dump({"approval": approval}, sort_keys=False, default_flow_style=False, width=1_000_000)
    return "\n".join(banner + body).rstrip("\n") + "\n\n" + tail


def promote(draft: Path, *, approver: str, note: str | None = None, rebuild: bool = True) -> dict:
    draft = draft.resolve()
    if approver.strip().lower() in FORBIDDEN_APPROVERS or not re.fullmatch(r"[\w .@'-]{2,80}", approver.strip()):
        raise PromoteError("a named human approver is required (--approver 'First Last')")
    sp = load(draft)
    if not sp.is_draft:
        raise PromoteError(f"{draft} is not a draft")
    got = load_report(sp.id)
    if got is None:
        raise PromoteError(f"no gate report for {sp.id}; run `ulpf gate {draft}` first")
    report, report_sha = got
    if report.get("verdict") != "PASS":
        raise PromoteError(f"latest gate report is {report.get('verdict')}; fix the draft and re-run `ulpf gate`")
    if report.get("content_sha256") != sp.content_sha256:
        raise PromoteError("the draft changed after it was gated (content hash differs); re-run `ulpf gate`")
    approved = discover(include_drafts=False)
    if report.get("approved_set_sha256") != approved_set_sha256(approved):
        raise PromoteError("approved specs changed since the gate ran; re-run `ulpf gate`")
    dest = destination(sp.id)
    if dest.exists():
        raise PromoteError(f"{dest} already exists")

    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    approval = {
        "approved_by": approver.strip(),
        "approved_at": now,
        "note": note or "",
        "content_sha256": sp.content_sha256,
        "gate_report_sha256": report_sha,
        "gate_created_at": report.get("created_at"),
        "fingerprint": (sp.data.get("onboarding") or {}).get("fingerprint") or "",
        "tool": f"ulpf {__version__}",
    }
    text = approved_text(draft.read_text(), approval)
    created: list[Path] = []
    golden_dir = GOLDEN / sp.id
    try:
        if not dest.parent.exists():
            dest.parent.mkdir(parents=True)
            created.append(dest.parent)
        tmp = dest.with_suffix(".yaml.tmp")
        created.append(tmp)
        tmp.write_text(text)
        new, issues = lint_file(tmp)
        errs = [str(i) for i in issues if i.level == "error"]
        if errs or new is None:
            raise PromoteError(f"promoted spec fails lint: {errs[:3]}")
        if new.content_sha256 != sp.content_sha256 or new.is_draft:
            raise PromoteError("internal error: promoted content differs from the gated draft")
        tmp.replace(dest)
        created.append(dest)

        # 2. golden files (after the move: the batch run uses the approved set)
        new_set = [p for p in discover(include_drafts=False)]
        if golden_dir.exists():
            raise PromoteError(f"{golden_dir} already exists")
        created.append(golden_dir)
        res = run_spec_tests(new_set, update_golden=True, only={sp.id})
        bad = [r.name for r in res if not r.ok]
        if bad or not res:
            raise PromoteError(f"test vectors failed while writing golden files: {bad}")
        res2 = run_spec_tests(new_set, only={sp.id})
        if not all(r.ok for r in res2):
            raise PromoteError("golden re-check failed (non-deterministic output?)")

        # 3. drift baseline from the captured samples
        from ..drift import profile_events, write_baseline

        records = read_samples(report_dir(sp.id) / "samples.ndjson")
        st = sample_stats(new_set, records, sp.id)
        prof = profile_events(st["events"]).get(sp.id)
        base_path = write_baseline(sp.id, prof, source=f"onboarding samples ({len(records)}) at promotion") if prof else None
        if base_path:
            created.append(base_path)

        # 4. live config
        build = None
        if rebuild:
            from ..build import build_live

            build = build_live()
    except Exception:
        for p in reversed(created):
            if p == dest.parent:
                if p.is_dir() and not any(p.iterdir()):
                    p.rmdir()
            elif p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            elif p.exists():
                p.unlink()
        raise

    # 5. archive the draft + audit log
    arch = report_dir(sp.id) / f"draft-{sp.content_sha256[:12]}.yaml"
    arch.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(draft, arch)
    draft.unlink()
    audit = {"event": "promote", "spec_id": sp.id, "version": sp.version, "path": str(dest.relative_to(paths.HOME)),
             "approved_by": approval["approved_by"], "approved_at": now, "content_sha256": sp.content_sha256,
             "spec_sha256": load(dest).sha256, "gate_report_sha256": report_sha,
             "config_sha256": (build or {}).get("config_sha256")}
    paths.STATE.mkdir(parents=True, exist_ok=True)
    with open(paths.STATE / "promotions.ndjson", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(audit, sort_keys=True) + "\n")
    return {"promoted": str(dest.relative_to(paths.HOME)), "golden": str(golden_dir.relative_to(paths.HOME)),
            "baseline": str(base_path.relative_to(paths.HOME)) if base_path and paths.HOME in base_path.parents else (str(base_path) if base_path else None),
            "draft_archived_as": str(arch), "live_config": (build or {}).get("config_sha256"),
            "specs_in_live_config": len((build or {}).get("specs", [])), "audit": audit}
