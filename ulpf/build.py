"""Build and atomically deploy the live Vector configuration.

Vector runs with --watch-config, so replacing vector-live.yaml is a hot
reload. That is safe for what spec changes touch, but not in general:
Vector 0.58 keeps a changed sink's buffer across a reload, and events the old
topology had already buffered are then encoded with the new sink settings
(verified: a json -> text codec change wrote them as empty lines, with no log
message; VERIFICATION_REPORT finding P6-4). `reload_hazards` therefore lists
every change outside the spec-dependent components; such a configuration is
applied only with a drained restart (`ulpf spec compile --restart`).
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os

import yaml

from . import __version__, paths, pipeline, settings, vector
from .compile import CompileError, compile_specs
from .spec import discover

# What a spec promotion, change or retirement may change in a hot reload: the
# spec programs (p_*), the matcher and router, and the input lists of the
# fan-in transforms that collect the spec outputs.
SPEC_COMPONENTS = {"ulpf_match", "ulpf_route"}
FAN_IN = {"ulpf_fallback", "ulpf_failed", "ulpf_finalize"}


def reload_hazards(old: dict, new: dict) -> list[str]:
    """Differences between two live configs that a hot reload cannot apply
    safely (anything a spec change does not explain)."""
    out = []
    for k in sorted(set(old) | set(new)):
        if k not in ("sources", "transforms", "sinks") and old.get(k) != new.get(k):
            out.append(f"global option {k!r} changed")
    for sect in ("sources", "transforms", "sinks"):
        a, b = old.get(sect) or {}, new.get(sect) or {}
        for name in sorted(set(a) | set(b)):
            if sect == "transforms" and (name.startswith("p_") or name in SPEC_COMPONENTS):
                continue
            x, y = a.get(name), b.get(name)
            if sect == "transforms" and name in FAN_IN:
                if x is None or y is None:
                    continue
                x = {k: v for k, v in x.items() if k != "inputs"}
                y = {k: v for k, v in y.items() if k != "inputs"}
            if x is None or y is None:
                out.append(f"{sect[:-1]} {name} {'added' if x is None else 'removed'}")
            elif x != y:
                keys = sorted(k for k in set(x) | set(y) if x.get(k) != y.get(k))
                out.append(f"{sect[:-1]} {name} changed ({', '.join(keys)})")
    return out


def build_live(*, include_drafts: bool = False, write: bool = True, restart: bool = False) -> dict:
    """Compile, validate and deploy. A configuration with reload hazards is
    deployed while Vector runs only with `restart` (stop -> Vector drains its
    buffers with the old configuration -> replace -> start)."""
    from . import stack

    spec_paths = discover(include_drafts=include_drafts)
    pl, lint = compile_specs(spec_paths)
    s = settings.load()
    text = pipeline.dump(pipeline.live_config(s, pl), specs=pl.parsers, purpose="live data plane")
    out_dir = paths.PIPELINE_GENERATED
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = out_dir / ".vector-live.tmp.yaml"  # extension decides the format Vector parses
    tmp.write_text(text)
    ok, log = vector.validate(tmp)
    if not ok:
        tmp.unlink()
        raise CompileError("generated configuration failed `vector validate`:\n" + log[-4000:])
    warn = {p.spec_id: w for p in pl.parsers if (w := vector.vrl_warnings(p.vrl))}
    mw = vector.vrl_warnings(pipeline.match_program(pl.parsers))
    if mw:
        warn["<match>"] = mw
    if warn:
        tmp.unlink()
        raise CompileError(f"generated VRL has compiler warnings: {warn}")
    report = {
        "compiler": f"ulpf {__version__}",
        "vector": vector.version(),
        "ocsf": paths.OCSF_VERSION,
        "specs": [{"id": p.spec_id, "version": p.version, "sha256": p.spec_sha256, "priority": p.priority} for p in pl.parsers],
        "config_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "built_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "drafts_included": include_drafts,
        "lint_warnings": {k: v for k, v in lint.items() if v},
        "written": write,
    }
    live = out_dir / "vector-live.yaml"
    hazards = reload_hazards(yaml.safe_load(live.read_text()) or {}, yaml.safe_load(text) or {}) if live.exists() else []
    running = stack.pid_of("vector") is not None
    report["reload_hazards"] = hazards
    if not write:
        tmp.unlink()
        return report
    if hazards and running and not restart:
        tmp.unlink()
        raise CompileError(
            "structural change -- NOT applied by hot reload (it would re-encode events Vector has already "
            "buffered with the new settings, finding P6-4):\n  " + "\n  ".join(hazards) +
            "\nApply it with `ulpf spec compile --restart` (Vector drains its buffers, then restarts; the "
            "listeners are down meanwhile, so do it in a maintenance window: UDP senders lose packets, TCP "
            "senders must retry).")
    pdir = out_dir / "parsers"
    pdir.mkdir(exist_ok=True)
    for old in pdir.glob("*.vrl"):
        if old.read_text().startswith("# GENERATED FILE"):
            old.unlink()
    for p in pl.parsers:
        (pdir / f"{p.spec_id}.vrl").write_text(p.vrl)
    (out_dir / "match.vrl").write_text(pipeline.match_program(pl.parsers))
    if hazards and running:
        report["applied"] = "restart"
        report["vector_stop"] = stack.stop("vector")
        os.replace(tmp, live)
        report["vector_start"] = stack.start("vector")
    else:
        report["applied"] = "hot reload" if running else "written (Vector not running)"
        # Atomic replace: Vector (--watch-config) never observes a partial file.
        os.replace(tmp, live)
    (out_dir / "BUILD.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report
