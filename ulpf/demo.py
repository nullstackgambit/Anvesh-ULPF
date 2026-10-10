"""Demo traffic for the Live feed page (shown only when the UI runs with ULPF_DEMO=1).

Starts and stops `ulpf gen` in the background from the UI. The traffic is
SYNTHETIC TEST DATA and goes through the real pipeline (archive, parse,
index), exactly like any received log:

  main stream       the seven supported vendors in turn, plus `blackbox` (a
                    fictional source no approved spec recognises) when
                    `unknown` is set: about one event in eight
  malformed stream  the generator's MALFORMED corpus (broken JSON, truncated
                    CEF, invalid UTF-8, ...) at 1/20 of the main rate

Both streams use UDP: it carries every MALFORMED payload exactly as written
(newline-framed TCP cannot send the empty frame) and a UDP sender keeps going
if Vector restarts. Every generator is given an event count of rate x
minutes, so a demo nobody stops ends by itself (each event costs about 6 KB of
archive, normalized file and index).

State: runtime/run/demo.json (settings, start/end, pids); sendlogs (one line
per sent payload, usable with `ulpf account --sendlog`) in
runtime/tmp/demo-<stream>.ndjson; generator output in runtime/logs/demo-*.log.
"""
from __future__ import annotations

import json
import math
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from . import paths

VENDORS = ["fortigate", "panos", "asa", "suricata", "zeek", "squid", "pfsense"]
UNKNOWN_VENDOR = "blackbox"
MAX_MINUTES = 15
MAX_EPS = 50


def _state_file() -> Path:
    return paths.RUN / "demo.json"


def sendlog(stream: str) -> Path:
    return paths.RUNTIME / "tmp" / f"demo-{stream}.ndjson"


def _exe() -> str:
    return str(Path(sys.executable).with_name("ulpf"))


def commands(eps: float, *, unknown: bool, malformed: bool, minutes: float = MAX_MINUTES,
             seed: int = 1) -> dict[str, list[str]]:
    """{stream: argv} for the generators. Pure, so the mix and the auto-stop
    caps are unit-tested without starting anything."""
    if not 0 < eps <= MAX_EPS:
        raise ValueError(f"events per second must be in (0, {MAX_EPS}]")
    if not 0 < minutes <= MAX_MINUTES:
        raise ValueError(f"minutes must be in (0, {MAX_MINUTES}]")
    vendors = VENDORS + ([UNKNOWN_VENDOR] if unknown else [])
    out = {"main": [_exe(), "gen", *[a for v in vendors for a in ("--vendor", v)], "--scenario", "mixed",
                    "--eps", f"{eps:g}", "--count", str(math.ceil(eps * minutes * 60)), "--transport", "udp",
                    "--seed", str(seed), "--sendlog", str(sendlog("main"))]}
    if malformed:
        rate = max(0.2, eps / 20)
        out["malformed"] = [_exe(), "gen", "--scenario", "malformed", "--eps", f"{rate:g}",
                            "--count", str(math.ceil(rate * minutes * 60)), "--transport", "udp",
                            "--seed", str(seed), "--sendlog", str(sendlog("malformed"))]
    return out


def _alive(pid: int) -> bool:
    """True while `pid` is a running `ulpf gen` (not a zombie, not a reused pid)."""
    try:
        os.waitpid(pid, os.WNOHANG)          # reap our own finished child; no-op for others
    except ChildProcessError:
        pass
    try:
        os.kill(pid, 0)
        stat = Path(f"/proc/{pid}/stat").read_text()
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
    except (ProcessLookupError, PermissionError, FileNotFoundError):
        return False
    return stat.rsplit(") ", 1)[-1][:1] != "Z" and b"\0gen\0" in cmdline


def _load() -> dict:
    try:
        return json.loads(_state_file().read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _lines(p: Path) -> int:
    try:
        with open(p, "rb") as fh:
            return sum(1 for _ in fh)
    except FileNotFoundError:
        return 0


def status() -> dict:
    st = _load()
    if not st:
        return {"running": False}
    pids = st.get("pids") or {}
    alive = sorted(name for name, pid in pids.items() if _alive(pid))
    sent = {name: _lines(sendlog(name)) for name in pids}
    return {**st, "running": bool(alive), "alive": alive, "sent": sum(sent.values()), "sent_by_stream": sent}


def start(eps: float, *, unknown: bool = True, malformed: bool = True, minutes: float = MAX_MINUTES) -> dict:
    """Start the generators (no-op while a demo is running)."""
    if status()["running"]:
        return status()
    now = time.time()
    cmds = commands(eps, unknown=unknown, malformed=malformed, minutes=minutes, seed=int(now))
    for d in (paths.RUN, paths.LOGS, paths.RUNTIME / "tmp"):
        d.mkdir(parents=True, exist_ok=True)
    pids = {}
    for name, argv in cmds.items():
        sendlog(name).unlink(missing_ok=True)
        with open(paths.LOGS / f"demo-{name}.log", "ab") as log:
            pids[name] = subprocess.Popen(argv, cwd=paths.HOME, stdout=log, stderr=subprocess.STDOUT,
                                          start_new_session=True).pid
    _state_file().write_text(json.dumps({"started_at": now, "ends_at": now + minutes * 60, "eps": eps,
                                         "unknown": unknown, "malformed": malformed, "pids": pids}))
    return status()


def stop() -> dict:
    """Stop the generators and forget the demo (no-op when none runs)."""
    st = _load()
    pids = [pid for pid in (st.get("pids") or {}).values() if _alive(pid)]
    for pid in pids:
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.time() + 5
    while time.time() < deadline and any(_alive(pid) for pid in pids):
        time.sleep(0.1)
    _state_file().unlink(missing_ok=True)
    return {"running": False, "stopped": len(pids)}
