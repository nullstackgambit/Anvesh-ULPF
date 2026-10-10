"""Thin wrapper around the Vector binary.

ULPF never re-implements parsing in Python (ADR-010): golden tests, replay and
onboarding all push events through the real Vector binary via these helpers.
"""
from __future__ import annotations

import json
import os
import re
import signal
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from . import paths

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


class VectorError(RuntimeError):
    pass


def binary() -> Path:
    b = paths.VECTOR_BIN
    if not b.exists():
        raise VectorError(f"Vector binary not found at {b} (run `make runtime` or set ULPF_VECTOR_BIN)")
    return b


def version() -> str:
    out = subprocess.run([str(binary()), "--version"], capture_output=True, text=True, check=True).stdout
    return out.strip()


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


# Warnings that are understood and accepted. Every other warning fails
# validation (equivalent to --deny-warnings).
ACCEPTED_WARNINGS = [
    # Syslog over UDP/TCP has no delivery acknowledgement protocol; sink-level
    # acks still protect the file and HTTP inputs. Documented in
    # README.md, Known limitations ("syslog transports cannot be acknowledged").
    re.compile(r"Source has acknowledgements enabled by a sink, but acknowledgements are not supported by this source"),
    re.compile(r"Internal log \[Source has acknowledgements enabled by a sink"),
    # VRL's own style checker (e.g. "unexpected identifier `x` reported as
    # used") - informational, not a configuration problem.
    re.compile(r"vrl::compiler::unused_expression_checker"),
]


def validate(config: Path, *, environment: bool = False) -> tuple[bool, str]:
    """`vector validate`, failing on any warning not in ACCEPTED_WARNINGS.

    With environment=False sinks and health checks are not contacted.
    """
    cmd = [str(binary()), "validate"]
    if not environment:
        cmd.append("--no-environment")
    cmd.append(str(config))
    p = subprocess.run(cmd, capture_output=True, text=True, env=_env())
    out = strip_ansi(p.stdout + p.stderr)
    unexpected = [
        line for line in out.splitlines()
        if " WARN " in line and not any(rx.search(line) for rx in ACCEPTED_WARNINGS)
    ]
    if unexpected:
        out += "\nULPF: unaccepted warnings:\n" + "\n".join(unexpected)
    return p.returncode == 0 and not unexpected, out


def _env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ)
    # Vector prints coloured logs to a TTY; keep logs machine-readable.
    env.setdefault("VECTOR_COLOR", "never")
    env["TZ"] = "UTC"
    env.update(extra or {})
    return env


def run_batch(config: Path, stdin: bytes, *, timeout: float = 120, env: dict[str, str] | None = None) -> tuple[bytes, str]:
    """Run Vector once over ``stdin`` (stdin source) and return (stdout, stderr).

    The config must use a `stdin` source; Vector exits when stdin closes and
    all sinks have flushed.
    """
    p = subprocess.run(
        [str(binary()), "--config", str(config), "--quiet"],
        input=stdin,
        capture_output=True,
        timeout=timeout,
        env=_env(env),
    )
    err = strip_ansi(p.stderr.decode("utf-8", "replace"))
    if p.returncode != 0:
        raise VectorError(f"vector exited {p.returncode}:\n{err[-4000:]}")
    return p.stdout, err


def run_vrl(program: str, event: dict | None = None) -> dict:
    """Evaluate a VRL program against one event with `vector vrl` (UTC).

    The program's result object must be JSON-representable (convert
    timestamps with format_timestamp before returning them).
    """
    with tempfile.TemporaryDirectory(prefix="ulpf-vrl-") as d:
        prog = Path(d) / "p.vrl"
        inp = Path(d) / "in.json"
        prog.write_text(program)
        inp.write_text(json.dumps(event or {}) + "\n")
        p = subprocess.run(
            [str(binary()), "vrl", "-z", "UTC", "--input", str(inp), "--program", str(prog), "--print-object"],
            capture_output=True,
            text=True,
            env=_env(),
        )
        out = strip_ansi(p.stdout).strip()
        if p.returncode != 0 or not out:
            raise VectorError(strip_ansi(p.stdout + p.stderr)[-4000:])
        return json.loads(out, strict=False)  # `vector vrl` prints raw control characters inside strings


@dataclass
class Running:
    proc: subprocess.Popen
    log_path: Path

    def stop(self, timeout: float = 30) -> int:
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        return self.proc.returncode

    def log(self) -> str:
        return strip_ansi(self.log_path.read_text(errors="replace")) if self.log_path.exists() else ""


def start(config: Path, log_path: Path, *, watch: bool = False, env: dict[str, str] | None = None) -> Running:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [str(binary()), "--config", str(config)]
    if watch:
        cmd.append("--watch-config")
    fh = open(log_path, "ab")  # noqa: SIM115 (kept open for the child's lifetime)
    proc = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT, env=_env(env), start_new_session=True)
    return Running(proc, log_path)


def wait_tcp(host: str, port: int, timeout: float = 30) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def vrl_warnings(program: str) -> list[str]:
    """Compile-time warnings of a VRL program (e.g. E900 unused variable).

    `vector validate` does not print these; Vector only logs them when the
    topology starts, so the build checks every generated program here.
    """
    with tempfile.TemporaryDirectory(prefix="ulpf-vrlw-") as d:
        prog, inp = Path(d) / "p.vrl", Path(d) / "in.json"
        prog.write_text(program)
        inp.write_text("{}\n")
        p = subprocess.run([str(binary()), "vrl", "--print-warnings", "--input", str(inp), "--program", str(prog)],
                           capture_output=True, text=True, env=_env())
        out = strip_ansi(p.stdout + p.stderr)
        return [line.strip() for line in out.splitlines() if line.strip().startswith("warning[")]
