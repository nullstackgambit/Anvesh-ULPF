"""Native process supervisor for the ULPF stack (ADR-002: no containers).

Services run as the invoking (non-root) user, bind to loopback by default,
write logs to runtime/logs and PID files to runtime/run.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import paths
from .settings import Settings, load as load_settings

OPENSEARCH_HOME = paths.RUNTIME / "opensearch"
DASHBOARDS_HOME = paths.RUNTIME / "opensearch-dashboards"
LIVE_CONFIG = paths.PIPELINE_GENERATED / "vector-live.yaml"
VECTOR_SHUTDOWN_LIMIT_S = 120


@dataclass
class Service:
    name: str
    cmd: Callable[[Settings], list[str]]
    env: Callable[[Settings], dict[str, str]]
    health: Callable[[Settings], bool]
    available: Callable[[], bool]
    cwd: Path = paths.HOME
    start_timeout: float = 120
    stop_timeout: float = 60


def _http_ok(url: str, timeout: float = 2.0, ok=(200,)) -> bool:
    try:
        ctx = None
        if url.startswith("https"):
            import ssl
            ca = paths.CERTS / "ulpf-ca.crt"
            ctx = ssl.create_default_context(cafile=str(ca)) if ca.exists() else ssl.create_default_context()
        req = urllib.request.Request(url)
        user, pw = paths.SECRETS / "opensearch-admin.user", paths.SECRETS / "opensearch-admin.password"
        if url.startswith("https") and user.exists():
            import base64
            tok = base64.b64encode(f"{user.read_text().strip()}:{pw.read_text().strip()}".encode()).decode()
            req.add_header("Authorization", f"Basic {tok}")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:  # noqa: S310 (loopback)
            return r.status in ok
    except Exception:  # noqa: BLE001 - any failure means "not healthy yet"
        return False


def _opensearch_conf(s: Settings) -> Path:
    """Render opensearch.yml into an ULPF-owned config dir each start."""
    conf = paths.RUNTIME / "opensearch-config"
    src = OPENSEARCH_HOME / "config"
    conf.mkdir(parents=True, exist_ok=True)
    for f in ("jvm.options", "log4j2.properties"):
        if (src / f).exists() and not (conf / f).exists():
            (conf / f).write_bytes((src / f).read_bytes())
    (conf / "jvm.options.d").mkdir(exist_ok=True)
    data = paths.DATA / "opensearch"
    (data / "data").mkdir(parents=True, exist_ok=True)
    (data / "logs").mkdir(parents=True, exist_ok=True)
    lines = [
        "# Rendered by `ulpf stack up` from deploy/ulpf.yaml - do not edit here.",
        "cluster.name: ulpf",
        "node.name: ulpf-node-1",
        f"path.data: {data / 'data'}",
        f"path.logs: {data / 'logs'}",
        "network.host: 127.0.0.1",
        "http.port: 9200",
        "transport.port: 9300",
        "discovery.type: single-node",
        # Absolute free-space watermarks: the default percentages refuse writes
        # on a nearly-full development disk.
        "cluster.routing.allocation.disk.watermark.low: 1500mb",
        "cluster.routing.allocation.disk.watermark.high: 1000mb",
        "cluster.routing.allocation.disk.watermark.flood_stage: 600mb",
        # Never auto-create ulpf-* indices (they must get the ULPF template and
        # aliases explicitly); other system indices may be auto-created.
        'action.auto_create_index: "-ulpf-*,+*"',
    ]
    sec = paths.RUNTIME / "opensearch-security.yml"
    if sec.exists():
        lines.append(sec.read_text())
    elif (OPENSEARCH_HOME / "plugins" / "opensearch-security").exists():
        lines.append("plugins.security.disabled: true")
    (conf / "opensearch.yml").write_text("\n".join(lines) + "\n")
    return conf


def _pii_env() -> dict[str, str]:
    key = paths.SECRETS / "pii.key"
    return {"ULPF_PII_KEY": key.read_text().strip()} if key.exists() else {}


SERVICES: dict[str, Service] = {
    "opensearch": Service(
        "opensearch",
        cmd=lambda s: [str(OPENSEARCH_HOME / "bin" / "opensearch")],
        env=lambda s: {"OPENSEARCH_PATH_CONF": str(_opensearch_conf(s)), "OPENSEARCH_JAVA_OPTS": os.environ.get("ULPF_OS_HEAP", "-Xms1g -Xmx1g")},
        health=lambda s: _http_ok(s.opensearch_url),
        available=lambda: (OPENSEARCH_HOME / "bin" / "opensearch").exists(),
        # first start with the security plugin initialises the security index
        start_timeout=300,
    ),
    "vector": Service(
        "vector",
        # On SIGTERM Vector stops its sources and drains every buffer; after
        # the graceful-shutdown limit it KILLS the components still draining
        # (their events are lost; verified with a slow sink). 120 s instead of
        # the default 60 s, and ulpf waits longer than that before SIGKILL.
        cmd=lambda s: [str(paths.VECTOR_BIN), "--config", str(LIVE_CONFIG), "--watch-config", "--color", "never",
                       "--graceful-shutdown-limit-secs", str(VECTOR_SHUTDOWN_LIMIT_S)],
        env=lambda s: {"TZ": "UTC", **_pii_env()},
        health=lambda s: _http_ok(f"http://{s['vector']['api_address']}/health"),
        available=lambda: paths.VECTOR_BIN.exists() and LIVE_CONFIG.exists(),
        # VRL type checking of all compiled specs dominates start-up (~50 s for
        # 13 specs on the reference VM; see VERIFICATION_REPORT finding P4b-1)
        start_timeout=240,
        stop_timeout=VECTOR_SHUTDOWN_LIMIT_S + 30,
    ),
    "dashboards": Service(
        "dashboards",
        cmd=lambda s: [str(DASHBOARDS_HOME / "bin" / "opensearch-dashboards"), "-c", str(paths.RUNTIME / "dashboards.yml")],
        env=lambda s: {},
        health=lambda s: _http_ok("http://127.0.0.1:5601/api/status"),
        available=lambda: (DASHBOARDS_HOME / "bin" / "opensearch-dashboards").exists() and (paths.RUNTIME / "dashboards.yml").exists(),
        start_timeout=240,
    ),
    "ui": Service(
        "ui",
        cmd=lambda s: [sys.executable, "-m", "streamlit", "run", str(paths.HOME / "ulpf" / "ui" / "app.py"),
                       "--server.address", "127.0.0.1", "--server.port", "8501", "--server.headless", "true",
                       # Streamlit collects usage statistics by default; an
                       # air-gapped deployment must not try to phone home.
                       "--browser.gatherUsageStats", "false",
                       # no "Deploy" (Streamlit Community Cloud) button / menu
                       "--client.toolbarMode", "minimal"],
        env=lambda s: {"STREAMLIT_BROWSER_GATHER_USAGE_STATS": "false"},
        health=lambda s: _http_ok("http://127.0.0.1:8501/_stcore/health"),
        available=lambda: (paths.HOME / "ulpf" / "ui" / "app.py").exists(),
        start_timeout=60,
    ),
}
ORDER = ["opensearch", "vector", "dashboards", "ui"]


def _pidfile(name: str) -> Path:
    return paths.RUN / f"{name}.pid"


def pid_of(name: str) -> int | None:
    pf = _pidfile(name)
    if not pf.exists():
        return None
    try:
        pid = int(pf.read_text().strip())
        os.kill(pid, 0)
        return pid
    except (ValueError, ProcessLookupError, PermissionError):
        return None


def start(name: str, s: Settings | None = None, wait: bool = True) -> str:
    s = s or load_settings()
    svc = SERVICES[name]
    if not svc.available():
        return f"{name}: not installed/configured (skipped)"
    if pid_of(name):
        return f"{name}: already running (pid {pid_of(name)})"
    if svc.health(s):
        return f"{name}: something already answers on its port; not starting a second instance"
    paths.RUN.mkdir(parents=True, exist_ok=True)
    paths.LOGS.mkdir(parents=True, exist_ok=True)
    if name == "vector":
        from .settings import load as _load

        inbox = _load()["listen"]["inbox_glob"]
        for d in (paths.VECTOR_DATA, paths.ARCHIVE_RAW, paths.NORMALIZED, paths.DLQ,
                  (paths.HOME / inbox).parent if not inbox.startswith("/") else Path(inbox).parent):
            d.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update(svc.env(s))
    log = open(paths.LOGS / f"{name}.log", "ab")  # noqa: SIM115 - inherited by the child
    proc = subprocess.Popen(svc.cmd(s), cwd=svc.cwd, env=env, stdout=log, stderr=subprocess.STDOUT,
                            start_new_session=True)
    _pidfile(name).write_text(str(proc.pid))
    if not wait:
        return f"{name}: started pid {proc.pid}"
    deadline = time.time() + svc.start_timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return f"{name}: EXITED with code {proc.returncode}; see {paths.LOGS / (name + '.log')}"
        if svc.health(s):
            return f"{name}: healthy (pid {proc.pid})"
        time.sleep(1)
    return f"{name}: started pid {proc.pid} but not healthy after {svc.start_timeout}s"


def stop(name: str, timeout: float | None = None) -> str:
    timeout = SERVICES[name].stop_timeout if timeout is None else timeout
    pid = pid_of(name)
    if not pid:
        _pidfile(name).unlink(missing_ok=True)
        return f"{name}: not running"
    log = paths.LOGS / f"{name}.log"
    log_at = log.stat().st_size if log.exists() else 0
    os.killpg(pid, signal.SIGTERM)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
            time.sleep(0.5)
        except ProcessLookupError:
            _pidfile(name).unlink(missing_ok=True)
            return f"{name}: stopped" + _shutdown_warning(name, log, log_at)
    os.killpg(pid, signal.SIGKILL)
    _pidfile(name).unlink(missing_ok=True)
    return f"{name}: KILLED after {timeout}s (buffered events may be lost: run `ulpf account`)"


def _shutdown_warning(name: str, log: Path, offset: int) -> str:
    """Vector logs when its graceful-shutdown limit forced it to kill
    components that were still draining: report it instead of "stopped"."""
    if name != "vector" or not log.exists():
        return ""
    with open(log, "rb") as fh:
        fh.seek(offset)
        tail = fh.read().decode("utf-8", "replace")
    if "Failed to gracefully shut down in time" in tail:
        return (f" -- WARNING: Vector killed components that had not drained within "
                f"{VECTOR_SHUTDOWN_LIMIT_S}s (buffered events may be lost: run `ulpf account`)")
    return ""


def status(s: Settings | None = None) -> list[tuple[str, str]]:
    s = s or load_settings()
    out = []
    for name in ORDER:
        svc = SERVICES[name]
        pid = pid_of(name)
        if not svc.available():
            out.append((name, "not installed"))
        elif pid and svc.health(s):
            out.append((name, f"healthy (pid {pid})"))
        elif pid:
            out.append((name, f"running, not healthy (pid {pid})"))
        elif svc.health(s):
            out.append((name, "answering, but not managed by ulpf"))
        else:
            out.append((name, "stopped"))
    return out
