"""Assemble the Vector configuration (the ULPF data plane).

Two modes share every stage after the envelope (ADR-010):

* ``live``  network/file sources -> live envelope -> raw archive + parse chain
            -> normalized NDJSON, OpenSearch, DLQ, recorded losses, metrics.
* ``batch`` stdin with raw-archive records -> replay envelope -> parse chain
            -> stdout (golden tests, onboarding) or an OpenSearch index (replay).

The output is a single self-contained YAML file. It starts with a GENERATED
header that records the compiler version, the specs it was built from, and a
SHA-256 of the body; :func:`check_generated` refuses hand-edited files.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import __version__, paths
from .settings import Settings

_SAFE_VALUE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")
HEADER_TAG = "# GENERATED FILE - DO NOT EDIT"


@dataclass
class CompiledParser:
    spec_id: str
    version: str
    spec_sha256: str
    transform_id: str
    match_condition: str          # VRL boolean expression evaluated in detect
    priority: int
    vrl: str                      # full remap program


@dataclass
class Pipeline:
    parsers: list[CompiledParser] = field(default_factory=list)


def _safe(value: str, what: str) -> str:
    if not _SAFE_VALUE.match(value):
        raise ValueError(f"{what} {value!r} must match {_SAFE_VALUE.pattern}")
    return value


def render_static(name: str, **params: Any) -> str:
    """Load pipeline/vector/static/<name>.vrl and substitute @@KEY@@ placeholders.

    Values are restricted to a safe character set (or ints) so substitution can
    never inject VRL code.
    """
    text = (paths.PIPELINE_STATIC / f"{name}.vrl").read_text()
    for key, val in params.items():
        token = f"@@{key}@@"
        if isinstance(val, bool) or not isinstance(val, (int, str)):
            raise TypeError(f"{key}: only int/str placeholders are supported")
        rendered = str(val) if isinstance(val, int) else _safe(val, key)
        text = text.replace(token, rendered)
    left = re.findall(r"@@[A-Z_]+@@", text)
    if left:
        raise ValueError(f"{name}.vrl: unsubstituted placeholders {sorted(set(left))}")
    return text


def match_program(parsers: list[CompiledParser]) -> str:
    """Generated spec matching. Runs in its own transform so that every ._pre
    field is typed `any` again (VRL infers precise types inside the program
    that assigned them, which would make the generated `?? ""` fallbacks
    "unnecessary" -- error E651)."""
    lines = ["# GENERATED FILE - DO NOT EDIT (spec matching, compiled by `ulpf spec compile`)",
             "# First match wins; order = priority desc, then spec id.", ".ulpf.parser_id = null"]
    ordered = sorted(parsers, key=lambda p: (-p.priority, p.spec_id))
    if ordered:
        lines.append("if .ulpf.oversized != true && !exists(.ulpf.integrity_error) {")
        for i, p in enumerate(ordered):
            kw = "if" if i == 0 else "} else if"
            lines.append(f"  {kw} {p.match_condition} {{")
            lines.append(f'    .ulpf.parser_id = "{_safe(p.spec_id, "spec id")}"')
        lines.append("  }")
        lines.append("}")
    return "\n".join(lines) + "\n"


def _parser_stages(settings: Settings, pl: Pipeline, detect_input: str) -> tuple[dict, list[str]]:
    """Transforms from detect to finalize; returns (transforms, finalize_inputs)."""
    t: dict[str, Any] = {}
    t["ulpf_preparse"] = {"type": "remap", "inputs": [detect_input],
                          "source": render_static("preparse", MAX_PARSE_BYTES=int(settings["limits"]["max_parse_bytes"])),
                          "drop_on_error": True, "drop_on_abort": True, "reroute_dropped": True}
    t["ulpf_match"] = {"type": "remap", "inputs": ["ulpf_preparse"], "source": match_program(pl.parsers),
                       "drop_on_error": True, "drop_on_abort": True, "reroute_dropped": True}
    routes = {p.transform_id: f'.ulpf.parser_id == "{p.spec_id}"' for p in pl.parsers}
    fallback_inputs = ["ulpf_preparse.dropped", "ulpf_match.dropped"]
    if routes:
        t["ulpf_route"] = {"type": "route", "inputs": ["ulpf_match"], "route": routes}
        fallback_inputs.append("ulpf_route._unmatched")
    else:
        fallback_inputs.append("ulpf_match")
    t["ulpf_fallback"] = {"type": "remap", "inputs": fallback_inputs, "source": render_static("fallback")}
    finalize_inputs = ["ulpf_fallback"]
    failed_inputs = []
    for p in pl.parsers:
        t[p.transform_id] = {
            "type": "remap", "inputs": [f"ulpf_route.{p.transform_id}"], "source": p.vrl,
            "drop_on_error": True, "drop_on_abort": True, "reroute_dropped": True,
        }
        finalize_inputs.append(p.transform_id)
        failed_inputs.append(f"{p.transform_id}.dropped")
    if failed_inputs:
        t["ulpf_failed"] = {"type": "remap", "inputs": failed_inputs, "source": render_static("failed")}
        finalize_inputs.append("ulpf_failed")
    t["ulpf_finalize"] = {"type": "remap", "inputs": finalize_inputs,
                          "source": render_static("finalize", ULPF_VERSION=__version__, OCSF_VERSION=paths.OCSF_VERSION)}
    return t, finalize_inputs


def _hostport(addr: str) -> tuple[str, int]:
    host, _, port = addr.rpartition(":")
    return host, int(port)


def live_config(settings: Settings, pl: Pipeline) -> dict:
    s = settings
    lim = int(s["limits"]["max_frame_bytes"])
    cid = _safe(s["collector_id"], "collector_id")
    listen = s["listen"]
    permit = list(listen.get("permit_origin") or [])
    bucket = s.archive_bucket_format
    sources: dict[str, Any] = {}
    tags: dict[str, Any] = {}

    def sock(name: str, mode: str, addr: str, framing: dict | None, transport: str) -> None:
        src: dict[str, Any] = {"type": "socket", "mode": mode, "address": addr, "decoding": {"codec": "bytes"}}
        if framing:
            src["framing"] = framing
        # Vector 0.58 accepts permit_origin only for TCP sockets; UDP origin
        # filtering must come from the bind address / host firewall.
        if permit and mode == "tcp":
            src["permit_origin"] = permit
        sources[name] = src
        tags[f"tag_{name}"] = {"type": "remap", "inputs": [name],
                               "source": f'.ulpf_t = "{transport}"\n.ulpf_peer = {{"ip": .host, "port": .port}}\n'}

    sock("in_syslog_udp", "udp", listen["syslog_udp"], {"method": "bytes"}, "syslog-udp")
    sock("in_syslog_tcp", "tcp", listen["syslog_tcp"],
         {"method": "newline_delimited", "newline_delimited": {"max_length": lim}}, "syslog-tcp")
    if listen.get("syslog_tcp_octet"):
        # Opt-in only: Vector 0.58's octet_counting framer is NOT byte-transparent.
        # A frame with invalid UTF-8 makes it drop that frame and every later
        # frame on the connection (P0 finding V20); see README.md, Known limitations.
        sock("in_syslog_tcp_octet", "tcp", listen["syslog_tcp_octet"],
             {"method": "octet_counting", "octet_counting": {"max_length": lim}}, "syslog-tcp-octet")
    tls_cert = paths.CERTS / "ulpf-server.crt"
    tls_key = paths.CERTS / "ulpf-server.key"
    if tls_cert.exists() and tls_key.exists():
        sock("in_syslog_tls", "tcp", listen["syslog_tls"],
             {"method": "newline_delimited", "newline_delimited": {"max_length": lim}}, "syslog-tls")
        sources["in_syslog_tls"]["tls"] = {"enabled": True, "crt_file": str(tls_cert), "key_file": str(tls_key)}
        ca = paths.CERTS / "ulpf-ca.crt"
        if ca.exists():
            sources["in_syslog_tls"]["tls"]["ca_file"] = str(ca)
    sources["in_http"] = {"type": "http_server", "address": listen["http_ndjson"], "decoding": {"codec": "bytes"},
                          "framing": {"method": "newline_delimited", "newline_delimited": {"max_length": lim}}}
    tags["tag_in_http"] = {"type": "remap", "inputs": ["in_http"],
                           "source": '.ulpf_t = "http"\n.ulpf_peer = {"ip": .host}\n'}
    inbox = listen["inbox_glob"]
    inbox = str((paths.HOME / inbox).resolve()) if not inbox.startswith("/") else inbox
    # The file source always yields raw bytes (no decoding option); lines longer
    # than max_line_bytes are discarded by Vector and logged (recorded loss).
    sources["in_inbox"] = {"type": "file", "include": [inbox], "read_from": "beginning", "max_line_bytes": lim}
    tags["tag_in_inbox"] = {"type": "remap", "inputs": ["in_inbox"],
                            "source": '.ulpf_t = "file"\n.ulpf_peer = {"file": .file, "host": .host}\n'}
    sources["ulpf_internal_logs"] = {"type": "internal_logs"}
    sources["ulpf_internal_metrics"] = {"type": "internal_metrics", "scrape_interval_secs": 5}

    transforms: dict[str, Any] = dict(tags)
    transforms["ulpf_envelope"] = {"type": "remap", "inputs": list(tags), "source": render_static("envelope", COLLECTOR_ID=cid)}
    transforms["ulpf_archive_record"] = {"type": "remap", "inputs": ["ulpf_envelope"], "source": render_static("archive_record")}
    parse_t, _ = _parser_stages(settings, pl, "ulpf_envelope")
    transforms.update(parse_t)
    transforms["ulpf_dlq_filter"] = {"type": "filter", "inputs": ["ulpf_finalize"],
                                     "condition": '.ulpf.status == "fallback" || .ulpf.status == "failed"'}
    # File sinks write one line per event in one write() each: batch lines with
    # reduce (<= 1000 lines, flushed at least every 500 ms) -> ~11k lines/s
    # instead of ~210/s on the reference VM; bytes per line are unchanged.
    line = 'del(._osid)\n. = {"message": encode_json(.), "timestamp": now()}\n'
    transforms["ulpf_normalized_line"] = {"type": "remap", "inputs": ["ulpf_finalize"], "source": line}
    transforms["ulpf_dlq_line"] = {"type": "remap", "inputs": ["ulpf_dlq_filter"], "source": line}
    for name, src in (("ulpf_archive_batch", "ulpf_archive_record"), ("ulpf_normalized_batch", "ulpf_normalized_line"),
                      ("ulpf_dlq_batch", "ulpf_dlq_line")):
        transforms[name] = {"type": "reduce", "inputs": [src], "merge_strategies": {"message": "concat_newline"},
                            "max_events": 1000, "expire_after_ms": 500, "end_every_period_ms": 500, "flush_period_ms": 100}
    # Vector's own warnings/errors (discarded frames, rejected bulk items,
    # dropped events) are written next to the DLQ as recorded losses (P0 V15).
    transforms["ulpf_loss_filter"] = {"type": "filter", "inputs": ["ulpf_internal_logs"],
                                      "condition": 'includes(["WARN", "ERROR"], .metadata.level) && '
                                                   '!starts_with(string(.message) ?? "", "Source has acknowledgements enabled by a sink") && '
                                                   '!contains(string(.message) ?? "", "[Source has acknowledgements enabled by a sink")'}

    osc = s["opensearch"]
    sinks: dict[str, Any] = {
        "out_archive": {
            "type": "file", "inputs": ["ulpf_archive_batch"],
            "path": str(paths.ARCHIVE_RAW / "%Y-%m-%d" / f"raw-{bucket}-{cid}.ndjson"),
            "encoding": {"codec": "text"},
            "idle_timeout_secs": 30,
            "acknowledgements": {"enabled": True},
        },
        "out_normalized": {
            "type": "file", "inputs": ["ulpf_normalized_batch"],
            "path": str(paths.NORMALIZED / "%Y-%m-%d" / f"events-{bucket}-{cid}.ndjson"),
            "encoding": {"codec": "text"},
            "idle_timeout_secs": 30,
            "acknowledgements": {"enabled": True},
        },
        "out_dlq": {
            "type": "file", "inputs": ["ulpf_dlq_batch"],
            "path": str(paths.DLQ / "%Y-%m-%d" / f"dlq-{bucket}-{cid}.ndjson"),
            "encoding": {"codec": "text"},
            "idle_timeout_secs": 30,
        },
        "out_losses": {
            "type": "file", "inputs": ["ulpf_loss_filter"],
            "path": str(paths.DLQ / "%Y-%m-%d" / f"vector-internal-{cid}.ndjson"),
            "encoding": {"codec": "json"},
        },
        "out_opensearch": {
            "type": "elasticsearch", "inputs": ["ulpf_finalize"],
            "endpoints": [s.opensearch_url],
            # api_version auto sends `_type`, which OpenSearch 3.x rejects and
            # Vector then drops the events (P0 finding V11).
            "api_version": "v8",
            "mode": "bulk",
            "bulk": {"index": osc["write_alias"], "action": "index"},
            "id_key": "_osid",
            "healthcheck": {"enabled": True},
            "acknowledgements": {"enabled": True},
            # OpenSearch outages must never back-pressure the raw archive: the
            # index gets its own buffer that drops when full (losses are logged
            # and `ulpf replay missing` re-indexes them from the archive).
            "buffer": _os_buffer(osc["buffer"]),
        },
        "out_metrics": {"type": "prometheus_exporter", "inputs": ["ulpf_internal_metrics"],
                        "address": s["vector"]["metrics_address"]},
    }
    cfg = {
        "data_dir": str(paths.VECTOR_DATA),
        "timezone": s["timezone"],
        "api": {"enabled": True, "address": s["vector"]["api_address"]},
        "sources": sources,
        "transforms": transforms,
        "sinks": sinks,
    }
    if _apply_opensearch_auth(sinks["out_opensearch"]):
        cfg["secret"] = _secret_backend()
    return cfg


def _os_buffer(b: dict) -> dict:
    """memory: up to max_events in RAM (lost on a Vector restart -> replay
    missing); disk: survives restarts but Vector allocates >= 256 MiB."""
    if b.get("type", "memory") == "disk":
        return {"type": "disk", "max_size": int(b["max_bytes"]), "when_full": b["when_full"]}
    return {"type": "memory", "max_events": int(b["max_events"]), "when_full": b["when_full"]}


SECRET_BACKEND = "ulpf_secrets"


def _secret_backend() -> dict:
    """Vector `directory` secret backend over runtime/secrets: the generated
    config references `SECRET[ulpf_secrets.<file>]` and never contains the
    secret itself (Vector 0.58 also refuses ${ENV} interpolation unless
    started with --dangerously-allow-env-var-interpolation)."""
    return {SECRET_BACKEND: {"type": "directory", "path": str(paths.SECRETS), "remove_trailing_whitespace": True}}


def _apply_opensearch_auth(sink: dict) -> bool:
    """Use credentials/CA from runtime/secrets when the secured stack is installed.
    Returns True when the config needs the secret backend."""
    user_file = paths.SECRETS / "opensearch-ulpf-writer.user"
    pass_file = paths.SECRETS / "opensearch-ulpf-writer.password"
    ca = paths.CERTS / "ulpf-ca.crt"
    used = False
    if user_file.exists() and pass_file.exists() and sink["endpoints"][0].startswith("https"):
        sink["auth"] = {"strategy": "basic", "user": user_file.read_text().strip(),
                        "password": f"SECRET[{SECRET_BACKEND}.{pass_file.name}]"}
        used = True
    if sink["endpoints"][0].startswith("https") and ca.exists():
        sink["tls"] = {"ca_file": str(ca), "verify_certificate": True, "verify_hostname": True}
    return used


def batch_config(settings: Settings, pl: Pipeline, *, replay_run: str, sink: dict | None = None) -> dict:
    """stdin (archive records) -> ... -> stdout, or a caller-supplied sink."""
    sources = {"in_records": {"type": "stdin", "decoding": {"codec": "json"},
                              "framing": {"method": "newline_delimited",
                                          "newline_delimited": {"max_length": 16 * 1024 * 1024}}}}
    transforms: dict[str, Any] = {
        "ulpf_envelope": {"type": "remap", "inputs": ["in_records"],
                          "source": render_static("replay_envelope", REPLAY_RUN=replay_run)},
    }
    parse_t, _ = _parser_stages(settings, pl, "ulpf_envelope")
    transforms.update(parse_t)
    out = sink or {"type": "console", "encoding": {"codec": "json", "except_fields": ["_osid"]}}
    out = dict(out, inputs=["ulpf_finalize"])
    cfg = {
        "data_dir": str(paths.VECTOR_DATA / f"batch-{replay_run}"),
        "timezone": settings["timezone"],
        "sources": sources,
        "transforms": transforms,
        "sinks": {"out": out},
    }
    if out["type"] == "elasticsearch" and _apply_opensearch_auth(out):
        cfg["secret"] = _secret_backend()
    return cfg


def preparse_config(settings: Settings, *, replay_run: str) -> dict:
    """stdin (archive records) -> replay envelope -> preparse -> stdout.

    Onboarding uses this to see unknown events exactly as the runtime's
    pre-parser does (body, syslog header, detected layers) instead of
    re-implementing that logic in Python.
    """
    project = (
        '. = {"event_uid": .ulpf.event_uid, "format": .ulpf.format, "fingerprint": .ulpf.fingerprint,\n'
        '     "oversized": .ulpf.oversized == true, "integrity_error": .ulpf.integrity_error, "pre": ._pre}\n'
    )
    return {
        "data_dir": str(paths.VECTOR_DATA / f"batch-{replay_run}"),
        "timezone": settings["timezone"],
        "sources": {"in_records": {"type": "stdin", "decoding": {"codec": "json"},
                                   "framing": {"method": "newline_delimited",
                                               "newline_delimited": {"max_length": 16 * 1024 * 1024}}}},
        "transforms": {
            "ulpf_envelope": {"type": "remap", "inputs": ["in_records"],
                              "source": render_static("replay_envelope", REPLAY_RUN=replay_run)},
            "ulpf_preparse": {"type": "remap", "inputs": ["ulpf_envelope"],
                              "source": render_static("preparse", MAX_PARSE_BYTES=int(settings["limits"]["max_parse_bytes"]))},
            "ulpf_project": {"type": "remap", "inputs": ["ulpf_preparse"], "source": project},
        },
        "sinks": {"out": {"type": "console", "inputs": ["ulpf_project"], "encoding": {"codec": "json"}}},
    }


# --------------------------------------------------------------------- output
class _Dumper(yaml.SafeDumper):
    pass


def _str_repr(dumper: yaml.SafeDumper, data: str):
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_Dumper.add_representer(str, _str_repr)


def dump(config: dict, *, specs: list[CompiledParser], purpose: str) -> str:
    body = yaml.dump(config, Dumper=_Dumper, sort_keys=False, width=200, allow_unicode=False)
    digest = hashlib.sha256(body.encode()).hexdigest()
    spec_lines = [f"#   {p.spec_id}@{p.version} sha256:{p.spec_sha256}" for p in sorted(specs, key=lambda p: p.spec_id)] or ["#   (none)"]
    header = [
        HEADER_TAG,
        f"# purpose: {purpose}",
        f"# compiler: ulpf {__version__} | OCSF {paths.OCSF_VERSION} | generated {_dt.datetime.now(_dt.timezone.utc).isoformat(timespec='seconds')}",
        "# source specifications:",
        *spec_lines,
        "# Regenerate with `ulpf spec compile`; edits are detected by the hash below.",
        f"# content-sha256: {digest}",
    ]
    return "\n".join(header) + "\n" + body


def check_generated(path: Path) -> tuple[bool, str]:
    text = path.read_text()
    if not text.startswith(HEADER_TAG):
        return False, f"{path} lacks the GENERATED header"
    head, _, body = text.partition("\n# content-sha256: ")
    recorded, _, rest = body.partition("\n")
    actual = hashlib.sha256(rest.encode()).hexdigest()
    if recorded.strip() != actual:
        return False, f"{path} was modified after generation (recorded {recorded.strip()[:12]}, actual {actual[:12]})"
    return True, "ok"
