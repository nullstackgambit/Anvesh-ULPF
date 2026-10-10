"""Deployment settings loaded from deploy/ulpf.yaml (or ULPF_CONFIG)."""
from __future__ import annotations

import copy
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from . import paths
from .yamlsafe import load_file

DEFAULTS: dict[str, Any] = {
    "collector_id": "ulpf-collector-01",
    "timezone": "UTC",
    "listen": {
        "syslog_udp": "127.0.0.1:5514",
        "syslog_tcp": "127.0.0.1:5514",
        "syslog_tcp_octet": None,
        "syslog_tls": "127.0.0.1:6514",
        "http_ndjson": "127.0.0.1:8088",
        "inbox_glob": "runtime/data/inbox/*.log",
        "permit_origin": ["127.0.0.0/8"],
    },
    "limits": {"max_frame_bytes": 1048576, "max_parse_bytes": 65536},
    "archive": {"bucket": "minute"},
    "opensearch": {
        "url": "http://127.0.0.1:9200",
        "index_prefix": "ulpf-events",
        "read_alias": "ulpf-events",
        "write_alias": "ulpf-events-write",
        # buffer in front of the OpenSearch sink (outage protection); memory by
        # default: a Vector disk buffer is never smaller than 256 MiB on disk
        "buffer": {"type": "memory", "max_events": 50000, "max_bytes": 268435488, "when_full": "drop_newest"},
        # security plugin (TLS + users); set by `ulpf os secure` in runtime/ulpf.local.yaml
        "security": False,
    },
    "vector": {"api_address": "127.0.0.1:8686", "metrics_address": "127.0.0.1:9598"},
}
# Vector 0.58 rejects smaller disk buffers at start-up only (`vector validate`
# accepts them): "must be greater than or equal to 268435488 bytes" (P6 finding).
MIN_DISK_BUFFER = 268435488


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


@dataclass(frozen=True)
class Settings:
    raw: dict

    def __getitem__(self, key: str) -> Any:
        return self.raw[key]

    @property
    def opensearch_url(self) -> str:
        url = os.environ.get("ULPF_OPENSEARCH_URL", self.raw["opensearch"]["url"])
        if self.raw["opensearch"].get("security") and url.startswith("http://"):
            url = "https://" + url[len("http://"):]
        return url

    @property
    def archive_bucket_format(self) -> str:
        """strftime pattern used in archive file names (Vector path template)."""
        return {"minute": "%Y%m%dT%H%M", "hour": "%Y%m%dT%H"}[self.raw["archive"]["bucket"]]


@lru_cache(maxsize=1)
def load() -> Settings:
    data = load_file(paths.DEPLOY_CONFIG) if paths.DEPLOY_CONFIG.exists() else {}
    merged = _merge(DEFAULTS, data or {})
    # installation-local overrides written by the control plane (e.g. `ulpf os secure`)
    local = paths.RUNTIME / "ulpf.local.yaml"
    if local.exists():
        merged = _merge(merged, load_file(local) or {})
    if merged["archive"]["bucket"] not in ("minute", "hour"):
        raise ValueError("archive.bucket must be 'minute' or 'hour'")
    buf = merged["opensearch"]["buffer"]
    if buf.get("type", "memory") not in ("memory", "disk"):
        raise ValueError("opensearch.buffer.type must be memory or disk")
    if buf.get("type") == "disk" and int(buf["max_bytes"]) < MIN_DISK_BUFFER:
        raise ValueError(f"opensearch.buffer.max_bytes must be >= {MIN_DISK_BUFFER} (Vector disk buffer minimum)")
    if buf.get("type", "memory") == "memory" and int(buf.get("max_events", 0)) < 1:
        raise ValueError("opensearch.buffer.max_events must be >= 1")
    if buf["when_full"] not in ("drop_newest", "block"):
        raise ValueError("opensearch.buffer.when_full must be drop_newest or block")
    return Settings(merged)
