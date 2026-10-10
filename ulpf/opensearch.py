"""Minimal OpenSearch REST client (stdlib only, ADR-012) and the ULPF index
template, which is *generated from the vendored OCSF dictionary* so that every
OCSF attribute gets the OpenSearch type its OCSF type implies.

OCSF attributes are globally typed by name (verified: only 5 of 1017
dictionary names deviate, all between string subtypes), so name-based dynamic
templates are exact.
"""
from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

from . import paths
from .ocsf import Ocsf, default as default_ocsf
from .settings import Settings, load as load_settings


class OpenSearchError(RuntimeError):
    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}: {body[:2000]}")
        self.status = status
        self.body = body


@dataclass
class Client:
    url: str
    user: str | None = None
    password: str | None = None
    ca_file: str | None = None
    timeout: float = 60

    @classmethod
    def from_settings(cls, settings: Settings | None = None, *, role: str = "admin") -> "Client":
        s = settings or load_settings()
        user = password = None
        u, p = paths.SECRETS / f"opensearch-{role}.user", paths.SECRETS / f"opensearch-{role}.password"
        if u.exists() and p.exists():
            user, password = u.read_text().strip(), p.read_text().strip()
        ca = paths.CERTS / "ulpf-ca.crt"
        return cls(s.opensearch_url, user, password, str(ca) if ca.exists() else None)

    def _ctx(self) -> ssl.SSLContext | None:
        if not self.url.startswith("https"):
            return None
        ctx = ssl.create_default_context(cafile=self.ca_file) if self.ca_file else ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    def request(self, method: str, path: str, body: Any = None, *, ndjson: bool = False,
                ok: Iterable[int] = (200, 201)) -> Any:
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            if ndjson:
                data = body if isinstance(body, bytes) else body.encode()
                headers["Content-Type"] = "application/x-ndjson"
            else:
                data = json.dumps(body).encode()
                headers["Content-Type"] = "application/json"
        if self.user is not None:
            tok = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
            headers["Authorization"] = f"Basic {tok}"
        req = urllib.request.Request(self.url.rstrip("/") + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx()) as resp:  # noqa: S310
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as e:
            raw, status = e.read(), e.code
        if status not in ok:
            raise OpenSearchError(status, raw.decode("utf-8", "replace"))
        return json.loads(raw) if raw else None

    # convenience -------------------------------------------------------
    def info(self) -> dict:
        return self.request("GET", "/")

    def exists(self, index: str) -> bool:
        try:
            self.request("HEAD", f"/{index}")
            return True
        except OpenSearchError as e:
            if e.status == 404:
                return False
            raise

    def count(self, index: str, query: dict | None = None) -> int:
        body = {"query": query} if query else None
        return int(self.request("POST", f"/{index}/_count", body)["count"])

    def search(self, index: str, body: dict) -> dict:
        return self.request("POST", f"/{index}/_search", body)

    def refresh(self, index: str) -> None:
        self.request("POST", f"/{index}/_refresh")

    def bulk(self, lines: bytes) -> dict:
        return self.request("POST", "/_bulk", lines, ndjson=True)

    def aliases(self, actions: list[dict]) -> None:
        self.request("POST", "/_aliases", {"actions": actions})

    def alias_targets(self, alias: str) -> list[str]:
        try:
            return sorted(self.request("GET", f"/_alias/{alias}").keys())
        except OpenSearchError as e:
            if e.status == 404:
                return []
            raise

    def scroll_all(self, index: str, query: dict | None = None, size: int = 1000,
                   source: list[str] | bool | None = None) -> Iterable[dict]:
        body: dict[str, Any] = {"size": size, "query": query or {"match_all": {}}, "sort": ["_doc"]}
        if source is not None:
            body["_source"] = source
        res = self.request("POST", f"/{index}/_search?scroll=2m", body)
        sid = res.get("_scroll_id")
        try:
            while True:
                hits = res["hits"]["hits"]
                if not hits:
                    break
                yield from hits
                res = self.request("POST", "/_search/scroll", {"scroll": "2m", "scroll_id": sid})
                sid = res.get("_scroll_id", sid)
        finally:
            if sid:
                try:
                    self.request("DELETE", "/_search/scroll", {"scroll_id": sid})
                except OpenSearchError:
                    pass


# ------------------------------------------------------------- index template
_OS_TYPE = {
    "ip_t": {"type": "ip"},
    "port_t": {"type": "integer"},
    "timestamp_t": {"type": "date", "format": "epoch_millis"},
    "long_t": {"type": "long"},
    # integer_t is mapped as long: some OCSF integer attributes (e.g. TCP
    # sequence numbers) can exceed int32 in real data.
    "integer_t": {"type": "long"},
    "float_t": {"type": "double"},
    "boolean_t": {"type": "boolean"},
    "datetime_t": {"type": "date"},
    # json_t can hold any JSON value; keep it in _source without indexing.
    "json_t": {"type": "object", "enabled": False},
}


def index_template(ocsf: Ocsf | None = None, *, index_prefix: str = "ulpf-events") -> dict:
    o = ocsf or default_ocsf()
    names_by_type: dict[str, list[str]] = defaultdict(list)
    for name, a in o.export["dictionary"]["attributes"].items():
        t = a.get("type")
        if t in _OS_TYPE:
            names_by_type[t].append(name)
    dyn = []
    for t in sorted(names_by_type):
        names = sorted(names_by_type[t])
        dyn.append({f"ocsf_{t}": {"match_pattern": "regex", "match": "^(" + "|".join(names) + ")$",
                                 "mapping": _OS_TYPE[t]}})
    dyn.append({"strings_as_keyword": {"match_mapping_type": "string",
                                       "mapping": {"type": "keyword", "ignore_above": 4096}}})
    return {
        "index_patterns": [f"{index_prefix}-v*"],
        "priority": 100,
        "_meta": {"generated_by": "ulpf", "ocsf_version": o.version},
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "refresh_interval": "1s",
                # Safety net (P0 finding O3): a malformed value never rejects
                # the whole document; it is listed in _ignored and kept in _source.
                "index.mapping.ignore_malformed": True,
                "index.mapping.total_fields.limit": 4000,
            },
            "mappings": {
                "dynamic": True,
                "dynamic_templates": dyn,
                "properties": {
                    "time": {"type": "date", "format": "epoch_millis"},
                    "message": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
                    "raw_data": {"type": "text"},
                    "unmapped": {"type": "flat_object"},
                    "ulpf": {"properties": {
                        "status": {"type": "keyword"},
                        "reasons": {"type": "keyword"},
                        "format": {"type": "keyword"},
                        "fingerprint": {"type": "keyword"},
                        "ingest": {"properties": {
                            "time": {"type": "date_nanos"},
                            "time_ms": {"type": "date", "format": "epoch_millis"},
                        }},
                        "raw": {"properties": {"b64": {"type": "binary"}}},
                        "lineage": {"type": "object", "enabled": False},
                        "errors": {"type": "object", "enabled": False},
                        "coverage": {"properties": {"ratio": {"type": "float"}}},
                    }},
                },
            },
        },
    }


def bootstrap(client: Client, settings: Settings | None = None) -> dict:
    """Install the template and create the first backing index + aliases if absent."""
    s = settings or load_settings()
    osc = s["opensearch"]
    client.request("PUT", f"/_index_template/{osc['index_prefix']}", index_template(index_prefix=osc["index_prefix"]))
    targets = client.alias_targets(osc["write_alias"])
    if targets:
        return {"template": "updated", "write_index": targets}
    first = f"{osc['index_prefix']}-v1"
    if not client.exists(first):
        client.request("PUT", f"/{first}", {"aliases": {
            osc["read_alias"]: {},
            osc["write_alias"]: {"is_write_index": True},
        }})
    return {"template": "installed", "write_index": [first]}
