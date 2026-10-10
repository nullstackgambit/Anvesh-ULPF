"""Phase 6 security against the RUNNING secured stack (`ulpf os secure`).

* OpenSearch: TLS only, no anonymous access, least-privilege users
* TLS syslog listener (Vector) with the deployment CA; plain TCP on the TLS
  port is not accepted as an event
* generated configurations never contain secret values

Payloads are SYNTHETIC TEST DATA.
"""
import base64
import hashlib
import json
import socket
import ssl
import time
import urllib.error
import urllib.request
import uuid

import pytest

from ulpf import paths
from ulpf.opensearch import Client
from ulpf.settings import load

pytestmark = [pytest.mark.opensearch, pytest.mark.vector]


@pytest.fixture(scope="module")
def s():
    st = load()
    if not st["opensearch"].get("security"):
        pytest.skip("security plugin not enabled (ulpf os secure)")
    return st


def _req(method, path, user=None, body=None, scheme="https"):
    ctx = ssl.create_default_context(cafile=str(paths.CERTS / "ulpf-ca.crt"))
    req = urllib.request.Request(f"{scheme}://127.0.0.1:9200{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    if user:
        pw = (paths.SECRETS / f"opensearch-{user}.password").read_text().strip()
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode())
    try:
        with urllib.request.urlopen(req, context=ctx if scheme == "https" else None, timeout=15) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, ConnectionError, OSError):
        return "refused"


def test_opensearch_access_control(s):
    assert _req("GET", "/", scheme="http") == "refused"
    assert _req("GET", "/") == 401
    assert _req("GET", "/", "admin") == 200
    assert _req("POST", "/ulpf-events/_search", "ulpf-reader", {"size": 0}) == 200
    assert _req("POST", "/ulpf-events-write/_doc", "ulpf-reader", {"probe": 1}) == 403
    assert _req("POST", "/ulpf-events/_search", "ulpf-writer", {"size": 0}) == 403
    assert _req("DELETE", "/ulpf-events-v1", "ulpf-writer") == 403
    assert _req("GET", "/_plugins/_security/api/internalusers", "ulpf-reader") == 403
    # demo users of the plugin's sample configuration do not exist
    req = urllib.request.Request("https://127.0.0.1:9200/", headers={"Authorization": "Basic " + base64.b64encode(b"admin:admin").decode()})
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req, context=ssl.create_default_context(cafile=str(paths.CERTS / "ulpf-ca.crt")), timeout=15)
    assert e.value.code == 401


def _find(c, sha, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        c.refresh(load()["opensearch"]["read_alias"])
        hits = c.search("ulpf-events", {"query": {"term": {"raw_data_hash.value": sha}}})["hits"]["hits"]
        if hits:
            return hits[0]["_source"]
        time.sleep(2)
    return None


def test_tls_syslog_round_trip_and_plaintext_rejected(s):
    host, port = s["listen"]["syslog_tls"].rsplit(":", 1)
    token = uuid.uuid4().hex
    line = f"<134>Oct  7 10:15:30 tls-host app: SYNTHETIC TEST DATA tls {token}".encode()
    ctx = ssl.create_default_context(cafile=str(paths.CERTS / "ulpf-ca.crt"))
    with socket.create_connection((host, int(port)), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            assert tls.version() in ("TLSv1.2", "TLSv1.3")
            tls.sendall(line + b"\n")
    plain_token = uuid.uuid4().hex
    plain = f"<134>Oct  7 10:15:30 tls-host app: SYNTHETIC TEST DATA plain {plain_token}".encode()
    with socket.create_connection((host, int(port)), timeout=10) as raw:
        raw.sendall(plain + b"\n")
        time.sleep(1)
    c = Client.from_settings(s)
    doc = _find(c, hashlib.sha256(line).hexdigest())
    assert doc is not None, "TLS syslog event not indexed"
    assert doc["ulpf"]["ingest"]["transport"] == "syslog-tls" and doc["raw_data"] == line.decode()
    assert _find(c, hashlib.sha256(plain).hexdigest(), timeout=8) is None


def test_tls_listener_presents_deployment_certificate(s):
    host, port = s["listen"]["syslog_tls"].rsplit(":", 1)
    with socket.create_connection((host, int(port)), timeout=10) as raw:
        with pytest.raises(ssl.SSLCertVerificationError):
            ssl.create_default_context().wrap_socket(raw, server_hostname="localhost")  # system CAs only


def test_generated_configs_contain_no_secrets(s):
    secrets = [p.read_text().strip() for p in paths.SECRETS.glob("*.password")] + [(paths.SECRETS / "pii.key").read_text().strip()]
    files = list((paths.PIPELINE_GENERATED).rglob("*")) + list((paths.RUNTIME / "tmp").glob("*.yaml"))
    for f in files:
        if f.is_file():
            text = f.read_text(errors="replace")
            for sec in secrets:
                assert sec not in text, f"secret value found in {f}"
