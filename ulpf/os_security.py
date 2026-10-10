"""`ulpf os secure`: enable the OpenSearch security plugin (TLS + users).

Uses ONLY locally generated material (`ulpf certs init`, `ulpf secrets init`)
and the SHA-256-pinned plugin from runtime/dist; the plugin's demo installer
and demo users (well-known passwords) are never used.

  TLS      HTTP and transport with the deployment CA (opensearch-node cert)
  users    admin        -> all_access          (control plane: template, aliases, replay)
           ulpf-writer  -> ulpf_writer         (Vector: bulk index into ulpf-*; no read, no delete)
           ulpf-reader  -> ulpf_reader         (UI / detections: read ulpf-*; no write)
  auth     HTTP basic against the internal user database; anonymous disabled
  hashes   BCrypt via the plugin's own Hasher (password passed in an
           environment variable, never on a command line)
  admin    the opensearch-admin client certificate is the only admin_dn

The security index is initialised from these files on first start
(plugins.security.allow_default_init_securityindex). Turning security on
writes runtime/ulpf.local.yaml (opensearch.security: true), which switches
every client (CLI, Vector, UI) to https + credentials.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import yaml

from . import paths, runtime

OS_HOME = paths.RUNTIME / "opensearch"
PLUGIN = OS_HOME / "plugins" / "opensearch-security"
CONF = paths.RUNTIME / "opensearch-config"
SEC_DIR = CONF / "opensearch-security"
FRAGMENT = paths.RUNTIME / "opensearch-security.yml"
LOCAL = paths.RUNTIME / "ulpf.local.yaml"
DN = "CN={cn},OU=ULPF deployment,O=ULPF"

ROLES = {
    "ulpf_writer": {
        "description": "Vector: write normalized events (no read, no delete, no admin)",
        "cluster_permissions": ["cluster_monitor", "indices:data/write/bulk"],
        "index_permissions": [{"index_patterns": ["ulpf-*"],
                               "allowed_actions": ["indices:data/write/index", "indices:data/write/bulk*",
                                                   "indices:admin/mapping/put"]}],
    },
    "ulpf_reader": {
        "description": "UI and detections: read normalized events",
        "cluster_permissions": ["cluster_composite_ops_ro"],
        "index_permissions": [{"index_patterns": ["ulpf-*"], "allowed_actions": ["read", "indices:admin/mappings/get"]}],
    },
}


def _hash(password: str) -> str:
    env = dict(os.environ, OPENSEARCH_JAVA_HOME=str(OS_HOME / "jdk"), ULPF_HASH_PW=password)
    p = subprocess.run(["bash", str(PLUGIN / "tools" / "hash.sh"), "-env", "ULPF_HASH_PW"], capture_output=True, text=True,
                       env=env, timeout=120)
    lines = [ln.strip() for ln in p.stdout.splitlines() if ln.strip().startswith("$2")]
    if p.returncode != 0 or not lines:
        raise RuntimeError(f"hash.sh failed: {p.stderr[-500:]}")
    return lines[-1]


def _meta(kind: str) -> dict:
    return {"_meta": {"type": kind, "config_version": 2}}


def _dump(path: Path, obj: dict) -> None:
    path.write_text("---\n" + yaml.safe_dump(obj, sort_keys=False))
    os.chmod(path, 0o600)


def enable() -> dict:
    from .credentials import password

    log = runtime.install(paths.RUNTIME / "dist", with_security=True)
    need = [paths.CERTS / f for f in ("ulpf-ca.crt", "opensearch-node.crt", "opensearch-node.key",
                                      "opensearch-admin.crt", "opensearch-admin.key")]
    need += [paths.SECRETS / f"opensearch-{u}.password" for u in ("admin", "ulpf-writer", "ulpf-reader")]
    missing = [str(p) for p in need if not p.exists()]
    if missing:
        raise RuntimeError("run `ulpf certs init` and `ulpf secrets init` first; missing: " + ", ".join(missing))
    certs = CONF / "certs"
    certs.mkdir(parents=True, exist_ok=True)
    for f in ("ulpf-ca.crt", "opensearch-node.crt", "opensearch-node.key", "opensearch-admin.crt", "opensearch-admin.key"):
        shutil.copy2(paths.CERTS / f, certs / f)
        os.chmod(certs / f, 0o600)
    SEC_DIR.mkdir(parents=True, exist_ok=True)
    # unchanged plugin defaults for files ULPF does not customise
    for f in ("action_groups.yml", "allowlist.yml", "nodes_dn.yml", "tenants.yml", "audit.yml"):
        shutil.copy2(PLUGIN / "config" / f, SEC_DIR / f)
    users = {"admin": {"hash": _hash(password("admin")), "reserved": True, "backend_roles": ["admin"],
                       "description": "ULPF control plane"},
             "ulpf-writer": {"hash": _hash(password("ulpf-writer")), "reserved": True, "description": "Vector index writer"},
             "ulpf-reader": {"hash": _hash(password("ulpf-reader")), "reserved": True, "description": "UI / detections reader"}}
    _dump(SEC_DIR / "internal_users.yml", {**_meta("internalusers"), **users})
    _dump(SEC_DIR / "roles.yml", {**_meta("roles"), **ROLES})
    _dump(SEC_DIR / "roles_mapping.yml", {**_meta("rolesmapping"),
                                          "all_access": {"reserved": True, "backend_roles": ["admin"], "users": ["admin"]},
                                          "ulpf_writer": {"reserved": True, "users": ["ulpf-writer"]},
                                          "ulpf_reader": {"reserved": True, "users": ["ulpf-reader"]}})
    _dump(SEC_DIR / "config.yml", {**_meta("config"), "config": {"dynamic": {
        "http": {"anonymous_auth_enabled": False, "xff": {"enabled": False}},
        "authc": {"basic_internal_auth_domain": {
            "description": "HTTP basic against the internal user database", "http_enabled": True, "transport_enabled": True,
            "order": 0, "http_authenticator": {"type": "basic", "challenge": True},
            "authentication_backend": {"type": "intern"}}},
        "authz": {}}}})
    FRAGMENT.write_text("\n".join([
        "# Rendered by `ulpf os secure` - security plugin (TLS + internal users).",
        "plugins.security.ssl.transport.pemcert_filepath: certs/opensearch-node.crt",
        "plugins.security.ssl.transport.pemkey_filepath: certs/opensearch-node.key",
        "plugins.security.ssl.transport.pemtrustedcas_filepath: certs/ulpf-ca.crt",
        "plugins.security.ssl.transport.enforce_hostname_verification: false",
        "plugins.security.ssl.http.enabled: true",
        "plugins.security.ssl.http.pemcert_filepath: certs/opensearch-node.crt",
        "plugins.security.ssl.http.pemkey_filepath: certs/opensearch-node.key",
        "plugins.security.ssl.http.pemtrustedcas_filepath: certs/ulpf-ca.crt",
        "plugins.security.allow_default_init_securityindex: true",
        f'plugins.security.authcz.admin_dn: ["{DN.format(cn="ulpf-admin")}"]',
        f'plugins.security.nodes_dn: ["{DN.format(cn="ulpf-opensearch-node")}"]',
        "plugins.security.audit.type: internal_opensearch",
        "plugins.security.enable_snapshot_restore_privilege: true",
        "plugins.security.check_snapshot_restore_write_privileges: true",
        'plugins.security.restapi.roles_enabled: ["all_access"]',
        "plugins.security.system_indices.enabled: true",
    ]) + "\n")
    LOCAL.write_text("# Written by `ulpf os secure` (this installation's overrides of deploy/ulpf.yaml)\n"
                     "opensearch:\n  security: true\n")
    return {"plugin": log or ["already installed"], "config_dir": str(SEC_DIR), "users": sorted(users),
            "local_override": str(LOCAL), "next": "ulpf stack down opensearch && ulpf stack up opensearch"}


def disable() -> dict:
    for p in (FRAGMENT, LOCAL):
        if p.exists():
            p.unlink()
    return {"security": False, "next": "ulpf stack down opensearch && ulpf stack up opensearch"}
