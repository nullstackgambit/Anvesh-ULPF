"""Filesystem layout. Everything is relative to ULPF_HOME (the repository or
install directory) unless overridden by environment variables, so the same
tree works from a git checkout and from an extracted air-gap bundle."""
from __future__ import annotations

import os
from pathlib import Path

OCSF_VERSION = "1.9.0"


def _env_path(name: str, default: Path) -> Path:
    v = os.environ.get(name)
    return Path(v).expanduser().resolve() if v else default


HOME = _env_path("ULPF_HOME", Path(__file__).resolve().parent.parent)
RUNTIME = _env_path("ULPF_RUNTIME", HOME / "runtime")
DATA = _env_path("ULPF_DATA", RUNTIME / "data")

SCHEMA = HOME / "schema"
OCSF = SCHEMA / "ocsf" / OCSF_VERSION
SPEC_SCHEMA = SCHEMA / "spec.schema.json"
PROVENANCE_SCHEMA = SCHEMA / "provenance.schema.json"

SPECS = HOME / "specs"
DRAFTS = SPECS / "_drafts"
SAMPLES = HOME / "samples"
DETECTIONS = HOME / "detections"
DEPLOY = HOME / "deploy"
DEPLOY_CONFIG = _env_path("ULPF_CONFIG", DEPLOY / "ulpf.yaml")
KEYS = _env_path("ULPF_KEYS", DEPLOY / "keys")
CERTS = _env_path("ULPF_CERTS", DEPLOY / "certs")

PIPELINE = HOME / "pipeline" / "vector"
PIPELINE_STATIC = PIPELINE / "static"
PIPELINE_GENERATED = PIPELINE / "generated"

VECTOR_BIN = _env_path("ULPF_VECTOR_BIN", RUNTIME / "vector" / "bin" / "vector")

# Runtime data layout (written by Vector and by the control plane).
ARCHIVE = DATA / "archive"
ARCHIVE_RAW = ARCHIVE / "raw"            # Vector writes raw records here
ARCHIVE_MANIFESTS = ARCHIVE / "manifests"  # ulpf seal writes signed manifests here
ARCHIVE_INDEX = ARCHIVE / "index.sqlite"   # event_uid -> record location
NORMALIZED = DATA / "normalized"         # normalized OCSF NDJSON (system of record)
DLQ = DATA / "dlq"                       # fallback/failed events + recorded losses
ONBOARDING = DATA / "onboarding"         # unknown-source queue
STATE = DATA / "state"                   # baselines, gate reports, approvals
LAKE = DATA / "lake"                     # Parquet
VECTOR_DATA = DATA / "vector"            # Vector's data_dir (buffers, checkpoints)
LOGS = RUNTIME / "logs"
RUN = RUNTIME / "run"                    # pid files
SECRETS = _env_path("ULPF_SECRETS", RUNTIME / "secrets")
