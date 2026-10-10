# Architecture decisions

Each entry: decision, reason, alternatives, evidence, trade-offs, date. When
later evidence disproves an assumption, the entry is amended (never silently
rewritten) — see the "Amended" lines.

---

## ADR-001 — OCSF 1.9.0 is the canonical model; ULPF adds one envelope key
* **Decision:** normalized documents are OCSF 1.9.0 events plus a single
  top-level `ulpf` object (provenance, status, coverage, lineage). OCSF-native
  slots are used wherever they exist (`metadata.uid`, `logged_time`,
  `processed_time`, `original_time`, `log_format`, `loggers`,
  `transformation_info_list`, `raw_data`, `raw_data_hash`, `raw_data_size`,
  `unmapped`).
* **Reason:** do not invent a competing schema; keep everything that OCSF
  cannot express in one clearly-owned place.
* **Alternatives:** an OCSF *extension* (needs a compiled server build to get
  JSON Schemas); stuffing provenance into `unmapped` (pollutes source data).
* **Evidence:** P0 finding S4.
* **Trade-off:** strict OCSF consumers must drop the `ulpf` key
  (`ulpf export --ocsf-only`). Validation strips it before the OCSF layers.
* **Date:** 2026-10-07

## ADR-002 — Native user-level processes instead of Docker
* **Decision:** Vector, OpenSearch (and Dashboards, Streamlit) run as
  ordinary user processes from verified upstream tarballs, supervised by
  `ulpf stack`. No container files are shipped.
* **Reason:** Docker/Podman are not installed, sudo is unavailable, and rootless
  containers are blocked by AppArmor userns restrictions.
* **Alternatives:** rootless Podman (needs `newuidmap` + AppArmor profile);
  daemonless image building with crane (images still could not be run).
* **Evidence:** P0 §1.
* **Trade-off:** requirement "containerized" is **not implemented**; platform
  independence comes from a static musl Vector, OpenSearch with bundled JDK and
  pure wheels for CPython 3.12 x86_64.
* **Date:** 2026-10-07

## ADR-003 — OpenSearch *min* distribution + security plugin
* **Decision:** `opensearch-min-3.8.0` plus `opensearch-security-3.8.0.0`
  from Maven Central.
* **Reason:** the full bundle is 1 GB compressed; the host had 3.4–5.3 GB free.
* **Evidence:** measured sizes (min 240 MB → 453 MB unpacked).
* **Trade-off:** plugins beyond security (alerting, SQL, …) are absent.
* **Date:** 2026-10-07

## ADR-004 — Byte-preserving intake with `socket`/`file` sources and `bytes` codec
* **Decision:** never use Vector's `syslog` source; receive frames as bytes,
  hash and base64 them in VRL before any parsing.
* **Reason:** the `syslog` source parses the header and keeps only the message.
* **Evidence:** P0 V1–V4.
* **Trade-off:** syslog parsing is done in VRL (needed anyway for V9/V10).
* **Date:** 2026-10-07

## ADR-005 — Vector 0.58.0 (musl)
* **Decision / reason:** 0.59.0 shipped the day before work began; 0.58.0 had
  six weeks without a patch release. Static musl build for portability.
* **Upgrade path:** `make test` includes the platform-assumption tests that
  pin every relied-upon behaviour (P0 table).
* **Date:** 2026-10-07

## ADR-006 — `elasticsearch` sink with `api_version: v8` against OpenSearch
* **Decision:** explicit `api_version: v8`, `id_key: _osid`, `action: index`.
* **Reason:** `auto` sends `_type`, OpenSearch 3.8 rejects it and Vector drops
  the events (P0 V11). `index` (not `create`) makes re-delivery idempotent
  because `_id` is the event UID.
* **Date:** 2026-10-07

## ADR-007 — Tamper-evident raw archive
* **Decision:** Vector writes one JSON record per event
  (`event_uid, ingest_time, collector_id, transport, peer, raw_len,
  raw_sha256, raw_b64`) into per-minute files; `ulpf seal` builds an RFC 6962
  Merkle tree over the exact record lines of closed files, writes a manifest
  that includes the previous manifest's hash, and signs it with Ed25519.
* **Reason:** detects modified, reordered, deleted and inserted records and
  files, and broken chains, with standard primitives.
* **Trade-off:** the storage is writable, so this is **tamper-evident, not
  WORM/immutable**. Truncating the newest manifests is only detectable against
  an externally recorded head hash (`ulpf verify --expect-head`).
* **Date:** 2026-10-07

## ADR-008 — Batch sealing instead of per-event OCSF `record_integrity` attestations
* **Reason:** VRL has no asymmetric signing; per-event signatures would need a
  second processing engine in the hot path.
* **Date:** 2026-10-07

## ADR-009 — drain3 for mining only; templates stored as plain JSON
* **Reason:** drain3 persistence uses jsonpickle (object instantiation on load).
* **Date:** 2026-10-07

## ADR-010 — One interpretation of a spec: everything executes generated VRL in the real Vector
* **Decision:** golden tests, gate, onboarding field extraction, replay and
  live processing all run the same generated VRL inside the Vector binary. The
  Python control plane never re-implements parsing.
* **Exception (deliberate):** the completeness *test oracle* independently
  tokenises raw samples in Python to prove the runtime did not lose fields.
  A test oracle must be independent of the system under test.
* **Date:** 2026-10-07

## ADR-011 — AI-assisted mapping is optional and never authoritative
* **Decision:** deterministic suggester by default; an optional adapter for an
  OpenAI-compatible *local* endpoint is disabled unless configured. Every
  suggestion (from either) passes the same gate: schema, types, lint, golden,
  completeness, human approval.
* **Reason:** no local model fits the disk budget; the prompt forbids faking it.
* **Date:** 2026-10-07

## ADR-012 — stdlib `urllib` OpenSearch client
* **Reason:** the needed API surface (bulk, search, count, templates, aliases)
  is small; fewer wheels in the air-gap bundle.
* **Date:** 2026-10-07

## ADR-013 — Vector runs in UTC; every timezone assumption is recorded
* **Reason:** P0 V8. A zone-less source timestamp is interpreted in the spec's
  declared zone (default UTC) and `ulpf.time.assumed_timezone` records it.
* **Date:** 2026-10-07

## ADR-014 — Validation = official OCSF JSON Schema + schema-driven semantic checks
* **Decision:** draft-07 JSON Schemas generated by the OCSF server are
  vendored per (class, profiles) combination; semantic checks are derived from
  the vendored export (type_uid rule, sibling captions, constraints).
* **Reason:** no hand-written copy of OCSF rules that could drift.
* **Date:** 2026-10-07
