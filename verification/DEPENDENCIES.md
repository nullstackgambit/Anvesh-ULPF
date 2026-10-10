# Dependency verification

Method for every Python dependency: version and license read from PyPI's JSON
API (2026-10-07), wheel downloaded into a local wheelhouse, installed with
`pip install --no-index --find-links <wheelhouse>` (the same mechanism the
air-gap installer uses), then **exercised by a functional test** on CPython
3.12.3. `pip check` reported no broken requirements.

## Direct dependencies

| Package | Version | License | Role | Functional verification |
|---|---|---|---|---|
| PyYAML | 6.0.3 | MIT | spec/config parsing | used through `ulpf.yamlsafe.StrictLoader` (duplicate-key detection + YAML 1.2 booleans); unit-tested |
| jsonschema | 4.26.0 | MIT | spec schema + OCSF JSON Schema validation | official OCSF draft-07 schema accepted a valid Network Activity event and rejected a string port, `action_id=7` and an invented attribute |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | Ed25519 signing of archive manifests | sign/verify OK; 1-byte message change raised `InvalidSignature` |
| click | 8.5.0 | BSD-3-Clause | CLI | — |
| drain3 | 0.9.11 (2022-07-17, sdist only) | MIT | template mining for onboarding/drift | see note 1 |
| jsonpickle | 1.5.1 | BSD | drain3 pin | — |
| cachetools | 4.2.1 | MIT | drain3 pin | — |
| pyarrow | 25.0.1 | Apache-2.0 | Parquet lake | nested struct table written with zstd and read back identically |
| scikit-learn | 1.9.1 | BSD-3-Clause | IsolationForest | planted outlier (index 200 of 201) ranked first |
| numpy | 2.5.3 | BSD-3-Clause AND others | ML | — |
| streamlit | 1.65.0 | Apache-2.0 | operator UI | (UI phase) |
| pandas | 3.0.6 | BSD-3-Clause | UI tables | — |
| pySigma | 1.5.1 | **LGPL-2.1-only** | Sigma rule conversion (optional extra) | see note 2 |
| pySigma-backend-opensearch | 2.0.3 | **LGPL-3.0-only** | Sigma → OpenSearch Lucene/DSL | see note 2 |
| pytest | 9.1.1 | MIT | tests | — |

Transitive packages and their licenses are listed in `THIRD_PARTY.md`.

### Note 1 — drain3

* Published only as an sdist. An offline `pip install` of an sdist needs
  setuptools from an index, so the wheel is **pre-built** at bundle time
  (`drain3-0.9.11-py3-none-any.whl`) and the sdist is kept for provenance.
* Its `setup.py` pins `jsonpickle==1.5.1` and `cachetools==4.2.1` exactly and
  declares classifiers only up to Python 3.7. Verified on 3.12.3 with
  `-W error::DeprecationWarning`: template creation, template generalisation
  (`user <*> logged in from <*> port <*>`), `match()` of seen/unseen lines and
  `FilePersistence` save/restore all worked.
* **Security decision:** drain3's persistence serialises state with
  jsonpickle, and decoding a tampered jsonpickle file can instantiate
  arbitrary objects. ULPF therefore never loads drain3 state files; mined
  templates are stored as plain JSON and re-matched with ULPF's own
  template→regex matcher (ADR-009).

### Note 2 — pySigma

* pySigma 2.0.0 was released 2026-10-04, but every OpenSearch/Elasticsearch
  backend still requires `pysigma<2.0.0`, so 1.5.1 (latest 1.x) is pinned.
* Verified: a Sigma rule using the generic firewall taxonomy (`dst_port`,
  `src_ip|cidr`, `action`) plus a ULPF `FieldMappingTransformation` produced
  `(dst_endpoint.port:22 AND action:allowed) AND (NOT src_endpoint.ip:10.0.0.0\/8)`.
  Output formats available: `default`, `dashboards_ndjson`, `monitor_rule`, `dsl_lucene`.
* LGPL: used as an unmodified, dynamically imported library in an optional
  extra (`ulpf[sigma]`); ULPF works without it.

## Non-Python components

See [VERSIONS.md](VERSIONS.md) for Vector, OpenSearch and the security plugin.

| Component | License | Evidence |
|---|---|---|
| Vector | MPL-2.0 | `LICENSE` inside the release tarball |
| OpenSearch / security plugin / Dashboards | Apache-2.0 | `LICENSE.txt` inside the tarball |
| OCSF schema | Apache-2.0 | <https://github.com/ocsf/ocsf-schema> |
| RFC 6962 Merkle test vectors | Apache-2.0 | transparency-dev/merkle `testonly/constants.go` @ `77f1b57d7aa25fcd2e51273166b6b2b0e74923b1` (vectors re-typed into tests, attributed) |

## Rejected / not used

| Candidate | Reason |
|---|---|
| Docker / Docker Compose | not installed, no sudo; not used (ADR-002) |
| Vector `syslog` source | parses and drops the original header bytes — violates raw-first preservation (ADR-004) |
| Vector `api_version: auto` against OpenSearch 3.8 | sends `_type`, OpenSearch returns 400, Vector **drops the events** (ADR-006) |
| opensearch-py | not needed; a ~150-line stdlib `urllib` client keeps the air-gap bundle smaller |
| Local LLM | no model can be installed within the disk budget; AI-assisted mapping is implemented as an optional, disabled-by-default adapter (ADR-011) |
