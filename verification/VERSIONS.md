# Versions (pinned)

Every version below was **downloaded and exercised** on the build host on
2026-10-07. Checksums were verified against the publisher's checksum files;
PGP-signed artifacts were verified against the publisher's key.

## Runtime components (native, user-level processes — no Docker, see ADR-002)

| Component | Version | Artifact | Integrity evidence | Why this version |
|---|---|---|---|---|
| Vector | **0.58.0** (`2bcad9b`, 2026-08-26) | `vector-0.58.0-x86_64-unknown-linux-musl.tar.gz` (static musl) | SHA-256 `ad013ddc164b80e425cc403d2174e26b811673846d1125c80bc7b5024826ce39` matches `vector-0.58.0-SHA256SUMS` from the GitHub release | 0.59.0 was released on 2026-10-06, the day before this project started; 0.58.0 had ~6 weeks in the field with no patch release needed. musl build = no glibc dependency (portable to any x86_64 Linux in an air gap). |
| OpenSearch | **3.8.0** (`e5a3c56`, Lucene 10.5.0, bundled OpenJDK 25.0.4 LTS) | `opensearch-min-3.8.0-linux-x64.tar.gz` | SHA-512 matches `.sha512`; PGP "Good signature" from `release@opensearch.org`, primary key `A8B2 D9E0 4CD5 1FEF 6AA2 DB53 BA81 D999 8119 1457` — the fingerprint published at <https://opensearch.org/verify-signatures/> for 3.0.0+ | 3.9.0 was one week old; 3.8.0 had ~2 months. The *min* build (240 MB) was chosen over the full bundle (1 GB) because of disk constraints; only the security plugin is added. |
| opensearch-security plugin | **3.8.0.0** | Maven Central `org/opensearch/plugin/opensearch-security/3.8.0.0` | SHA-512 matches Maven Central `.sha512` | Must equal the OpenSearch version. |
| OpenSearch Dashboards | 3.8.0 (min) | not yet downloaded | — | Planned for Phase 5. |

## Schema

| Item | Version | Source | Evidence |
|---|---|---|---|
| OCSF | **1.9.0** (released 2026-08-03, latest release) | `https://schema.ocsf.io/1.9.0/export/v2/schema` + 14 JSON Schemas from `https://schema.ocsf.io/schema/classes/<class>?profiles=<p>` | `schema/ocsf/1.9.0/MANIFEST.json` (SHA-256 of every file, fetch time, server default version = 1.9.0 at fetch time). `ulpf doctor` re-checks these hashes offline. |

## Python (control plane)

Interpreter: CPython **3.12.3** (Ubuntu 24.04 system Python). The full pinned
set with licenses is in [DEPENDENCIES.md](DEPENDENCIES.md); the exact lock
with hashes is `requirements.lock`.

## Host used for verification

| Property | Value |
|---|---|
| OS | Ubuntu 24.04.5 LTS (VirtualBox guest), kernel 7.0.0-38-generic, x86_64 |
| CPU | 8 vCPU, Intel Core i7-14700 (1 thread/core as exposed to the VM) |
| RAM | 7.7 GiB (+3.8 GiB swap) |
| Disk | 50 GB root; 3.4 GB free at start, 5.3 GB after space was freed |
| Timezone | Asia/Kolkata (+05:30) — relevant: VRL parses zone-less timestamps in the process timezone unless told otherwise |
| Containers | none (no Docker/Podman; no sudo) |
