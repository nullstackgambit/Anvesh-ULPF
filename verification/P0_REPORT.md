# Phase 0 — Environment, dependency verification and spikes

Date: 2026-10-07. Host details: [VERSIONS.md](VERSIONS.md). Every finding marked
**VERIFIED** was observed by running the real binary or library on this host;
the corresponding automated re-check lives in
`tests/platform/test_vector_assumptions.py` and
`tests/platform/test_opensearch_assumptions.py`, so an upgrade that changes the
behaviour fails the test suite.

## 1. Environment report

| Check | Result | Consequence |
|---|---|---|
| Python | 3.12.3, **no pip** module; `ensurepip` (pip 24.0) available | venv + wheelhouse install works (VERIFIED) |
| Docker / Podman | **not installed** | — |
| sudo | requires a password | cannot install system packages |
| Rootless containers | `kernel.apparmor_restrict_unprivileged_userns = 1`, no `newuidmap` | rootless Docker/Podman impossible without admin action |
| Network isolation | `unshare -rn` and `bwrap --unshare-net` both work; inside, only `lo` exists and `pypi.org` does not resolve | a **real** network-isolated air-gap test is possible (VERIFIED) |
| Disk | 3.4 GB free at start (93 % used); 5.3 GB after space was freed | OpenSearch *min* build instead of the 1 GB full bundle; benchmarks sized to disk |
| RAM | 7.7 GiB, ~4.4 GiB available | OpenSearch heap 1 GiB |
| Kernel limits | `vm.max_map_count = 1048576`, `ulimit -n = 1048576` | OpenSearch bootstrap checks satisfied |
| Timezone | Asia/Kolkata (+05:30) | exposed a real normalization hazard (finding V8) |
| Internet | PyPI, GitHub, opensearch.org, schema.ocsf.io reachable | used only at build time |

**Decisions (2026-10-07):** no Docker; disk space freed before installing.
Recorded as ADR-002 / ADR-003 in `docs/architecture-decisions.md`.

## 2. Dependency verification

See [DEPENDENCIES.md](DEPENDENCIES.md) (Python, licenses, rejected options)
and [VERSIONS.md](VERSIONS.md) (binaries, checksums, signatures).

## 3. Findings from spikes

### Vector 0.58.0

| # | Finding | Status | Design consequence |
|---|---|---|---|
| V1 | `socket`/`file` sources with `decoding.codec: bytes` + `encode_base64(.message)` reproduce the received bytes **exactly**, incl. invalid UTF-8 (`\xff\xfe\x80`), NUL, CR, TAB, multibyte UTF-8 and a 5000-byte line: 21/21 events (7 samples × TCP/UDP/file), SHA-256 equal to Python `hashlib` | VERIFIED | raw is carried as base64 in the archive |
| V2 | The JSON encoder writes the `message` string **lossily** (invalid bytes → U+FFFD) | VERIFIED | never archive `.message` as JSON text |
| V3 | `length()` counts bytes (17 for `café 漢字`), `strlen()` counts characters (12) | VERIFIED | `raw_len` uses `length()` |
| V4 | UDP default framing keeps one datagram = one event (embedded `\n` preserved); TCP `octet_counting` (RFC 6587) works; peer address arrives as separate `host` and `port` fields | VERIFIED | the online docs say `host` includes the port — **doc discrepancy**, observed behaviour wins |
| V5 | VRL has **no `parse_leef`** and **no `is_valid_utf8`** (error E105) | VERIFIED | LEEF compiled to `parse_regex` + `parse_key_value`; UTF-8 validity = `parse_json(encode_json(raw)) == raw` (V17) |
| V6 | `x, err = to_int("abc")` yields `err` **and `x = 0`**; failed `parse_timestamp` yields `1970-01-01` | VERIFIED | compiler always branches on `err`; ignoring it would turn an invalid port into port 0 |
| V7 | `parse_json` with duplicate keys keeps the **last** value silently; `parse_key_value` turns duplicate keys into an array | VERIFIED | documented limitation for JSON; raw archive keeps both values |
| V8 | RFC 3164 timestamps (no zone) and zone-less `parse_timestamp` use the **process timezone** (host IST shifted `10:15:30` to `04:45:30Z`); `parse_timestamp(..., timezone:)` accepts IANA zones | VERIFIED | Vector runs with `timezone: UTC`; specs declare zones; assumptions recorded in `ulpf.time` |
| V9 | `parse_syslog` on Cisco ASA `<166>Oct 07 2026 10:15:30: %ASA-6-302013: Built …` puts `%ASA-6-302013` into `hostname` and drops it from `message` — **silent misattribution** | VERIFIED | pre-parse exposes `after_pri` (raw minus `<PRI>`); vendor specs may parse that instead of `parse_syslog` output |
| V10 | `parse_syslog` fails on `<PRI>` directly followed by a body (`<189>date=…`) and on `<166>%ASA-…` | VERIFIED | PRI-only layer in pre-parse |
| V11 | `elasticsearch` sink with `api_version: auto` against OpenSearch 3.8.0 sends `_type`; OpenSearch answers 400 and **Vector drops the events** (`Events dropped intentional=false count=3`) | VERIFIED | `api_version: v8` (v7 also works) + end-to-end accounting |
| V12 | `id_key` removes the key field from the indexed document | VERIFIED | dedicated `_osid` field is used as `id_key`; `metadata.uid` stays |
| V13 | runtime error with `drop_on_error: false` (default) lets the **partially processed** event continue | VERIFIED | parser transforms use `drop_on_error: true` + `reroute_dropped: true` |
| V14 | with `reroute_dropped`, aborts and runtime errors emit the **original input event** on `<id>.dropped`; no reason metadata is attached (`%` is `{}`) | VERIFIED | failed path identifies the parser from the event's own `ulpf.parser.id` |
| V15 | frames longer than `max_length` are discarded with a WARN log only | VERIFIED | `internal_logs` source captures "Discarding frame larger than max_length." (with `buf_len`, `max_length`, component id) into the DLQ as a recorded loss |
| V16 | VRL rejects *unhandled* fallibility (E103) and *unnecessary* `??` on infallible expressions (E651) | VERIFIED | the compiler tracks fallibility; every generated program is compiled by the real Vector (`vector validate`) |
| V17 | `parse_json(encode_json(raw)) == raw` is true for valid UTF-8 and false for invalid UTF-8 | VERIFIED | `ulpf.raw.utf8` flag; inline base64 only when false |
| V18 | `uuid_v7(timestamp)` accepted (infallible) | VERIFIED | event UIDs are time-ordered by receipt time |
| V19 | `parse_cef` handles `\=` escapes and values with spaces; `community_id()` exists; `is_ipv4("10.1.1.300")` is false | VERIFIED | — |

### OpenSearch 3.8.0

| # | Finding | Status | Design consequence |
|---|---|---|---|
| O1 | single-node cluster green with 1 GiB heap from the min tarball | VERIFIED | — |
| O2 | an invalid IP in an `ip` field rejects the **whole document** (`mapper_parsing_exception`) | VERIFIED | generated VRL validates IPs → bad value to `unmapped`, status `partial` |
| O3 | `index.mapping.ignore_malformed: true` indexes the document, lists bad fields in `_ignored`, keeps `_source` | VERIFIED | safety net in the index template |
| O4 | `flat_object` field type supports dotted-path term queries | VERIFIED | `unmapped` is `flat_object` (no mapping explosion) |
| O5 | `ip` field supports CIDR term queries (`10.1.0.0/16`) | VERIFIED | — |
| O6 | `POST /_aliases` with remove+add swaps an alias atomically | VERIFIED | replay switch |
| O7 | default `number_of_replicas: 1` leaves single-node indices yellow | VERIFIED | template sets replicas 0 |

### OCSF 1.9.0

| # | Finding | Status |
|---|---|---|
| S1 | Latest release 1.9.0 (2026-08-03); schema server default is 1.9.0; `/1.9.0/export/schema` (legacy) returns 400 for 1.9.0 because of multi-profile attributes, `/1.9.0/export/v2/schema` works | VERIFIED |
| S2 | `/schema/classes/<c>?profiles=` returns an official draft-07 JSON Schema with `additionalProperties:false`; without `profiles`, *all* profiles are applied and e.g. `cloud`/`osint` become required — so the profile set must be explicit | VERIFIED |
| S3 | Network Activity: uid 4001, category 4, `activity_id` {0 Unknown,1 Open,2 Close,3 Reset,4 Fail,5 Refuse,6 Traffic,7 Listen,99 Other}; `action_id`/`disposition_id` come from the `security_control` profile; constraint `at_least_one [dst_endpoint, src_endpoint]` (present in the JSON Schema as `anyOf`) | VERIFIED |
| S4 | Native provenance slots exist: `metadata.uid`, `logged_time`, `processed_time`, `original_time`, `log_format`, `loggers[]`, `transformation_info_list[]`, `raw_data`, `raw_data_size`, `raw_data_hash` (fingerprint, `algorithm_id` 3 = SHA-256, `encoding_id` 1 = Hex), `unmapped` | VERIFIED |
| S5 | `record_integrity` profile (per-event attestations) exists — not used: VRL has no Ed25519; batch sealing instead (ADR-008) | VERIFIED (existence) |
| S6 | `port_t` is integer [0,65535]; `ip_t`/`mac_t`/`uuid_t`/`datetime_t`/`email_t` are regex-constrained strings; `timestamp_t` is long (epoch ms) | VERIFIED |

### Libraries and references

| # | Finding | Status |
|---|---|---|
| L1 | drain3 0.9.11 works on CPython 3.12.3 with its exact pins | VERIFIED (DEPENDENCIES.md note 1) |
| L2 | pySigma 1.5.1 + OpenSearch backend 2.0.3 convert Sigma → Lucene/DSL with a field-mapping pipeline | VERIFIED |
| L3 | Ed25519 (cryptography 50.0.2), Parquet (pyarrow 25.0.1), IsolationForest (scikit-learn 1.9.1) work | VERIFIED |
| L4 | RFC 6962 Merkle test vectors taken from transparency-dev/merkle @ `77f1b57d` | VERIFIED source |
| L5 | pfSense filterlog CSV grammar taken from the official Netgate BNF (IPv6 puts protocol-text *before* protocol-id) | VERIFIED source |
| L6 | FortiOS 7.6.0 `LOG_ID_TRAFFIC_END_FORWARD` (0000000013) field table (172 fields, types) extracted to `verification/vendor_refs/` | VERIFIED source |
| L7 | FortiOS `log syslogd setting` formats are default/csv/cef/rfc5424/json; the exact header layout of *default* is **UNVERIFIED**, so the parser accepts PRI-only, RFC 3164 and RFC 5424 headers | PARTIAL |

## 4. Assumptions

| ID | Assumption | Status |
|---|---|---|
| A1 | Raw bytes of a newline-framed TCP stream are the bytes *between* delimiters; the delimiter itself is framing, not event content | DESIGN DECISION (documented in data-model.md) |
| A2 | Archive files are partitioned by receipt minute; a file is "closed" once its minute is over by a grace period and Vector's `idle_timeout_secs` has passed | ARCHITECTURAL DESIGN — tested in Phase 3 |
| A3 | Vendor samples are synthetic, built from official field documentation, and labelled `SYNTHETIC TEST DATA` | POLICY |
| A4 | Tail truncation of the manifest chain cannot be detected from the chain alone; an externally recorded head hash is required | KNOWN LIMIT, documented |

## 5. Items requiring external verification (not possible here)

* Docker/Compose deployment (not used, ADR-002).
* Real vendor devices (no FortiGate/PAN-OS/ASA/Check Point hardware): only
  documentation-derived synthetic samples.
* Throughput on production hardware (only this VM is measured).
* A local LLM (none installed).

## 6. Phase plan and acceptance criteria for the first vertical slice

Phase 1 acceptance (all must pass before Phase 2):

1. FortiGate traffic events (synthetic, documentation-derived) sent over UDP
   and TCP reach Vector and are written to the raw archive with SHA-256 equal
   to the sender's bytes.
2. They are parsed into OCSF 1.9.0 Network Activity events that pass the
   vendored JSON Schema and ULPF semantic checks.
3. They are indexed in OpenSearch (write alias → `ulpf-events-v1`) and
   queryable by `src_endpoint.ip`.
4. An unknown line becomes an OCSF Base Event with `ulpf.status = fallback`,
   is indexed, and lands in the DLQ.
5. Accounting: events sent = archived = normalized = indexed (by event UID).
