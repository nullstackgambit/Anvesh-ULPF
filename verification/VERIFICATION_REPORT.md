# Verification report

Status vocabulary: **VERIFIED** (observed on this host with an automated or
recorded check) · **IMPLEMENTED AND TESTED** (ULPF code with passing tests) ·
**ARCHITECTURAL DESIGN** (described, not built) · **ASSUMPTION** ·
**UNVERIFIED** · **NOT IMPLEMENTED**.

Phase 0 findings (platform facts) are in [P0_REPORT.md](P0_REPORT.md) and
pinned by `tests/platform/`.

In the evidence logs, local absolute paths are written as `<repo>` (the
repository root).

---

## Phase 1 — minimal vertical slice (2026-10-07) — PASSED

Pipeline: `ulpf gen` → UDP / TCP / HTTP → Vector 0.58.0 (live config built by
`ulpf spec compile`) → raw archive (file) + preparse → match → FortiGate parser
→ finalize → normalized NDJSON + OpenSearch 3.8.0 (`ulpf-events-write` alias)
+ DLQ.

| Acceptance criterion | Evidence | Result |
|---|---|---|
| Raw archive SHA-256 equals sender bytes | `ulpf account --sendlog`: sent 612, `sent_not_archived` 0 (multiset of SHA-256) | PASS |
| Parsed into valid OCSF 1.9.0 Network Activity | 0 JSON-Schema / semantic / envelope failures over 145 events (scratch run) and all golden vectors | PASS |
| Indexed and queryable | 612 indexed, `archived_not_indexed` 0; exact IP and CIDR (`10.0.0.0/8`) term queries | PASS |
| Unknown events visible as fallback + DLQ | 112 fallback Base Events (100 unknown vendor, 12 malformed), all in DLQ | PASS |
| Accounting by event UID | archive UID set == normalized UID set == OpenSearch `_id` set; Vector `component_received_events_total` = 312 UDP + 200 TCP + 100 HTTP = 612 | PASS |
| Semantics vs ground truth | 0 mismatches of src/dst IP+port, protocol, action, bytes, time for 120 FortiGate events (generator ground truth) | PASS |

Automated: `tests/e2e/test_live_slice.py` (3 tests, needs the running stack).

Defects found **and fixed** during Phase 1 (each would otherwise have caused
silent loss or wrong data):

1. Vector `octet_counting` framer drops the rest of a TCP connection after an
   invalid-UTF-8 frame → listener disabled by default (finding V20).
2. `community_id` without ports for UDP produced `""` → only computed for
   port-less protocols; empty values never assigned.
3. `elasticsearch` sink `api_version: auto` → events dropped (V11) → `v8`.
4. Vector parsed a temp config named `*.yaml.tmp` as TOML → temp file now
   ends in `.yaml`.
5. OCSF requires `connection_info.direction_id`; FortiGate does not state a
   direction → schema-derived default `0 (Unknown)`.

## Phase 2 — specification system (2026-10-07) — PASSED

| Capability | Implementation | Evidence | Status |
|---|---|---|---|
| YAML DSL | `schema/spec.schema.json` (draft 2020-12) | `ulpf spec lint` | IMPLEMENTED AND TESTED |
| Strict YAML | duplicate keys rejected, YAML 1.2 booleans | `tests/unit/test_yamlsafe_vrl.py` | IMPLEMENTED AND TESTED |
| Semantic lint against vendored OCSF | paths, profiles, types, enum values, reserved attributes, sibling captions, duplicate destinations, double-consumed sources, class constraints, Rust-regex compatibility, timezones | `tests/unit/test_spec_lint.py` (22 negative cases, each rule must fire) | IMPLEMENTED AND TESTED |
| Never compile a failing spec | `compile_specs` raises on lint errors | `test_compiler_refuses_specs_with_lint_errors` | IMPLEMENTED AND TESTED |
| Compiler → VRL | `ulpf/compile.py`; every program has a GENERATED header with spec id, version, spec SHA-256, compiler version | `test_all_approved_specs_compile_validate_and_have_no_vrl_warnings` | IMPLEMENTED AND TESTED |
| Real runtime validation | `vector validate` + `vector vrl --print-warnings` on every build (`ulpf spec compile`) | build refuses warnings (E900 found and fixed) | IMPLEMENTED AND TESTED |
| Hand-edit detection | content SHA-256 in the generated header; `ulpf stack up` refuses a modified config | `test_hand_edited_generated_file_is_detected` | IMPLEMENTED AND TESTED |
| Golden / expectation / schema / completeness / round-trip tests | `ulpf test`, executed through the Vector binary | `tests/golden/test_golden.py`: 6/6 FortiGate vectors pass all checks | IMPLEMENTED AND TESTED |
| Field-level lineage | `ulpf.lineage` (OCSF path → source field / enum / derivation / const) | golden files | IMPLEMENTED AND TESTED |
| Type coercion failures preserved | invalid port `abc`, invalid IP `10.1.1.300` → original value in `unmapped`, error recorded, status `partial` | golden `invalid_*_is_partial` | IMPLEMENTED AND TESTED |
| Unknown enum value | `99 (Other)` + source value in the caption sibling, status `partial` | golden `unknown_action_is_other` | IMPLEMENTED AND TESTED |

OCSF validation gap found in Phase 2: the official server-generated JSON
Schemas encode `ip_t`/`mac_t` as plain strings and `port_t` as a plain
integer (no range, no pattern). ULPF's semantic layer now enforces the
dictionary's ranges, regexes, max lengths and IP/subnet validity
(`Ocsf._types`); `tests/unit/test_ocsf.py` covers port 70000.

## Phase 3 - lossless integrity (2026-10-07) - PASSED

| Capability | Evidence | Status |
|---|---|---|
| RFC 6962 Merkle tree | transparency-dev vectors (empty + sizes 1-8), inclusion proofs for 7 tree sizes, forged proofs rejected | IMPLEMENTED AND TESTED |
| `ulpf keygen/seal/verify/raw get` | Ed25519 signed, hash-chained manifests; key mode 0600; refuses to overwrite | IMPLEMENTED AND TESTED |
| Tamper detection | flipped byte, deleted/reordered record, deleted file, deleted/edited manifest, wrong key, unsealed file (`tests/unit/test_integrity.py`, 30 tests) | IMPLEMENTED AND TESTED |
| Tail truncation | detected only with an external head (`--expect-head`) - documented limitation, test proves both halves | IMPLEMENTED AND TESTED |
| Scenario 4 losslessness | 25 tricky payloads (invalid UTF-8, NUL, emoji, multi-line datagram, 3 KB) over UDP/TCP/HTTP round-trip byte-for-byte from archive and normalized event (`tests/e2e/test_lossless.py`) | PASS |
| Scenario 5 tampering | `scripts/demo_tamper.sh` on a copy of the real archive: PASS -> one byte -> FAIL (file hash, Merkle, record hash) | PASS |

## Phase 4 - multi-source (2026-10-07) - PASSED (Check Point / ASA 106023 out of scope: UNVERIFIED formats)

| Item | Status |
|---|---|
| Vendor specs: FortiGate, PAN-OS (130 documented columns), Cisco ASA 302013-302016, pfSense filterlog (IPv4/IPv6 BNF), Suricata flow + alert, Zeek conn, Squid access | IMPLEMENTED AND TESTED (formats verified from official docs; samples SYNTHETIC) |
| Generic syslog/JSON/KV/CEF/LEEF specs (status=fallback, structured) | IMPLEMENTED AND TESTED |
| Check Point | NOT IMPLEMENTED - official field reference is login-gated (UNVERIFIED) |
| Cisco ASA 106023 (deny) | NOT IMPLEMENTED - official template is defective (UNVERIFIED) |
| Scenario 2 cross-vendor equivalence (6 vendors, one query) | PASS (`tests/e2e/test_cross_vendor.py`) |
| Unknown-source onboarding (fingerprint/mine/onboard/gate/promote) | IMPLEMENTED AND TESTED - see Phase 4b |
| Drift detection, scorecard | IMPLEMENTED AND TESTED - see Phase 4b |

## Phase 4b - unknown-source onboarding, drift, scorecard (2026-10-07) - PASSED

| Capability | Evidence | Status |
|---|---|---|
| Fingerprint for unframed plain text (leading token + `|`/`;` profile) | before: every unstructured text event shared one fingerprint (`sha256("text\|\|")`), so unknown sources were lumped with the malformed corpus; after: the blackbox source is one cluster. Only the Squid goldens changed (fingerprint field only; reviewed, `--update`) | IMPLEMENTED AND TESTED |
| `ulpf fingerprint`, `ulpf mine` (drain3 in memory, `--split`) | `tests/unit/test_onboard.py` (clusters, templates, Rust-compatible patterns) | IMPLEMENTED AND TESTED |
| `ulpf onboard` draft writer | samples from the archive (sha256 re-verified), runtime pre-parser view via real Vector, value-type + synonym + OCSF-resolution checks, minimal vendored profiles, expectations computed independently in Python and equal to generator ground truth (`test_propose_blackbox_draft_offline`), YAML round-trip check | IMPLEMENTED AND TESTED |
| Local-LLM suggestions | stub OpenAI-compatible server: invented path, type mismatch, unknown field, enum target, descend-into-scalar all discarded; confidence capped 0.8; non-local URL refused; suggestions only ever written as inactive comments | IMPLEMENTED AND TESTED (no real model run) |
| `ulpf gate` (lint, compile + `vector validate`, draft tests, regression, samples) | PASS on the generated draft; a greedy draft (`regex: '.'`, priority 999) FAILS the regression gate (`tests/e2e/test_onboarding.py`) | IMPLEMENTED AND TESTED |
| `ulpf promote` | refuses: non-human approver (`llm`, `auto`, ...), stale gate (content changed), changed approved set; rollback on failure (found and fixed: empty vendor dir left behind); writes spec + approval record, goldens (re-checked), drift baseline, live config, audit log | IMPLEMENTED AND TESTED |
| Scenario 3 (offline, isolated home) | 120 unknown events -> draft -> gate -> reviewer edit -> stale gate refused -> re-gate -> promote -> archive replay: 120/120 parsed, every value == ground truth | PASS (`tests/e2e/test_onboarding.py`, 2 tests) |
| **Scenario 3 LIVE** | isolated home, own Vector on demo ports, shared OpenSearch: 200 unknown events over TCP (fallback, accounting PASS) -> onboard -> gate PASS -> scripted review edit -> promote refused (stale) -> re-gate -> promote -> **Vector hot-reloaded 14.0 s after promote** -> 200 new events parsed by `acme.blackbox.flow`; accounting 400 sent = 400 archived = 400 indexed; drift lists the 200 earlier events as UNKNOWN_SOURCE until backfilled. Log: `verification/scenario3_onboarding_live.log` | PASS |
| Drift (`ulpf drift check/baseline`) | 7 unit tests: NEW_UNMAPPED_FIELD, MAPPED_FIELD_MISSING, STATUS_SHIFT, NEW_ERROR, MAPPED_RATIO_DROP, NEW_FINGERPRINT, PARSER_CHANGED, LOW_VOLUME; bug found and fixed: `dataclasses.asdict` turns Counter keys into tuples | IMPLEMENTED AND TESTED |
| Scorecard (`ulpf scorecard`) | tests/golden/parse-rate/mapped-ratio/drift/provenance per spec with documented thresholds; shown in the live demo and the UI | IMPLEMENTED AND TESTED |

The approval in the live demo is recorded as "Scripted Demo Reviewer" with the
note "scripted demo - not a human review"; no spec in the repository's own
`specs/` was approved by a scripted run.

### Finding P4b-1: Vector start-up dominated by VRL type checking (fixed)

`vector validate` of the full configuration took ~40 s and a batch run ~59 s
(single core), so every `ulpf test`, gate and hot reload paid ~1 min.
Measured cause: generated VRL that VRL's type checker handles quadratically -
(a) one statically keyed assignment per CSV column (PAN-OS: 130 columns, 17.9 s
alone), (b) per-field writes to `lin."a.b"`, `used."x"`, `um."x"` and pushes onto
`errs`, which make the checker track every key/index and merge them at every
branch. Fix in the compiler: name tables with `for_each` + dynamic `set()` for
CSV columns and regex captures, and bookkeeping objects/arrays created with an
opaque type (`object(parse_json("{}") ?? null) ?? {}`) and written with `set()`.
Result: full validate 40 s -> 17.5 s, `ulpf test` 67 s -> 27 s, FortiGate
program compile 1.83 s -> 0.89 s; **all 31 golden vectors byte-identical**
(behaviour unchanged). Also measured: Vector compiles each remap program 2-3x
during start-up (validate ~2x, run ~3x the `vector vrl` time) - upstream
behaviour, not changeable by ULPF.

## Phase 5 - replay, detections, lake, UI (2026-10-07) - PASSED (Dashboards not installed)

| Capability | Evidence | Status |
|---|---|---|
| **Scenario 6** replay to a new index + atomic alias switch under live load | live Vector + 4000 events at 50 eps during `ulpf replay new-index`: 1846 archived = 1846 replayed into `ulpf-events-v2`, aliases moved in one `_aliases` call mid-stream, catch-up replayed 1588 recent records, 0 missing; afterwards `ulpf account`: 5410 archived = 5410 indexed via the read alias (now v2), 0 duplicates; v1 frozen as rollback target (`ulpf replay rollback --to ulpf-events-v1`). `verification/scenario6_replay.json`, `scenario6_account.txt` | PASS |
| Backfill (`ulpf replay backfill --status fallback`) | same `_id` (= event_uid) replaces fallback docs in place after onboarding | IMPLEMENTED (exercised in Phase 6 run below) |
| **Scenario 7** Sigma (pySigma 1.5.1 + OpenSearch Lucene backend 2.0.3) | 5 rules + ULPF pipeline (firewall logsource -> class_uid 4001, rule field names -> OCSF). Hit counts equal an independent Python evaluation for every rule (150 / 463 / 333 / 25 / 274); one rule matches FortiGate, PAN-OS, Suricata, ASA, pfSense (`tests/e2e/test_detections.py`, `verification/scenario7_sigma.txt`) | PASS |
| **Scenario 8** IsolationForest port-scan ranking | scanner 10.66.6.6 (500 denied probes) ranked #1 of 5499 source windows (score 0.944 vs 0.855 next); 27 other windows flagged (0.49%: sources with 2 events/min in synthetic traffic). Finding: with sklearn's default 256-point subsample the scanner ranked 26th (masking by thousands of near-identical windows) -> trees built on all windows (`max_samples=1.0` up to 50k). `tests/unit/test_detect.py`, `verification/scenario8_anomaly.txt` | PASS |
| Parquet lake (`ulpf lake compact/verify/stats`) | 7 closed files, 7435 rows, 36.0 MB NDJSON -> 2.47 MB Parquet (zstd); every `event_json` equals its source line (lossless), manifest sha256 verified | IMPLEMENTED AND TESTED |
| Streamlit UI (`ulpf stack up ui`, 127.0.0.1:8501) | 5 pages render without exceptions (`tests/e2e/test_ui.py`, AppTest); manually checked in a browser: event click-through to lineage, original bytes (sha256 equal to archive and index), Merkle proof when sealed; usage statistics and the "Deploy" toolbar disabled | IMPLEMENTED AND TESTED |
| OpenSearch Dashboards | NOT INSTALLED: ~1 GB extracted would leave < 2 GB free next to OpenSearch's 1.5 GB low watermark and the air-gap bundle test; the Streamlit UI covers the operator views | NOT IMPLEMENTED (disk constraint) |

## Phase 6 - operations hardening (2026-10-07 to 2026-10-10) - IN PROGRESS

Only the finding below is written up so far. Security, outage, air-gap re-run
and benchmark results are still pending.

### Finding P6-4: a hot reload that changes a file sink's codec re-encodes its buffered events (fixed)

**Observed.** After the live configuration switched the archive and
normalized file sinks from the `json` codec to `text`, which was needed for
reduce batching, the raw archive contained 1311 empty lines, in
`raw-20261007T1052` and `raw-20261007T1053`. Their 1311 events were indexed but
had no archive record. Vector logged no warning or error. The normalized file
for 10:53 also had 745 empty lines. `ulpf repair` recovered all 1311 archive
records from the index: the bytes were accepted only when they matched the
ingest-time SHA-256 and length, and were written to a separate `recovered`
file (`verification/repair_after_reload_incident.json`). Accounting then
passed.

**Cause (reproduced).** `scripts/reload_codec_experiment.sh` uses the real
Vector 0.58.0 binary with a minimal configuration and no ULPF components.
Log: `verification/reload_codec_experiment.log`, 2026-10-10, 60,000-event burst.

| Change applied while the sink still had a backlog | Empty lines | Events missing |
|---|---|---|
| hot reload, same sink key, codec json → text | 2048 | 2048 |
| hot reload, sink renamed | 0 | 0 |
| graceful stop, then start with the new config | 0 | 0 |

Vector keeps a changed sink's buffer across a hot reload. Events the old
topology had already buffered were then encoded by the new `text` codec, and
since they have no `message` field each became an empty line. The number
depends on how much was buffered at the moment of the reload: 4096 in an
earlier run, and none with a 6000-event burst, which had drained before the
reload took effect.

**Fix.**
- **Refuse unsafe reloads.** `ulpf spec compile` compares the new
  configuration with the running one (`build.reload_hazards`). It applies by
  hot reload only the changes a spec promotion makes: the spec programs, the
  matcher and router, and the fan-in input lists. Any other change (sinks,
  codecs, the archive branch, sources, global options) is refused while Vector
  runs. `--restart` applies it with a drained restart instead.
  `tests/unit/test_reload.py` covers this on the real generated configurations.
- **Drain on stop.** Vector's graceful-shutdown limit is now 120 s (default
  60 s). `ulpf stack stop` waits 150 s and reports any components Vector had to
  kill.
- **Seal with declared gaps.** `ulpf seal` holds a file with empty lines back
  until `--accept-gaps`. It then declares the gaps in the signed manifest; the
  gap lines remain Merkle leaves, so filling one later is detected.
  `verification/seal_declared_gaps.log`: 1311 declared, `ulpf verify` PASS.
- **Byte-exact lake restore.** `ulpf lake compact` records empty-line
  positions, so `ulpf lake restore` reproduces the original file byte for byte.
  `ulpf lake verify --repair-layout` recovered the 745-line layout of the one
  already-pruned file, matched against its recorded SHA-256.
  `tests/unit/test_lake.py`, `tests/unit/test_integrity.py`.
