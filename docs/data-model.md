# Data model

A normalized ULPF event is **one OCSF 1.9.0 event** plus two additions:
`unmapped` (an OCSF attribute) holding every source field that was not
mapped, and a single top-level `ulpf` envelope with provenance. ULPF invents
no OCSF attributes (ADR-001); every path a spec writes is resolved against
the vendored schema at lint time, and every output is validated against the
official JSON Schema plus semantic checks (ADR-014).

## OCSF-native provenance slots

| Attribute | Set to |
|---|---|
| `metadata.uid` | the ULPF event UID (UUIDv7 from the receipt time; stable across replays) |
| `metadata.logged_time` | receipt time at the collector (ms) |
| `metadata.processed_time` | when ULPF finalized the event (ms) |
| `metadata.original_time` | the source timestamp *as written* (e.g. `1791368130123456789`) |
| `metadata.log_format` | detected layers, e.g. `pri+kv`, `syslog+text`, `json` |
| `metadata.loggers[0]` | the collector: `name`/`uid` (collector id), product `ULPF Collector`, `event_uid`, `logged_time`, `log_format` |
| `metadata.transformation_info_list[0]` | the parser: `name` = spec id, `uid` = spec SHA-256, `lang` = `VRL`, product `ULPF`, `time` |
| `metadata.product` | `vendor_name` / `name` from the spec (`unknown` for fallback) |
| `metadata.version` | `1.9.0` |
| `metadata.profiles` | the profiles the spec applies (e.g. `host`, `security_control`) |
| `raw_data` | the exact received text (UTF-8 events) |
| `raw_data_size`, `raw_data_hash` | byte length; SHA-256 (`algorithm_id` 3, `encoding_id` 1 Hex) of the received bytes |
| `unmapped` | every unmapped source key → original value (strings as received) |

Non-UTF-8 payloads cannot be represented in a JSON string losslessly, so the
bytes are additionally carried base64-encoded in `ulpf.raw.b64`.

## The `ulpf` envelope (`schema/provenance.schema.json`)

| Key | Meaning |
|---|---|
| `v` | envelope version (1) |
| `event_uid` | same as `metadata.uid` |
| `status` | `parsed` (all mapped values valid) · `partial` (some source values failed coercion; kept in `unmapped`, listed in `errors`) · `fallback` (no approved spec claimed it, or a generic spec structured it) · `failed` (oversized, archive integrity failure, or a parser runtime error) |
| `reasons` | why, for non-`parsed` events (`no_matching_spec`, `oversized`, `archive_integrity`, `parser_runtime_error`, `parse_error`, ...) |
| `errors[]` | `{code, field, to, value}` per problem (e.g. `invalid_ip`, `port_out_of_range`, `enum_value_not_in_table`, `invalid_time`) |
| `parser` | `{id, version, spec_sha256, compiler}` |
| `format`, `fingerprint` | detected layers; 16-hex structural signature used by onboarding and drift |
| `ingest` | `{time (ns, RFC 3339), time_ms, collector_id, transport, peer}` |
| `raw` | `{sha256, len, utf8[, b64]}` computed from the received bytes before any parsing |
| `time` | `{source: field|ingest, field, format, assumed_timezone, year_inferred, skew_ms[, note]}` — every assumption about time is recorded |
| `coverage` | `{fields, mapped, unmapped, empty[, empty_fields]}`; invariant `fields = mapped + unmapped + empty` is checked at runtime |
| `lineage` | OCSF path → origin (see below) |
| `replay` | `{run}` when produced by a test, gate, replay or backfill run |
| `integrity_error` | set when an archived record failed re-verification during replay (event forced to `failed`) |

### Lineage values

| Value | Meaning |
|---|---|
| `srcip` | copied from source field `srcip` (after the spec's type coercion) |
| `date+time` | combined from several source fields (time) |
| `enum:action` | set by the enum table of source field `action` |
| `enum_missing:action` | enum `missing` default (field absent) |
| `derived:iana_protocol_name(connection_info.protocol_num)`, `derived:community_id`, `copy:<path>` | computed by a `derive` step |
| `const` | constant from the spec's `set` |
| `ingest` | time fell back to the receipt time |
| `default:unknown` | a required OCSF enum defaulted to 0 (Unknown) |

`ulpf raw get <uid> --proof` and the UI's *Explain a field* tab turn one
lineage entry into: normalized value → source field(s) → raw bytes → Merkle
inclusion proof.

## Raw archive record (one JSON line per received event)

```json
{"collector_id":"ulpf-collector-01","event_uid":"01a11458-432d-797d-…","ingest_time":"2026-10-07T03:11:27.600084220Z",
 "peer":{"ip":"127.0.0.1","port":39452},"raw_b64":"PDE4OT5kYXRl…","raw_len":546,"raw_sha256":"…","transport":"syslog-tcp","v":1}
```

Keys are sorted (Vector JSON codec / VRL `encode_json`, byte-identical).
Files are bucketed by *archive write time* (`raw-<YYYYmmddTHHMM>-<collector>.ndjson`)
so late events never reopen a sealed file. Records recovered by `ulpf repair`
live in separate `…-recovered-<time>.ndjson` files and carry
`"recovered": {"from": "opensearch", …}`.

## Seal manifest (`runtime/data/archive/manifests/<seq>.json` + `.sig`)

```json
{"format": "ulpf-seal-manifest/1", "seq": 1, "created_at": "…", "prev_manifest_sha256": null, "key_id": "67ae0d0df67612d8",
 "algorithms": {"leaf": "sha256(0x00 || record_line)", "node": "sha256(0x01 || left || right)",
                "tree": "RFC 6962 Merkle Tree Hash", "signature": "Ed25519 over the canonical manifest bytes"},
 "files": [{"path": "2026-10-07/raw-20261007T0311-ulpf-collector-01.ndjson", "bytes": 550784, "sha256": "…",
            "records": 612, "merkle_root": "…", "first_event_uid": "…", "last_event_uid": "…", …}],
 "records": 612, "merkle_root": "…"}
```

`HEAD` holds `<seq> <sha256 of the newest manifest>`; recording it outside the
host lets `ulpf verify --expect-head` detect tail truncation (the only attack
a self-contained hash chain cannot see).

## Index documents

OpenSearch `_id` = `event_uid`, so replays and backfills replace documents
instead of duplicating them. Mapping: generated from the OCSF dictionary types;
`unmapped` is a `flat_object`; `ulpf.lineage`/`ulpf.errors` are stored but not
indexed; `time` is `epoch_millis`; `ulpf.ingest.time` is `date_nanos`.

## Parquet lake

Columns: `event_uid, time, ingest_time_ms, class_uid, activity_id, severity_id,
status, parser_id, vendor, product, src_ip, src_port, dst_ip, dst_port,
protocol_num, action_id, bytes_out, bytes_in, fingerprint, raw_sha256` and
`event_json` = the exact normalized NDJSON line (lossless). Partitioned
`date=YYYY-MM-DD`; manifest with source and Parquet SHA-256.
