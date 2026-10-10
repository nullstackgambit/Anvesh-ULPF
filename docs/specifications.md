# Source specifications (YAML DSL)

A spec describes one source/log type declaratively. `ulpf spec lint` validates
it (strict YAML, `schema/spec.schema.json`, semantic checks against the
vendored OCSF 1.9.0 schema); `ulpf spec compile` turns every approved spec into
a VRL program, validates the whole configuration with the real Vector binary
and atomically replaces the live configuration; `ulpf test` runs the spec's
test vectors through that same Vector. Nobody writes VRL by hand.

Example: [`specs/fortinet/fortigate_traffic.yaml`](../specs/fortinet/fortigate_traffic.yaml).
Approved specs: FortiGate traffic, PAN-OS traffic (130 columns), Cisco ASA
302013–302016, pfSense filterlog, Suricata eve flow + alert, Zeek conn, Squid
access, and generic syslog/JSON/KV/CEF/LEEF (`generic: true`, status fallback).

## Top level

| Key | Required | Meaning |
|---|---|---|
| `id` | yes | `vendor.product.logtype` (lowercase, dots) |
| `version` | yes | semantic version; part of the spec hash recorded in every event |
| `status` | — | `approved` (default) or `draft` (never compiled into the live config) |
| `vendor`, `product` | yes | written to `metadata.product` |
| `description`, `references` | — | references = vendor documentation URLs the mapping was verified against |
| `samples` | (warning if absent) | `synthetic` · `real` · `mixed` — provenance of the test vectors |
| `priority` | — | match order (higher first); generic specs 10–20, onboarding drafts 150, vendor specs 200 |
| `generic` | — | structure-only spec: events get `status: fallback` |
| `ocsf` | yes | `{class, profiles}` — class name and a **vendored** profile combination (none, `security_control`, `host`+`security_control`) |
| `match` | yes | `all` / `any` / `none` lists of conditions |
| `parse` | yes | how to extract source fields |
| `time` | — | ordered time candidates |
| `fields` | — | source field → OCSF attribute (or deliberate `unmapped`) |
| `enums` | — | value tables → enum attributes (`action_id`, `disposition_id`, `activity_id`, `severity_id`, …) |
| `set` | — | constants (e.g. `device.type_id: 9`) |
| `derive` | — | computed attributes |
| `unmapped` | — | `empty_values: count|keep`, `empty_markers: ["-"]` |
| `pii` | — | `[{field, action: hmac_sha256}]` — pseudonymised with the install's `pii.key` before mapping |
| `tests` | yes (≥ 1) | `{name, raw|raw_file, expect, golden}` |
| `onboarding`, `approval` | — | written by `ulpf onboard` / `ulpf promote`; ignored by the compiler and the spec hash |

## `match` conditions

`{layer: syslog|pri|json|cef|leef|kv|csv|text}` or
`{field: <path>, <one of> equals|in|prefix|contains|regex|exists}`, where
`<path>` is `body`, `after_pri`, `text`, `raw` or `<layer>.<key>`
(`kv.devid`, `json.event_type`, `cef.deviceVendor`, `leef.vendor`,
`syslog.appname`). Regexes are checked for Rust-regex compatibility
(no look-around/backreferences — VRL uses Rust's `regex`).

## `parse`

| `kind` | Options | Source fields |
|---|---|---|
| `kv` | `kv: {field_delimiter, value_delimiter}` | keys |
| `json` | `json: {flatten: true}` | flattened keys (`a.b`) |
| `csv` | `csv: {delimiter, segments: [{columns: [...], when: {column, equals|in}}]}` | named columns; extra columns kept as `_extra_<i>` |
| `cef` | — | CEF header (`deviceVendor`, …) + extension keys |
| `leef` | — | LEEF 1.0/2.0 attributes + `leef.version/vendor/product/product_version/event_id` |
| `regex` | `regex: {pattern}` | named groups |

Common: `input: body|after_pri|text` (what to parse; `body` = syslog message
or text after PRI), `extract: <regex with (?P<payload>…)>` (cut a header off
first; other named groups become source fields), `include_syslog: true`
(expose `syslog.hostname`, `syslog.appname`, …, `syslog.timestamp_raw`).

## `time` (first candidate that succeeds wins; failures are recorded)

`{field | fields: [a, b], format, timezone, offset_field, year: infer}` with
`format` = `epoch_auto` (unit from digit count), `epoch_s|ms|us|ns`,
`rfc3339`, or a strftime pattern. No source time → receipt time, recorded as
`ulpf.time.source = ingest`. Assumed zones and inferred years are recorded.

## `fields`

```yaml
srcip:     {to: src_endpoint.ip, type: ip}
proto:     {to: connection_info.protocol_name, type: string, transform: lower}
duration:  {unmapped: true, note: "OCSF duration is for aggregate events only"}
```

`type`: `string`, `ip`, `subnet`, `port`, `int`, `long`, `float`, `bool`,
`mac`, `timestamp`, `json` (lint checks it against the OCSF attribute type);
`transform`: `lower|upper|trim`; `scale` for numeric units. A value that
fails coercion is never dropped: it stays in `unmapped` and the event becomes
`partial` with an error entry.

## `enums`

```yaml
- source: action
  map:
    accept: {activity_id: 6, action_id: 1, disposition_id: 1}
    deny:   {activity_id: 5, action_id: 2, disposition_id: 2}
  default: {activity_id: 99, action_id: 99, disposition_id: 99}   # unknown value: caption keeps the source value
  missing: {activity_id: 0, action_id: 0, disposition_id: 0}
  # case_insensitive: true (default) · match: exact|contains · otherwise: …
```

Every id is checked against the class's enum in OCSF 1.9.0; captions
(`action`, `disposition`, …) and `type_uid` are filled by the compiler.

## `derive`

`iana_protocol_name` / `iana_protocol_num` (vendored IANA registry),
`community_id` (needs src/dst IP + protocol number), `tz_offset_minutes`
(from an offset source field), `copy` (from another OCSF path).

## Lint rules (errors block compilation)

Strict YAML (duplicate keys, YAML 1.2 booleans) · schema validity · class and
profile combination vendored · every `to:` path exists in the class with the
applied profiles, no array traversal, no reserved attributes ULPF owns
(`class_uid`, `metadata.uid`, `raw_data`, `time`, …), no two mappings to the
same attribute · type compatibility · enum ids valid · `set` values typed ·
derive prerequisites present · each source field consumed once per kind ·
required class attributes and class constraints satisfiable · regexes
Rust-compatible and quote-free · unique test names · `raw_file` exists.

## Tests (`ulpf test`)

Each vector is pushed through the full live pipeline (all specs, so routing
is tested too) and checked for: delivered · routed to this spec · `expect`
subset · full **golden** equality (`tests/golden/<id>/<name>.expected.json`,
`--update` after review) · OCSF JSON Schema + semantic + envelope validity ·
**completeness** (an independent Python tokenizer re-derives the source
fields from the raw bytes; each must be mapped, unmapped or recorded empty) ·
byte-exact **round trip** of `raw_data`/`ulpf.raw.b64`.
