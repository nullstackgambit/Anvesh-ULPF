# Onboarding an unknown source

Status: **IMPLEMENTED AND TESTED** (`tests/unit/test_onboard.py`,
`tests/e2e/test_onboarding.py`, live run: `verification/scenario3_onboarding_live.md`).

An event no approved spec claims is never dropped: it is archived byte-for-byte,
indexed as an OCSF Base Event with `ulpf.status = fallback` (every generic layer
kept in `unmapped`) and copied to the DLQ. Onboarding turns such a cluster into
an approved spec without any hand-written VRL:

```
unknown traffic ─► DLQ (fallback) ─► ulpf fingerprint ─► ulpf onboard ─► draft
                                                                   │  (human review / edit)
                                     live config ◄─ ulpf promote ◄─ ulpf gate (PASS)
```

## 1. Find the cluster — `ulpf fingerprint`

Every event carries `ulpf.fingerprint`, a 16-hex structural signature computed by
the pre-parser (`pipeline/vector/static/preparse.vrl`):

| layer found            | shape used in the fingerprint                                   |
|------------------------|-----------------------------------------------------------------|
| JSON / KV              | the key set                                                     |
| CEF / LEEF             | vendor, product, event class                                    |
| CSV (commas)           | column count                                                    |
| syslog-framed text     | the syslog app name                                             |
| unframed plain text    | leading literal token + counts of `|` and `;`                  |

`ulpf fingerprint` groups the DLQ's fallback events by fingerprint (count,
format, first/last seen, transports, peers, an example). `ulpf mine FP` shows
drain3 templates for one cluster (in memory only; `--split '|;'` adds token
delimiters for display).

## 2. Propose a draft — `ulpf onboard FP --id vendor.product.type ...`

* **Samples come from the raw archive**, re-verified against their SHA-256
  (never from a normalized document), evenly spread over the cluster's time
  range (`--max-samples`, default 300). They are stored as replayable archive
  records in `runtime/data/onboarding/<id>/samples.ndjson`.
* The samples are run through the **runtime pre-parser** (real Vector,
  `pipeline.preparse_config`), so onboarding sees exactly the body, syslog
  header and layers the live pipeline sees.
* **Structure**: a layer the runtime already found (JSON, KV, CEF, LEEF, CSV)
  is used directly; otherwise `onboard/infer.py` looks for a consistent
  delimiter (header columns, optionally followed by a `k<sep>v` list), and for
  free text the dominant drain3 template becomes an anchored regex with one
  named group per parameter.
* **Types** are inferred from values (IP, MAC, port-sized int, long, float,
  RFC 3339 / strftime / epoch timestamps).
* **Mappings** (`onboard/suggest.py`): a name-synonym table **and** a value-type
  check **and** resolution against the vendored OCSF 1.9.0 class with the
  smallest vendored profile combination. Action-like fields are detected by
  their *values* (allow/deny vocabulary), so positional columns qualify.
  Each suggestion records its confidence and the evidence for it.
* **Active vs inactive**: suggestions with confidence ≥ 0.5 become active
  mappings; lower ones and every LLM suggestion are written as **comments**
  for the reviewer.
* **Tests**: up to `--max-tests` samples (covering every action value) become
  test vectors whose `expect` values are computed **in Python, independently
  of the VRL** the compiler will generate (time, ports, protocol numbers via
  the IANA table, enum ids).
* `--samples synthetic|real|mixed` is mandatory: the draft embeds samples
  verbatim, so their provenance must be stated (and real data reviewed for
  sensitive content before committing).

The draft is `specs/_drafts/<id>.yaml` with `status: draft`; drafts are never
compiled into the live configuration (`ulpf spec compile` skips them).

### Optional local LLM (`--llm`)

Off unless `ULPF_LLM_URL` points to an OpenAI-compatible endpoint on
**127.0.0.1/localhost/::1** (any other host is refused — no external API in the
processing path or the air-gapped deployment). The model sees field names,
inferred types and up to three example values. Every reply is validated:
unknown source fields, OCSF paths that do not exist in 1.9.0, paths needing an
unapplied profile, type-incompatible destinations and enum attributes are
discarded; confidence is capped at 0.8. Surviving suggestions are written as
`# LLM SUGGESTION (unverified)` comments only — the LLM never writes an active
mapping and never overrides deterministic validation. Tested against a stub
server (`tests/unit/test_onboard.py::test_llm_*`).

## 3. Review

The `review required:` list (also under `onboarding.review_required`) names what
a human must confirm: name-only evidence, policy choices (e.g. allow→Traffic,
deny→Refuse), the src/dst direction (`is_src_dst_assignment_known`) and the
fields that stay in `unmapped`. Edit the draft freely; the gate binds to the
content you leave.

## 4. Gate — `ulpf gate specs/_drafts/<id>.yaml`

| gate          | passes when                                                                                   |
|---------------|-----------------------------------------------------------------------------------------------|
| `lint`        | no lint errors in the draft or any approved spec; id is new                                   |
| `compile`     | approved specs + draft compile; real `vector validate`; no VRL compiler warnings               |
| `draft_tests` | every draft vector: delivered, routed to the draft, expectations, OCSF schema + envelope, completeness oracle, byte-exact round trip |
| `regression`  | every approved spec's vectors are unchanged (golden equality) with the draft in the pipeline — a greedy `match` fails here |
| `samples`     | the captured samples replayed through approved specs + draft: ≥ 95 % claimed by the draft (`--min-claim`), no failed events, ≤ 5 % partial, all schema-valid, all raw bytes reproduced |

The report (`runtime/data/onboarding/<id>/gate.json`, history in
`gate-<time>.json`) records the draft's **content hash** (spec content
excluding `status`, `approval`, `onboarding`) and a hash of the approved spec
set it ran against.

## 5. Promote — `ulpf promote <draft> --approver "First Last"`

Refused unless the approver is a named human (not `llm`, `ai`, `auto`, …), the
latest gate report is PASS, its content hash equals the draft's current
content and the approved spec set has not changed since. Then, with rollback
on any failure:

1. `specs/<vendor>/<name>.yaml` with `status: approved` and an `approval:`
   record (approver, time, note, content hash, gate-report hash);
2. golden files for its vectors, written and re-checked (determinism);
3. a drift baseline from the samples (`runtime/data/state/drift/<id>.baseline.json`);
4. the live configuration is rebuilt and atomically replaced — a running
   Vector (`--watch-config`) hot-reloads it without dropping events;
5. the draft is archived next to its gate reports and the promotion appended to
   `runtime/data/state/promotions.ndjson`.

Events that arrived while the source was unknown remain `fallback` in the
index until replayed through the new spec (see `docs/replay.md`).

## Drift and scorecard

`ulpf drift check` compares recent traffic per spec with its baseline using
explicit thresholds (new unmapped fields, mapped attributes disappearing,
partial/failed share rising, new error codes, mapped-ratio drop, new
fingerprints, spec version changes) and lists unknown clusters
(`UNKNOWN_SOURCE`). `ulpf drift baseline --spec ID` re-baselines from live
traffic after review. `ulpf scorecard` shows per-spec tests, goldens, parse
rate, mapped ratio, drift and provenance with documented thresholds.

## Limits (honest)

* Structure inference handles JSON/KV/CEF/LEEF/CSV layers, header-columns +
  key-value payloads, delimiter-separated columns and single-template free
  text. Multi-template free text needs one onboarding per template or manual
  regex work.
* Header columns get positional names (`h0`, `h1`, …); naming them is part of
  the review.
* Name synonyms are a fixed table; anything outside it stays unmapped (and is
  still preserved) until a reviewer maps it.
