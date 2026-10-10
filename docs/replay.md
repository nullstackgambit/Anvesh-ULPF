# Replay, backfill and repair

The raw archive is the source of truth. Any searchable copy can be rebuilt
from it with the current approved specs, through the same generated VRL that
runs live (ADR-010). Every replay re-verifies each record's SHA-256 and
length on the way (`replay_envelope.vrl`; a mismatch becomes
`status=failed`, `archive_integrity`). Replayed events keep their
`event_uid` (the OpenSearch `_id`), ingest time, collector and transport, and
carry `ulpf.replay.run`. Every run is appended to
`runtime/data/state/replays.ndjson`.

| Command | When | What it does |
|---|---|---|
| `ulpf replay new-index [--since ISO] [--until ISO] [--no-switch]` | the specs changed and the whole index should reflect them | Re-processes the archive into a new backing index `<prefix>-v<N+1>`. If the document count equals the number of distinct archived UIDs, it moves the read and write aliases in **one** `_aliases` request (atomic for searchers and for the live writer). It then catches up on events archived meanwhile, plus anything still only in the old index. If the counts differ, the aliases are not moved and the new index is left for inspection. |
| `ulpf replay rollback --to <index>` | the new index is wrong | Moves both aliases back atomically. |
| `ulpf replay backfill [--status fallback]` | after onboarding a source | Re-processes the archived events whose *indexed* status matches, into the index each document lives in. The same `_id` replaces the fallback document in place, so nothing is duplicated. |
| `ulpf replay missing` | after an OpenSearch outage (the index buffer was full, or Vector stopped while OpenSearch was unreachable) | Re-indexes archived events absent from the index. |
| `ulpf replay status` | any time | Lists backing indices, alias targets and counts. |
| `ulpf repair [--dry-run]` | `ulpf account` reports a gap | Closes accounting gaps in three directions (below). |

## `ulpf repair`

1. **archive ← index.** An event that is indexed but not archived is
   recovered from the indexed document (`ulpf.raw.b64`, else `raw_data`)
   only if the bytes hash to the SHA-256 and length computed at ingest. It is
   written to a separate file `raw-<bucket>-<collector>-recovered-<time>.ndjson`
   whose records carry `recovered: {from, index, at}`. The original archive
   files are never rewritten. A document without raw bytes cannot be
   recovered this way and is reported as rejected.
2. **normalized ← archive.** Archived events missing from the normalized
   store are re-processed by a batch run and appended.
3. **index ← archive.** The same as `ulpf replay missing`.

Evidence: `verification/repair_after_reload_incident.json` (1311 events
recovered after the hot-reload incident, finding P6-4), then accounting PASS.

## Evidence

| Scenario | File |
|---|---|
| new index + atomic alias switch + catch-up, under live traffic | `verification/scenario6_replay.json`, `verification/scenario6_account.txt` (sent 4000 during the replay; archived = normalized = indexed; PASS) |
| backfill after onboarding (fallback → parsed, same `_id`) | `verification/scenario3_onboarding_live.log` |
| outage → `replay missing` | `verification/outage_test.log`, `verification/outage_test_memory_buffer.log` |

Batch runs start a fresh Vector process each time. For 13 specs, VRL type
checking dominates start-up, so even a small replay takes about 15 s
(Scenario 6: 1,846 records in 17.6 s).
