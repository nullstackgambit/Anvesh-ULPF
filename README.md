# ULPF — Universal Log Pre-processing Framework

ULPF ingests heterogeneous security and network logs, **keeps every received
byte**, identifies the source and format, parses vendor fields, normalizes them
to **OCSF 1.9.0**, keeps whatever it could not map, records where every
normalized value came from, validates the result, and hands it to OpenSearch,
NDJSON and Parquet for SIEM, hunting and ML use. It runs as native processes
(no containers) and is designed to install on an **air-gapped** host from a
signed offline bundle.

> Status vocabulary used throughout: **VERIFIED**, **IMPLEMENTED AND TESTED**,
> ARCHITECTURAL DESIGN, ASSUMPTION, UNVERIFIED. The evidence for each claim is in
> [`verification/VERIFICATION_REPORT.md`](verification/VERIFICATION_REPORT.md)
> and the evidence files next to it. All sample logs in this repository are
> **SYNTHETIC TEST DATA** in formats checked against official vendor
> documentation.

## Why it exists

Every SOC re-implements parsers per vendor, per firmware, per SIEM, and each
of them silently drops what it does not understand. ULPF's principle is
**normalization must be non-destructive**:
- **Raw first:** the raw event is archived before anything else, and the
  archive is tamper-evident (Merkle tree, Ed25519 signature, hash chain).
- **Traceable:** the normalized event points back to it (event UID, SHA-256,
  field lineage).
- **Nothing discarded:** anything ULPF cannot map is kept.

New sources are onboarded from data (fingerprint, draft, gate, human approval)
without hand-written parser code.

## Architecture

```
 syslog UDP/TCP/TLS, HTTP NDJSON, file inbox                 (Vector 0.58, bytes codec)
        │
  envelope: event_uid (UUIDv7), ingest time, collector, transport, peer, raw SHA-256
        ├──────────────► raw archive  (one JSON line per event, base64 bytes)
        │                   └─ ulpf seal: RFC 6962 Merkle root, Ed25519, hash-chained manifests
        ▼
  pre-parse (PRI / syslog / CEF / LEEF / JSON / KV / CSV layers, fingerprint)
        ▼
  match ──► route ──► one compiled VRL program per approved spec (YAML DSL → VRL)
        │                         │
        │   no match / error      ▼
        └────► fallback ──► finalize: OCSF metadata, raw_data + hash, lineage, coverage, status
                                  ├──► OpenSearch (alias-based indices; own buffer, memory by default)
                                  ├──► normalized NDJSON ──► ulpf lake compact ──► Parquet
                                  └──► DLQ (fallback/failed) ──► ulpf fingerprint / onboard
control plane: `ulpf` CLI + Streamlit UI (lint, compile, test, onboard, gate, promote,
               seal, verify, replay, repair, drift, scorecard, detect, lake, bundle)
```

Details: [docs/architecture.md](docs/architecture.md) ·
data model: [docs/data-model.md](docs/data-model.md) ·
spec DSL: [docs/specifications.md](docs/specifications.md) ·
decisions: [docs/architecture-decisions.md](docs/architecture-decisions.md)

## Requirements

| | |
|---|---|
| OS | Linux x86-64. Tested on Ubuntu (kernel 7.0) in a VM with 8 vCPUs and 7.9 GB RAM. No root, no Docker. |
| Python | CPython **3.12** with the `venv` module. The pinned wheels are built for cp312/x86-64; on Debian/Ubuntu `python3 -m venv` may need the `python3.12-venv` package. If `python3` is not 3.12, pass it explicitly: `make PY=python3.12 fetch venv`. |
| Tools | `bash`, `make`. `openssl` is used only to check an offline bundle's signature; `bwrap` (bubblewrap) only by the air-gap test. |
| Memory | Measured at idle (2026-10-10): OpenSearch 1.35 GB (1 GB heap, set with `ULPF_OS_HEAP`), Vector 0.13 GB, UI 0.05 GB before the first page view. Plan on at least 4 GB of RAM. |
| Disk | About 2 GB for the installation (breakdown in [docs/architecture.md](docs/architecture.md#disk-footprint-measured-2026-10-07-reference-vm)). Data takes about 6 KB per event: archive 0.9 KB, normalized NDJSON 5 KB (0.3 KB once compacted to Parquet), index 2 KB. OpenSearch stops accepting writes when free space drops below 600 MB. |
| Network | Only for the one-time `make fetch`: pypi.org and files.pythonhosted.org (Python wheels), github.com (Vector), artifacts.opensearch.org (OpenSearch) and repo1.maven.org (security plugin). After that nothing is downloaded, and the processing path never contacts the internet. |

## Setup

All commands run from the repository root, as an ordinary user.

### 1. Download the pinned dependencies (online, once)

```bash
make fetch
```

This creates `.venv`. It downloads every Python wheel listed in
[`requirements.lock`](requirements.lock) into `runtime/wheelhouse`, with
`pip --require-hashes`. It also downloads Vector 0.58.0, OpenSearch 3.8.0 and
the OpenSearch security plugin into `runtime/dist`, each checked against its
SHA-256 pin in [`deploy/airgap/ARTIFACTS.json`](deploy/airgap/ARTIFACTS.json).
The one dependency PyPI publishes only as source (drain3 0.9.11) ships as a
pinned wheel in [`deploy/wheels/`](deploy/wheels/README.md).

`runtime/` is never committed. After this step, everything below works
offline. To install on a machine without internet access, build an offline
bundle instead (see [Air-gapped deployment](#air-gapped-deployment)).

### 2. Install

```bash
make venv                 # installs the wheels offline, hash-checked, plus ulpf itself
make runtime              # verifies the artifacts again and unpacks Vector + OpenSearch (+ security plugin)
.venv/bin/ulpf doctor     # self-check: every line should read [OK  ]
```

`ulpf doctor` checks:
- the Python and pinned package versions;
- the Vector and OpenSearch installs and the binary hashes;
- the vendored OCSF schema and IANA protocol table;
- spec lint, the generated config and the seal key;
- at least 1 GB of free disk;
- that every listener is bound to loopback.

Before the first compile and before `ulpf keygen`, it reports those two items
as warnings.

### 3. Keys, secrets and certificates (generated locally, never committed)

```bash
.venv/bin/ulpf keygen          # Ed25519 archive sealing key -> deploy/keys/seal.key (0600) + seal.pub
.venv/bin/ulpf secrets init    # PII HMAC key + OpenSearch passwords -> runtime/secrets/ (0700)
.venv/bin/ulpf certs init      # deployment CA + TLS certificates -> deploy/certs/
.venv/bin/ulpf os secure       # recommended: OpenSearch TLS + users admin / ulpf-writer / ulpf-reader
```

`make secure` runs the last three commands. `ulpf os secure` writes
`runtime/ulpf.local.yaml`, which switches every client (CLI, Vector, UI) to
HTTPS with credentials. Back up `deploy/keys/`, `deploy/certs/` and
`runtime/secrets/` together with the archive: manifests signed with a lost key
cannot be verified with a new one, and a new PII key changes every pseudonym.

### 4. Check the parsers

```bash
.venv/bin/ulpf spec lint
.venv/bin/ulpf test            # 31 test vectors of the 13 approved specs, through the real Vector binary
```

### 5. Start

```bash
make up                        # ulpf spec compile + ulpf stack up: OpenSearch, Vector, UI
.venv/bin/ulpf stack status    # each service should read "healthy"
```

On the reference VM, `make up` took 59 s. The first OpenSearch start after
`ulpf os secure` initialises the security index and can take up to 5 minutes.

Then open the UI at <http://127.0.0.1:8501>.

### 6. Send test traffic and prove nothing was lost

```bash
.venv/bin/ulpf gen --vendor fortigate --vendor panos --count 500 --transport tcp --sendlog runtime/data/sendlog.ndjson
.venv/bin/ulpf account --sendlog runtime/data/sendlog.ndjson
```

`account` compares sent, archived, normalized and indexed events by SHA-256
and UID. It ends with `verdict PASS` when they are all equal. `ulpf gen --list`
shows all synthetic sources.

## Sending logs

| Input | Address (default) | Notes |
|---|---|---|
| syslog over UDP | `127.0.0.1:5514` | one event per datagram, bytes kept exactly |
| syslog over TCP | `127.0.0.1:5514` | newline-framed, max 1 MiB per frame. RFC 6587 octet counting is off by default (finding V20, see `deploy/ulpf.yaml`). |
| syslog over TLS | `127.0.0.1:6514` | enabled once `ulpf certs init` has created the server certificate; senders trust `deploy/certs/ulpf-ca.crt` |
| HTTP | `POST http://127.0.0.1:8088/` | newline-delimited events |
| files | `runtime/data/inbox/*.log` | one event per line; files are read from the beginning |

Everything listens on loopback by default. To receive from other hosts:
- **Listeners:** change the addresses under `listen:` in
  [`deploy/ulpf.yaml`](deploy/ulpf.yaml).
- **TCP:** set `permit_origin`. Vector applies it to TCP listeners only, so
  restrict UDP with the bind address or a host firewall.
- **Certificates:** `ulpf certs init` issues loopback names only, so TLS from
  other hosts needs certificates for the real host name.

`ulpf doctor` reports non-loopback listeners as FAIL, on purpose.

Other local ports:

| Port | Service |
|---|---|
| 8686 | Vector API (health) |
| 9598 | Vector internal metrics (Prometheus) |
| 9200, 9300 | OpenSearch HTTP and transport |
| 8501 | UI |

## Everyday operation

```bash
make up / make down / make status        # all services (or: ulpf stack up|down|status [service])
.venv/bin/ulpf seal                      # seal closed raw-archive files (Merkle root, signature, chain)
.venv/bin/ulpf verify                    # re-check the whole archive against its signed manifests
make lake                                # compact closed normalized NDJSON to Parquet and prune it (~16x smaller)
.venv/bin/ulpf spec compile              # after a spec change: Vector hot-reloads the new parser
```

| What | Where |
|---|---|
| Service logs | `runtime/logs/<service>.log` |
| PID files | `runtime/run/` |
| Configuration | [`deploy/ulpf.yaml`](deploy/ulpf.yaml) (no secrets), plus `runtime/ulpf.local.yaml` written by `ulpf os secure` |

- **Seal regularly.** Record the line in
  `runtime/data/archive/manifests/HEAD` somewhere outside the host, so
  `ulpf verify --expect-head` can also detect a truncated chain.
- **Structural changes need a restart.** Changes outside the spec parsers
  (sinks, codecs, the archive branch, listeners) are refused while Vector runs,
  because a hot reload would re-encode events Vector had already buffered
  (finding P6-4). Apply them with `ulpf spec compile --restart`: Vector drains
  its buffers, then restarts. Listeners are down until Vector has started
  again (up to about a minute on the reference VM), so do it in a maintenance
  window.
- **What to back up:**
  - must keep: `runtime/data/archive/` (with `manifests/` and `index.sqlite`),
    `deploy/keys/`, `deploy/certs/`, `runtime/secrets/` and
    `runtime/data/state/` (drift baselines, promotion audit log);
  - only once NDJSON has been pruned: `runtime/data/lake/`;
  - the OpenSearch index and the normalized files can be rebuilt from the
    archive ([docs/replay.md](docs/replay.md)).

## Operator UI

<http://127.0.0.1:8501> has seven pages:

| Page | What it shows |
|---|---|
| Overview | service health, volume by product, processing status, parser scorecard, drift |
| Live feed | logs as they arrive (refreshes every second): the received line, how it was recognised, the OCSF event it became, step by step |
| Event explorer | search on OCSF fields; per event the lineage, the exact original bytes and a Merkle proof |
| Unknown sources & onboarding | unknown sources grouped by fingerprint; drafts, gate and promotion |
| Archive integrity | sealed batches and on-demand verification |
| Replay | indices, aliases and replay history |
| Detections | Sigma rules and anomaly ranking |

The page and text size are part of the URL (for example `?page=live&ts=lg`).
When OpenSearch security is on, the UI reads with the least-privilege
`ulpf-reader` user; only the Replay page uses the admin user, for index and
alias metadata. Its look is in [`ulpf/ui/theme.py`](ulpf/ui/theme.py) and
[`.streamlit/config.toml`](.streamlit/config.toml). After changing UI code,
restart it: `ulpf stack down ui && ulpf stack up ui`.

## Live demo

```bash
make demo-live      # restarts the UI in demo mode; open http://127.0.0.1:8501/?page=live and press Start
make demo-stop      # back to normal mode
```

Demo mode adds Start/Stop controls for synthetic traffic: the seven supported
vendors, optionally an unknown source and malformed lines. The traffic stops
by itself after 15 minutes. A recording script and the accounting check are
in [docs/demo-script.md](docs/demo-script.md).

## Example input (FortiGate traffic log, SYNTHETIC TEST DATA)

```
<189>date=2026-10-07 time=10:15:30 devname="FGT-HQ-01" devid="FGT60FTK00000001" eventtime=1791368130123456789 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.1.1.10 srcport=51234 srcintf="port1" srcintfrole="lan" dstip=203.0.113.10 dstport=443 dstintf="wan1" dstintfrole="wan" sessionid=123456 proto=6 action="close" policyid=5 policytype="policy" service="HTTPS" trandisp="snat" transip=198.51.100.1 transport=51234 duration=12 sentbyte=1520 rcvdbyte=8240 sentpkt=12 rcvdpkt=10 appcat="unscanned"
```

## Example normalized output (excerpt of `tests/golden/fortinet.fortigate.traffic/tcp_close_allowed.expected.json`)

```json
{
  "class_uid": 4001, "class_name": "Network Activity", "activity_name": "Close",
  "action": "Allowed", "disposition": "Allowed", "time": 1791368130123,
  "src_endpoint": {"interface_name": "port1", "ip": "10.1.1.10", "port": 51234},
  "dst_endpoint": {"interface_name": "wan1", "ip": "203.0.113.10", "port": 443},
  "connection_info": {"community_uid": "1:YMIi228T6sxFzIxP+kTfOVMeV/o=", "protocol_name": "tcp", "protocol_num": 6, "uid": "123456",
                      "direction": "Unknown", "direction_id": 0},
  "traffic": {"bytes_in": 8240, "bytes_out": 1520, "packets_in": 10, "packets_out": 12},
  "device": {"hostname": "FGT-HQ-01", "type": "Firewall", "type_id": 9, "uid": "FGT60FTK00000001"},
  "metadata": {"version": "1.9.0", "product": {"name": "FortiGate", "vendor_name": "Fortinet"}, "log_format": "pri+kv"},
  "raw_data_hash": {"algorithm_id": 3, "value": "a4cd9372…16803c"},
  "unmapped": {"appcat": "unscanned", "duration": "12", "service": "HTTPS", "…": "…"},
  "ulpf": {
    "status": "parsed",
    "parser": {"id": "fortinet.fortigate.traffic", "version": "1.1.0", "spec_sha256": "7658d632…5a213f"},
    "coverage": {"fields": 34, "mapped": 21, "unmapped": 13, "empty": 0},
    "lineage": {"connection_info.protocol_num": "proto", "action_id": "enum:action",
                "connection_info.protocol_name": "derived:iana_protocol_name(connection_info.protocol_num)", "…": "…"},
    "time": {"source": "field", "field": "eventtime", "format": "epoch_auto"}
  }
}
```

`raw_data` (not shown) holds the exact input line. `ulpf raw get <event_uid>
--proof` returns the archived bytes with a Merkle inclusion proof.

## Source onboarding

```bash
ulpf fingerprint                       # unknown clusters in the DLQ
ulpf onboard <FP> --id acme.blackbox.flow --vendor "…" --product "…" --samples synthetic
#   -> specs/_drafts/acme.blackbox.flow.yaml with every suggestion's evidence; edit/review it
ulpf gate specs/_drafts/acme.blackbox.flow.yaml        # lint, compile, tests, regression, samples
ulpf promote specs/_drafts/acme.blackbox.flow.yaml --approver "Your Name"
#   -> approved spec + goldens + drift baseline; Vector hot-reloads the live config
ulpf replay backfill --status fallback                 # re-process events received while unknown
```

An optional **local** LLM can add suggestions: set `ULPF_LLM_URL` to an
OpenAI-compatible endpoint on localhost (other hosts are refused), optionally
`ULPF_LLM_MODEL`, and pass `ulpf onboard --llm`. Its suggestions are checked
against the OCSF schema and written only as inactive comments; they never
change a mapping. Full workflow: [docs/onboarding.md](docs/onboarding.md).
Replay, backfill and repair: [docs/replay.md](docs/replay.md).

## Testing

```bash
make test-fast       # unit + golden tests (no services needed)
make test            # everything; tests that need the live stack skip when it is down
make test-golden     # ulpf test: every spec's vectors through the real Vector binary
```

- **`tests/unit`:** spec lint, YAML/VRL safety, the compiler, OCSF, archive
  integrity, the Parquet lake, drift, onboarding, detections, reload safety and
  demo traffic.
- **`tests/platform`:** the Vector and OpenSearch behaviours ULPF relies on.
- **`tests/golden`:** the spec vectors.
- **`tests/e2e`:** against the live stack: the live slice, losslessness,
  cross-vendor parsing, onboarding, detections, security and the UI.

`ulpf test` applies five checks to each vector: the expected values, the
golden file, the OCSF JSON schema, an independent completeness oracle, and a
byte-exact round trip of the raw input. Latest run (2026-10-10): the unit
and UI tests, 148 passed. The scenario evidence is in `verification/`.

## Air-gapped deployment

```bash
make bundle                            # signed bundle: source, pinned binaries, wheels, lock file
#   -> runtime/bundle/ulpf-bundle-0.1.0/  (ulpf bundle build --tar writes one .tar to transfer)
#   compare the SHA-256 of release.pub out of band, then on the target:
./install.sh /opt/ulpf --pubkey release.pub    # verifies, installs offline, generates keys and secrets
```

The installer checks the Ed25519 signature and every file hash, builds the
virtualenv from the bundled wheels, unpacks the runtime, generates keys,
secrets and certificates on the target, enables OpenSearch security and runs
`ulpf doctor`.

**Status:** `scripts/airgap_test.sh` runs the install inside a network
namespace with no route and no DNS. In the latest run
(`verification/scenario9_airgap.log`) the offline install and all 31 test
vectors passed. The end-to-end accounting step reported FAIL, because it ran
while the index was still catching up (217 of 300 events not yet indexed).
Accounting now waits for the index, and a re-run is pending.

## Troubleshooting

- **Services stop when their terminal closes.** On this Ubuntu desktop,
  closing the terminal that ran `make up` also stopped OpenSearch and Vector.
  Keep it open, or run `make up` again.
- **"something already answers on its port".** Another instance is running:
  check `ulpf stack status`, or stop it with `make down`.
- **`ulpf spec compile` refuses a "structural change".** See
  [Everyday operation](#everyday-operation): use `--restart`.
- **`ulpf seal` exits with "NOT SEALED (gaps)".** An archive file has empty
  lines (events written without a record). Check with `ulpf account`, close the
  gap with `ulpf repair`, then run `ulpf seal --accept-gaps` to declare the
  gaps in the signed manifest.
- **The index stops growing while the disk is nearly full.** OpenSearch
  refuses writes below 600 MB free (watermarks 1.5 GB / 1 GB / 600 MB). The raw
  archive keeps receiving everything. Free some space (for example
  `make lake`, `make clean`), then run `ulpf replay missing`.
- **OpenSearch is slow to come up.** The first start after `ulpf os secure`
  can take up to 5 minutes. Look in `runtime/logs/opensearch.log`.

## Known limitations

- **No containers.** Docker/Compose is not implemented; ULPF runs as native
  processes (ADR-002).
- **No OpenSearch Dashboards.** It is not installed (disk budget); the UI
  covers the operator views.
- **Formats.** Check Point and Cisco ASA 106023 are UNVERIFIED and not
  implemented.
- **Tamper-evident, not WORM.** Anyone holding `deploy/keys/seal.key` can
  re-sign a modified archive. Deleting the newest manifests is detected only
  against an externally recorded head (`ulpf verify --expect-head`). Key
  rotation with several trusted keys is not implemented.
- **PII in `raw_data`.** Fields a spec marks as `pii` are pseudonymised in the
  mapped and unmapped values. But `raw_data`, the full received line, still
  contains them in clear text in OpenSearch and in the normalized files. Not
  fixed yet.
- **No UI login.** The UI has no authentication of its own. It listens on
  loopback only, so anyone with a shell on the host can open it, including the
  gate and promotion forms (the approver name is self-declared).
- **Loopback certificates.** `ulpf certs init` issues certificates for
  localhost/127.0.0.1 only.
- **No service manager.** The services are not system services (no systemd
  units). They stop with the terminal or session that started them, and do
  not start at boot.
- **Hot reloads.** Spec changes are applied by Vector's hot reload. Structural
  configuration changes are refused unless applied with a drained restart
  (finding P6-4).
- **Syslog has no acknowledgements.** Syslog over UDP and TCP has no delivery
  acknowledgement, so ULPF cannot detect events lost before Vector accepted
  them: on the network, in socket buffers, or while Vector was down. Vector
  warns about this at start-up. File and HTTP inputs are acknowledged. For test
  traffic, `ulpf account --sendlog` proves delivery end to end.
- **Octet counting is opt-in.** RFC 6587 octet-counted TCP is off by default:
  Vector 0.58's octet-counting framer drops a frame with invalid UTF-8 and
  every later frame on that connection (finding V20).
- **Oversized frames.** Frames over 1 MiB are discarded at framing and
  recorded. Under bursts the recorded count is a lower bound: 128 of 500
  discards were captured (finding V15).
- **Air-gap test.** The full end-to-end air-gap run has to be repeated (see
  above).

## Documentation

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | data plane, control plane, processes and ports, security, state on disk, failure handling |
| [docs/data-model.md](docs/data-model.md) | the normalized event: OCSF fields and the `ulpf` envelope |
| [docs/specifications.md](docs/specifications.md) | the spec DSL |
| [docs/onboarding.md](docs/onboarding.md) | unknown-source onboarding |
| [docs/replay.md](docs/replay.md) | replay, backfill, repair |
| [docs/demo-script.md](docs/demo-script.md) | live demo for a video |
| [docs/architecture-decisions.md](docs/architecture-decisions.md) | ADR-001 to ADR-014 |
| [verification/](verification/) | verification report, evidence logs, versions, dependencies |
| [THIRD_PARTY.md](THIRD_PARTY.md) | third-party licences |

## Layout

```
ulpf/            control plane (CLI, compiler, onboarding, integrity, replay, demo) + ulpf/ui (Streamlit UI)
pipeline/vector/ static VRL (envelope, pre-parse, fallback, finalize) + generated live config
specs/           approved source specs (YAML DSL); specs/_drafts for onboarding drafts
schema/          vendored OCSF 1.9.0, spec + provenance JSON Schemas, IANA protocols
detections/      Sigma rules + ULPF pySigma pipeline
tests/           unit, platform, golden, e2e
deploy/          ulpf.yaml (no secrets), air-gap installer + artifact pins, wheels PyPI lacks,
                 keys/ and certs/ (generated, git-ignored)
scripts/         demos, air-gap test, reload experiments, benchmark
docs/            architecture, data model, spec DSL, onboarding, replay, demo script, ADRs
verification/    reports, evidence logs, vendor format references
.streamlit/      UI theme
runtime/         everything generated or downloaded: binaries, wheels, data, logs, secrets (git-ignored)
```
