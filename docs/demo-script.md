# Live demo for a video recording

The **Live feed** page shows logs being parsed as they arrive. Each received
line appears in the feed with how it was recognised and the OCSF event it
became, and the page refreshes every second. In demo mode the page also has
Start/Stop controls for synthetic traffic, so the whole demo runs in one
browser window.

## Before recording

1. Start everything in demo mode:

   ```bash
   make demo-live
   ```

   This starts OpenSearch and Vector if needed and restarts the UI with
   `ULPF_DEMO=1`. Run it from a terminal that stays open during the recording:
   closing the terminal that started OpenSearch and Vector stops them.
2. Open <http://127.0.0.1:8501/?page=live> in a browser window of
   1920×1080 or 1280×720 (full screen: F11). Press **A+** in the top bar if the
   text should be larger on video.
3. Check the two badges in the header read *OpenSearch: Healthy* and
   *Vector: Healthy*.

## Suggested flow (about 3 minutes)

| Time | On screen | Point out |
|---|---|---|
| 0:00 | Live feed, counters at zero | ULPF takes logs from any vendor, keeps every byte, and normalizes them to OCSF 1.9.0. |
| 0:15 | Press **Start** (3 events/s, both toggles on) | Rows start arriving about two seconds later; the counters climb. New rows flash briefly. |
| 0:30 | The feed | Seven formats in one schema: FortiGate key=value, PAN-OS CSV, Suricata and Zeek JSON, Cisco ASA and pfSense syslog, Squid access log. Each one becomes, for example, *Network Activity · source → destination · Allowed*. |
| 0:55 | *Parsing, step by step* | **Received**: the exact bytes and their SHA-256, archived before parsing. **Recognised**: the format, the fingerprint and the spec that matched. **Normalized**: the OCSF class and fields. **Field lineage**: every OCSF field next to the source field it came from. |
| 1:25 | Turn on **Pause**; pick an *Unrecognised* event from the list | A source with no parser yet (the fictional *Blackbox Gateway*). Nothing is dropped: the event is kept as an OCSF Base Event and grouped by its fingerprint. |
| 1:45 | *Unknown sources & onboarding* page | The same fingerprint as a cluster, with its count growing. `ulpf onboard` drafts a spec from it, and a named person approves it before it goes live. |
| 2:05 | Back to *Live feed*; pick a malformed line | Broken input (truncated CEF, invalid JSON, binary bytes, whitespace-only lines) is kept and flagged too, with its detected format (e.g. `cef_invalid`). |
| 2:25 | *Event explorer*: select any event, tab *Original bytes* | The exact bytes received, their SHA-256 matching the archive, and a Merkle inclusion proof marked VERIFIED. |
| 2:50 | *Live feed*: press **Stop** | Optional: show in a terminal that every event arrived (below). |

## After recording

- Press **Stop**, or let it end: the traffic stops by itself after 15 minutes.
- Prove that every event arrived (sent = archived = normalized = indexed):

  ```bash
  cat runtime/tmp/demo-main.ndjson runtime/tmp/demo-malformed.ndjson > /tmp/demo-sendlog.ndjson
  .venv/bin/ulpf account --sendlog /tmp/demo-sendlog.ndjson
  ```

  On 10 Oct 2026 a demo session sent 861 events and accounting reported
  `PASS`: 861 received by Vector, `sent_not_archived 0`, and archive,
  normalized store and index equal (29,897 events), no duplicates.
- Leave demo mode (the UI restarts without the controls):

  ```bash
  make demo-stop
  ```

## What the demo traffic is

- **SYNTHETIC TEST DATA** from `ulpf gen`: documented vendor formats with
  private and documentation-range addresses, sent over UDP to the normal
  syslog listener, so it takes exactly the path real logs take.
- The mix: the seven supported vendors in turn, plus about one event in eight
  from the unknown *Blackbox* source, plus malformed lines at 1/20 of the
  rate. Both extras can be switched off before Start.
- Disk: about 6 KB per event across archive, normalized files and index;
  15 minutes at 3 events/s is about 2,700 events, roughly 16 MB.
- Demo mode exists only when the UI is started with `ULPF_DEMO=1`. A normal
  deployment shows the Live feed page without any controls.
- Implementation: `ulpf/demo.py` (starts and stops the generators; state in
  `runtime/run/demo.json`), the Live feed page in `ulpf/ui/app.py`, styling in
  `ulpf/ui/theme.py`.
