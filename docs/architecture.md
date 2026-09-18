# Architecture

## Overview

```
                     ┌────────────────────┐
Flow telemetry  ───▶ │  POST /events       │
(NSL-KDD ingest,     │  (FastAPI)          │
 or any client)      └─────────┬──────────┘
                                │
                                ▼
                      ┌───────────────────┐
                      │ Detection engine    │
                      │  ├─ rule engine     │  explainable, threshold-based
                      │  └─ Isolation Forest│  unsupervised statistical outlier
                      └─────────┬──────────┘
                                │ (rule and/or ML hit)
                                ▼
                      ┌───────────────────┐
                      │ MITRE ATT&CK map    │  detection name -> technique ID
                      │ Risk scoring        │  confidence -> 0-100 + severity
                      └─────────┬──────────┘
                                │
                                ▼
                      ┌───────────────────┐
                      │ Postgres / SQLite   │  events, alerts, devices
                      └─────────┬──────────┘
                                │
                    ┌───────────┴────────────┐
                    ▼                        ▼
          GET /alerts /statistics   Dashboard (static HTML,
          /devices /events          polls the API every 5s)
```

## Why this shape

**One detection path, two techniques feeding it.** Rules and the Isolation
Forest both run against the same feature dict and both feed the same
`DetectionResult` (`app/detection/engine.py`). Neither is a separate
pipeline bolted on afterwards -- that's what makes `detection_source` in
the Alert model meaningful ("rule", "ml", or "rule+ml": both agreeing on
the same event raises its risk score, see `risk.py`).

**Flow-level, not packet-level.** SentinelFlow ingests aggregated
connection/flow records (the same shape Zeek's `conn.log` or a NetFlow
collector produces), not raw packets. This keeps the ingestion API simple
and matches what most real network monitoring stacks actually feed a
detection layer.

**Rules are explainable on purpose.** Every rule in `rules.py` is a
threshold a person can read and audit, with a plain-English rationale
attached to each match. This is deliberate: a SOC alert with no reasoning
attached is close to useless. The ML side exists specifically to catch
patterns the hand-written rules don't have a threshold for -- it's a
complement, not a replacement.

**The Isolation Forest is unsupervised, always.** It's fit only on the
numeric feature vectors, never on the ground-truth attack/normal label,
even during the evaluation run in `scripts/load_dataset.py`. That's what
makes it usable against live traffic where you don't have labels.

## Module map

| Path | Responsibility |
|---|---|
| `backend/app/models.py` | SQLAlchemy models: `Event`, `Alert`, `Device` |
| `backend/app/detection/rules.py` | Threshold-based rule detectors |
| `backend/app/detection/ml.py` | Isolation Forest wrapper |
| `backend/app/detection/engine.py` | Combines rules + ML into one `DetectionResult` |
| `backend/app/detection/mitre.py` | Detection name -> MITRE ATT&CK technique |
| `backend/app/detection/risk.py` | Confidence blending, 0-100 risk score, severity band |
| `backend/app/ingest.py` | Shared path: event -> DB rows -> (maybe) alert. Used by both the API and the offline evaluation script, so they can't drift apart |
| `backend/app/routers/*.py` | `/events`, `/alerts`, `/devices`, `/statistics` |
| `scripts/load_dataset.py` | Ingests the real labeled sample, fits the ML model, and reports actual precision/recall (see `docs/results.md`) |
| `frontend/index.html` | Single-file dashboard, polls the API |

## Known limitations (honest, not hidden)

- **Per-flow detection only.** The rule engine looks at one flow at a time.
  It cannot catch attacks that only become visible when you correlate many
  flows over time from the same source (e.g. a slow, spread-out credential
  guessing campaign where each individual attempt looks unremarkable). This
  is the single biggest reason recall isn't higher -- see `docs/results.md`
  for exactly which attack categories this affects.
- **The Isolation Forest model lives in process memory**, refit on
  ingestion, not persisted to disk between restarts. A production version
  would persist and version the fitted model.
- **No live packet/flow capture.** SentinelFlow ingests already-extracted
  flow records; it doesn't sniff a NIC or parse PCAP itself. Wiring in Zeek
  or Suricata as a flow source is a natural next step (see below) but was
  deliberately left out of this version rather than half-implemented.
- **Demonstration IPs.** NSL-KDD (like most public IDS datasets) does not
  include real source/destination IPs. `scripts/load_dataset.py` assigns
  them round-robin from a small private-range pool purely so the
  device-aggregation feature has something to group by. This is disclosed
  in that script's docstring, not left implicit.
- **Categorical features (protocol/service/flag) aren't fed to the ML
  model**, only to the rules. Encoding them for the Isolation Forest too is
  a reasonable next step.

## Roadmap (explicitly not built in this version)

Cut from the original scope on purpose, rather than half-built:

- **A real telemetry adapter layer.** `POST /events` currently expects a
  `features` dict shaped like NSL-KDD's engineered connection fields
  (`root_shell`, `num_failed_logins`, `hot`, and so on) because that's what
  the rules and the held-out evaluation are built and tuned against (see
  "A note on the input format" in `docs/results.md`). A production
  deployment needs a translation layer in front of this that derives those
  same engineered fields from whatever the real source actually is -- a
  Zeek `conn.log`, NetFlow/IPFIX, or host/auth logs -- each of which would
  need its own adapter module (`collectors/zeek/`, `collectors/netflow/`,
  etc.) mapping raw fields onto the common feature schema this project's
  rules already key on. This is the single biggest gap between "detection
  logic that works against a labeled dataset" and "detection logic
  deployed against real traffic," and it's called out explicitly rather
  than left implied by the README's original "flow telemetry" framing.
- Live capture via Zeek or Suricata as a flow source
- Threat intelligence enrichment (VirusTotal / AbuseIPDB IP reputation)
- Time-windowed / cross-flow correlation for slow-and-low attacks
- Prometheus + Grafana for operational metrics (distinct from the security
  dashboard, which is about detections, not infra health)
- Model persistence and versioning
- Cloud deployment
- A fuller risk model that also weighs asset criticality, internet
  exposure, and threat intelligence, not just detection confidence and
  repeat-offender activity (see `backend/app/detection/risk.py`'s
  docstring for what the current model does and doesn't account for)
