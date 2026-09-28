# SentinelFlow

[![CI](https://github.com/karkiram05/sentinelflow/actions/workflows/ci.yml/badge.svg)](https://github.com/karkiram05/sentinelflow/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](backend/requirements.txt)

A network/IoT threat-monitoring backend that ingests NSL-KDD-style
engineered connection records, runs them through a rule + Isolation Forest
detection engine, maps hits to MITRE ATT&CK, and scores risk, with a REST
API, a live dashboard, and a real held-out evaluation against labeled
attack data (not a self-generated traffic demo). See "A note on the input
format" in `docs/results.md` for exactly what `POST /events` expects and
why a real deployment would need an adapter in front of it.

```
NSL-KDD-style event → POST /events → [rules + Isolation Forest] → MITRE mapping
                                          → risk scoring → alerts → dashboard
```

## Why this exists

Informed by my security automation internship at NorthQ, where I built
anomaly detection (Isolation Forest plus rule-based thresholds) over
production telemetry from 2,244 IoT devices (31M+ feature rows), and by my
cybersecurity MSc. Rather than another
notebook classifying a public dataset, this is a small working system: an
API, a database, tests, CI with security scanning, and (the part most
portfolio projects skip) an honest report of what the detection engine
actually catches and misses. See `docs/results.md`.

## What's here (and what isn't, on purpose)

| | |
|---|---|
| ✅ | FastAPI REST backend (`/events`, `/alerts`, `/devices`, `/statistics`) |
| ✅ | Rule engine: explainable, auditable thresholds (`backend/app/detection/rules.py`) |
| ✅ | Isolation Forest anomaly detector, fit unsupervised on real traffic features |
| ✅ | MITRE ATT&CK mapping for every detection type that has one |
| ✅ | Risk scoring (0-100) and severity bands: rule hits drive severity, ML corroboration raises it, ML-only outliers are capped at MEDIUM |
| ✅ | PostgreSQL (Docker) / SQLite (local dev) via SQLAlchemy |
| ✅ | Live dashboard: single-file HTML, polls the API |
| ✅ | Evaluated against a real labeled dataset (NSL-KDD), with a full per-attack-category breakdown, not a headline number |
| ✅ | 43 pytest tests covering rules, ML, risk scoring, and the API |
| ✅ | GitHub Actions CI: tests + Bandit + pip-audit + Trivy scan of the built Docker image; Dependabot for dependency updates |
| ✅ | Docker Compose (API + Postgres) |
| ✅ | Threat model (STRIDE) of the application itself, not just the traffic it watches |
| ⛔ | Live packet/PCAP capture (Zeek/Suricata), threat-intel enrichment, Grafana/Prometheus, cloud deployment. Cut from this version deliberately rather than left half-built; see the Roadmap in `docs/architecture.md` |

## Try it with zero local setup (GitHub Codespaces)

This repo has a `.devcontainer/` config. Click **Code → Codespaces → Create
codespace on main** on GitHub, or open the repo in a devcontainer-compatible
editor. It automatically creates a venv, installs dependencies, and seeds
the database with the real evaluation dataset -- no manual steps. Once it's
done, run `cd backend && uvicorn app.main:app --host 0.0.0.0 --reload` and
open the forwarded port-8000 preview.

## Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt

# Ingest the real labeled sample dataset and fit the detector
python scripts/load_dataset.py --reset-db

# Run the API (serves the dashboard at /)
cd backend && uvicorn app.main:app --reload
```

Or, equivalently, run `./setup.sh` from the repo root -- it does exactly
the steps above (this is also what the Codespaces devcontainer runs
automatically).

Open `http://localhost:8000` for the dashboard, or `http://localhost:8000/docs`
for interactive API docs.

### Or with Docker

```bash
docker compose up --build
```

This starts the API against Postgres with an empty database. POST to
`/events` (see `docs/api.md`), or seed it with the real evaluation dataset
from the host:

```bash
DATABASE_URL=postgresql://sentinelflow:sentinelflow@localhost:5432/sentinelflow \
  python scripts/load_dataset.py --reset-db
```

### Run the tests

```bash
pip install -r backend/requirements-dev.txt
cd backend && python -m pytest tests/ -v
```

## Detection results

On a held-out test split of real labeled NSL-KDD data (the Isolation Forest
never sees it during fitting), SentinelFlow catches **46.9% of attacks**
(229 of 488) and flags **9 of 24 normal flows (37.5% false positive rate)**.
Precision is 96.2%, but the split is 95% attack traffic, so alerting on
every flow would already score 95.3%: precision is not a meaningful headline
here. Detection is strong on scans and single-flow exploits and near zero
on slow, multi-flow attacks that need cross-flow correlation.
**[docs/results.md](docs/results.md)** has the per-attack-type table, the
severity distribution, and what a real deployment's input format would need
to look like.

## Documentation

- [Architecture](docs/architecture.md): design decisions, module map, limitations, roadmap
- [Threat model](docs/threat-model.md): STRIDE analysis of SentinelFlow itself
- [API reference](docs/api.md)
- [Detection results](docs/results.md)

## Tech stack

Python, FastAPI, SQLAlchemy, PostgreSQL/SQLite, scikit-learn (Isolation
Forest), pandas, pytest, Docker, GitHub Actions, Bandit, pip-audit,
Dependabot.

## License

MIT, see [LICENSE](LICENSE).
