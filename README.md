# SentinelFlow

A network/IoT threat-monitoring backend that ingests NSL-KDD-style
engineered connection records, runs them through a rule + Isolation Forest
detection engine, maps hits to MITRE ATT&CK, and scores risk — with a REST
API, a live dashboard, and a real held-out evaluation against labeled
attack data (not a self-generated traffic demo). See "A note on the input
format" in `docs/results.md` for exactly what `POST /events` expects and
why a real deployment would need an adapter in front of it.

```
NSL-KDD-style event → POST /events → [rules + Isolation Forest] → MITRE mapping
                                          → risk scoring → alerts → dashboard
```

## Why this exists

Built on the intersection of two years running production IoT device
telemetry at NorthQ (2,244 devices, 31M+ feature rows, anomaly detection
with rule-based thresholds) and a cybersecurity MSc. Rather than another
notebook classifying a public dataset, this is a small working system: an
API, a database, tests, CI with security scanning, and — the part most
portfolio projects skip — an honest report of what the detection engine
actually catches and misses. See `docs/results.md`.

## What's here (and what isn't, on purpose)

| | |
|---|---|
| ✅ | FastAPI REST backend (`/events`, `/alerts`, `/devices`, `/statistics`) |
| ✅ | Rule engine — explainable, auditable thresholds (`backend/app/detection/rules.py`) |
| ✅ | Isolation Forest anomaly detector, fit unsupervised on real traffic features |
| ✅ | MITRE ATT&CK mapping for every detection type that has one |
| ✅ | Risk scoring (0-100) blending rule + ML confidence into a severity band |
| ✅ | PostgreSQL (Docker) / SQLite (local dev) via SQLAlchemy |
| ✅ | Live dashboard — single-file HTML, polls the API |
| ✅ | Evaluated against a real labeled dataset (NSL-KDD), with a full per-attack-category breakdown, not a headline number |
| ✅ | 33 pytest tests covering rules, ML, risk scoring, and the API |
| ✅ | GitHub Actions CI: tests + Bandit + pip-audit; Dependabot for dependency updates |
| ✅ | Docker Compose (API + Postgres) |
| ✅ | Threat model (STRIDE) of the application itself, not just the traffic it watches |
| ⛔ | Live packet/PCAP capture (Zeek/Suricata), threat-intel enrichment, Grafana/Prometheus, cloud deployment — cut from this version deliberately rather than left half-built; see the Roadmap in `docs/architecture.md` |

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

This starts the API against Postgres with an empty database — POST to
`/events` (see `docs/api.md`) or point `DATABASE_URL` at the same Postgres
instance and run `scripts/load_dataset.py` from the host to seed it with
the real evaluation dataset.

### Run the tests

```bash
cd backend && python -m pytest tests/ -v
```

## Detection results

Precision **96.2%**, recall **46.9%** on a held-out test split of a real
labeled dataset (the Isolation Forest never sees the test split during
fitting) — plus a full table of exactly which attack types are caught and
which aren't, why the precision number is sample-dependent and not a
production estimate, and what a real deployment's input format would need
to look like. See **[docs/results.md](docs/results.md)**.

## Documentation

- [Architecture](docs/architecture.md) — design decisions, module map, limitations, roadmap
- [Threat model](docs/threat-model.md) — STRIDE analysis of SentinelFlow itself
- [API reference](docs/api.md)
- [Detection results](docs/results.md)

## Tech stack

Python, FastAPI, SQLAlchemy, PostgreSQL/SQLite, scikit-learn (Isolation
Forest), pandas, pytest, Docker, GitHub Actions, Bandit, pip-audit,
Dependabot.

## License

MIT — see [LICENSE](LICENSE).
