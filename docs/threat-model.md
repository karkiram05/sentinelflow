# Threat Model

STRIDE analysis of SentinelFlow itself -- the application, not the traffic
it monitors. A monitoring tool that is itself insecure is a liability, so
this is treated as seriously as the detection logic.

## Assets

- Ingested event data (may include internal IP addressing / topology info)
- Alert data (reveals what an attacker already got past, if leaked)
- The Isolation Forest model's fitted parameters (low sensitivity, but
  poisoning it would degrade detection quality)
- API availability (a DoS'd monitoring system is a blind SOC)

## Trust boundaries

```
[Untrusted network / IoT devices]
          │  (flow telemetry, attacker-influenced values)
          ▼
[POST /events -- Pydantic validation] ── trust boundary #1
          ▼
[Detection engine -- rules + ML]
          ▼
[Database]  ── trust boundary #2 (SQL injection surface)
          ▼
[GET endpoints] ── trust boundary #3 (who can read alerts/events)
          ▼
[Dashboard -- browser rendering alert fields] ── trust boundary #4 (XSS surface)
```

## STRIDE

| Threat | Applies where | Mitigation in this codebase | Residual risk |
|---|---|---|---|
| **Spoofing** | `source_ip` / `destination_ip` in `POST /events` are client-supplied strings, not cryptographically verified | Out of scope for a telemetry ingestion API (the same is true of NetFlow/Zeek data by nature) -- SentinelFlow documents this as an assumption: ingestion must sit behind a trusted collector, not accept telemetry directly from the internet | If deployed directly internet-facing, an attacker could inject fabricated source IPs to pollute device risk scores |
| **Tampering** | Alert `status` field (OPEN/ACKNOWLEDGED/CLOSED) | `PATCH /alerts/{id}` validates status against an allow-list (`VALID_STATUSES` in `routers/alerts.py`), rejecting anything else with 400 | No authentication yet (see Roadmap) -- anyone who can reach the API can close alerts |
| **Repudiation** | No action currently logged with an actor identity | `created_at` timestamps exist on events/alerts, but there is no audit log of *who* changed an alert's status | Cannot currently prove who acknowledged/closed an alert. Flagged as a gap, not silently ignored |
| **Information Disclosure** | `GET /alerts`, `GET /events`, `GET /devices` return full detail, unauthenticated in this MVP | SQLAlchemy ORM + parameterized queries throughout (no raw string-built SQL anywhere in `routers/`), so SQL injection is not a live vector. Field values are escaped by the browser's `textContent`/template rendering, not raw `innerHTML`, on the dashboard | **No authentication/authorization is implemented in this MVP.** This is the single most important gap before any real deployment -- see Roadmap |
| **Denial of Service** | `POST /events` has no rate limiting | FastAPI + Uvicorn defaults only | A flood of POST requests could exhaust DB connections; no rate limiting or backpressure implemented |
| **Elevation of Privilege** | No user roles exist yet -- everyone who can reach the API has full read/write | N/A | Directly follows from the missing auth layer above |

## Input validation

All API input is validated through Pydantic schemas (`schemas.py`) before
it reaches the database or the detection engine -- unexpected types are
rejected with a 422 before any code runs on them. The `features` dict
accepts arbitrary keys (by design, so new detection features can be added
without an API contract change), but every value the rule engine and ML
model actually read is coerced through `_get()` / `numeric_vector()` with
safe numeric defaults, so a malformed or missing field degrades to "0",
not a crash.

## Dependency and code-level controls already in CI

- **Bandit** (`ci.yml` `security` job) -- static analysis for common Python
  security anti-patterns (hardcoded secrets, `eval`, insecure deserialization,
  etc.) on every push
- **pip-audit** -- flags dependencies with known CVEs
- **Dependabot** (`.github/dependabot.yml`) -- weekly PRs for pip, Docker
  base image, and GitHub Actions updates

## Before this goes anywhere near production

1. Authentication + authorization on every endpoint (this is the load-bearing
   gap -- everything else in this document assumes it gets fixed)
2. Rate limiting on `POST /events`
3. An audit log with actor identity for alert status changes
4. TLS termination in front of the API (not handled by this repo -- it's a
   deployment concern, documented here so it isn't forgotten)
5. Secrets (DB credentials) out of `docker-compose.yml` and into a secrets
   manager for anything beyond local dev
