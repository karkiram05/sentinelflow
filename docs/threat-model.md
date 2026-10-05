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
| **Spoofing (of the writer)** | Who is allowed to submit events or change alerts | `POST /events` and `PATCH /alerts/{id}` require an `X-API-Key` header, compared in constant time (`hmac.compare_digest`, `app/security.py`). With no key configured, writes return 503 (fail closed) | One shared key, not per-user identity: anyone holding it can write, and a leaked key has to be rotated by hand |
| **Tampering** | Alert `status` field (OPEN/ACKNOWLEDGED/CLOSED) | `PATCH /alerts/{id}` needs the API key and validates status against an allow-list (`VALID_STATUSES` in `routers/alerts.py`), rejecting anything else with 400 | Any holder of the shared key can close any alert |
| **Repudiation** | No action currently logged with an actor identity | `created_at` timestamps exist on events/alerts, but there is no audit log of *who* changed an alert's status | Cannot currently prove who acknowledged/closed an alert. Flagged as a gap, not silently ignored |
| **Information Disclosure** | `GET /alerts`, `GET /events`, `GET /devices` return full detail without a key, so the read-only dashboard works | SQLAlchemy ORM + parameterized queries throughout (no raw string-built SQL anywhere in `routers/`), so SQL injection is not a live vector. Docker Compose binds the API to 127.0.0.1 only. Data responses send `Cache-Control: no-store` | **Reads are unauthenticated by design.** Anyone who can reach the port can read alerts, so it must stay on loopback or behind an authenticating reverse proxy |
| **Tampering / Stored XSS via `source_ip`/`destination_ip`** | The dashboard (`frontend/index.html`) builds table rows with `innerHTML` from alert/event fields returned by the API, including `source_ip`/`destination_ip`, which originate from client-supplied `POST /events` payloads | Two layers: (1) `schemas.py` validates both fields as real IPv4/IPv6 addresses via `ipaddress.ip_address()`, rejecting anything else with 422 before it reaches the database; (2) the frontend's `esc()` helper HTML-escapes every interpolated value before insertion, as defense in depth for any future field added without equivalent backend validation | Both layers assume every new field flowing into the dashboard gets the same treatment -- a field added later without validation or escaping would reopen this |
| **Denial of Service** | Request floods, oversized bodies, huge `features` dicts | Per-client sliding-window rate limits (120 writes / 300 reads per minute, 429 + `Retry-After`); 16 KB body cap enforced on the bytes actually received, not just Content-Length (413); `features` capped at 64 scalar keys; pagination bounded (`limit` 1-500, `offset` >= 0) | The limiter is in-memory and per process: several workers or replicas each count separately, and an attacker with many source addresses is not slowed. A reverse proxy or shared store is needed for a global limit |
| **Clickjacking / injected script in the dashboard** | The dashboard page itself | Strict Content-Security-Policy (`script-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`); the dashboard's JavaScript moved out of an inline `<script>` into `frontend/app.js` so no `'unsafe-inline'` is needed for scripts; `X-Frame-Options: DENY`; `nosniff` | `/docs` and `/redoc` need jsDelivr and inline script for Swagger UI/ReDoc, so they get a separate, looser policy |
| **Elevation of Privilege** | No user roles: every key holder has full write access | Writes are at least gated behind the key; the container runs as a non-root user with a read-only root filesystem, all Linux capabilities dropped and `no-new-privileges` | No role model (analyst vs. ingest-only collector) yet |

## Input validation

All API input is validated through Pydantic schemas (`schemas.py`) before
it reaches the database or the detection engine -- unexpected types are
rejected with a 422 before any code runs on them. `source_ip` and
`destination_ip` specifically are validated as real IPv4/IPv6 addresses
(not just non-empty strings), since they flow through to the dashboard's
rendering (see the Information Disclosure row above). The `features` dict
accepts arbitrary keys (by design, so new detection features can be added
without an API contract change), but every value the rule engine and ML
model actually read is coerced through `_get()` / `numeric_vector()` with
safe numeric defaults, so a malformed or missing field degrades to "0",
not a crash.

## Dependency and code-level controls already in CI

- **Bandit** (`ci.yml` `security` job) -- static analysis for common Python
  security anti-patterns (hardcoded secrets, `eval`, insecure deserialization,
  etc.) on every push
- **pip-audit** -- fails the build on any dependency with a known CVE that
  has an available fix (see `ci.yml`'s comment for the exception policy)
- **Dependabot** (`.github/dependabot.yml`) -- weekly PRs for pip, Docker
  base image, and GitHub Actions updates
- **GitHub Actions pinned to commit SHA** (not mutable tags), workflow
  permissions defaulted to `contents: read`, and `persist-credentials:
  false` on checkout -- the same supply-chain hardening this project's
  sibling repo, TrustGraph, statically detects when it's missing elsewhere

## Secrets

No credential is stored in the repository. `docker-compose.yml` reads
`POSTGRES_PASSWORD` and `SENTINELFLOW_API_KEY` from an untracked `.env`
(template: `.env.example`) and refuses to start if either is missing, so
there is no guessable default to forget about. Generate both with
`python -c "import secrets; print(secrets.token_urlsafe(32))"`.

## Before this goes anywhere near production

Done in this version: API key on writes (fail closed), rate limiting, body
and field size limits, security headers with a strict CSP, secrets out of
the compose file, a hardened container. Still open:

1. Per-user authentication and roles (an ingest-only key for collectors,
   analyst accounts for alert triage), and authentication on reads
2. An audit log with actor identity for alert status changes
3. TLS termination in front of the API (a deployment concern, not handled
   by this repo, recorded here so it isn't forgotten)
4. A shared rate-limit store (or the reverse proxy) once there is more than
   one worker
5. A secrets manager instead of a `.env` file for anything beyond local dev
