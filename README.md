# ◎ SentryWatch

**Self-hosted uptime and security monitoring.** Point it at your sites and APIs; it checks them on a schedule, measures response times, watches TLS expiry, grades your security headers, opens incidents when things break, and fires a webhook when something goes down.

Runs locally or in Docker. One command to start.

![tests](https://img.shields.io/badge/tests-26%20passing-brightgreen) ![docker](https://img.shields.io/badge/docker-ready-blue) ![license](https://img.shields.io/badge/license-MIT-green)

## What it actually does

- **Uptime checks** — per-target interval, expected status code, hard timeout, response-time measurement
- **Incident lifecycle** — first failure opens an incident; recovery auto-resolves it; no duplicate incidents while down
- **Security grading** — analyses HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, flags `X-Powered-By` stack leaks, and grades A–F
- **TLS monitoring** — certificate expiry in days (warns under 14, fails when expired)
- **Webhook alerts** — POSTs JSON on the down transition and on recovery
- **Dashboard** — uptime %, average latency, per-check history sparkline, incident log, live findings
- **Docker ready** — compose file, healthcheck, persistent volume

## Quick start

```bash
npm install
npm start
# → http://localhost:4700
```

Add a target (name + URL), and it starts monitoring immediately.

### Docker

```bash
docker compose up -d --build
# → http://localhost:4700   (data persisted in the sentrywatch-data volume)
```

## Run the test suite

```bash
npm run selftest
```

26 end-to-end assertions against **real HTTP servers** it spins up:

- healthy target → up, response time recorded, security grade **A**
- bare target → up, but grade drops and missing CSP / stack leak are reported
- failing target → down, incident opened once, second failure does not duplicate it
- recovery → incident auto-resolved and timestamped
- uptime maths from the check history
- webhook delivered on the down transition with the real error
- scheduler fires checks on its own interval
- validation: bad URL, missing name, unknown target, cascade delete

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `PORT` | `4700` | HTTP port |
| `SW_DATA_DIR` | `./data` | SQLite location |
| `SW_TIMEOUT_MS` | `15000` | Per-check timeout |
| `SW_TICK_MS` | `5000` | Scheduler tick |
| `SW_DISABLE_SCHEDULER` | — | Set to `1` to disable background checks |

## Architecture

```
targets ──► scheduler (tick, per-target interval)
                 │
                 ▼
          checker.performCheck()
            ├─ fetch + timeout + response time
            ├─ expected-status evaluation
            ├─ header analysis → grade A–F
            ├─ TLS expiry (tls.connect)
            ▼
        checks table ──► uptime %, avg ms, sparkline
            │
            ├─ fail  → open incident → webhook "down"
            └─ ok    → resolve incident → webhook "recovered"
```

## API

| Method | Route | Purpose |
|---|---|---|
| GET | `/api/overview` | dashboard payload (targets + totals + incidents) |
| GET/POST | `/api/targets` | list / create targets |
| PATCH/DELETE | `/api/targets/:id` | edit / remove |
| POST | `/api/targets/:id/check` | run a check now |
| GET | `/api/targets/:id/checks` | recent check history |
| GET | `/api/incidents` | incident log |

## Project structure

```
server.js           Express API + dashboard
src/checker.js      checks, header grading, TLS, incidents, webhooks
src/scheduler.js    interval-based background checks
src/db.js           SQLite: targets, checks, incidents
public/             dashboard UI (vanilla JS, no build step)
tests/selftest.js   26-check suite with real test servers
Dockerfile / docker-compose.yml
```

MIT © Ntshuxeko Sambo
