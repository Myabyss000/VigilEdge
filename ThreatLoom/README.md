# ThreatLoom — SOC Platform for Custom Firewalls

A full-featured **Security Operations Center** platform built in Python, designed specifically for custom firewalls and Web Application Firewalls (WAF).

## Features

- **Multi-format log ingestion** — JSON, syslog (RFC 3164/5424), raw text
- **Three-layer detection engine** — signature rules, behavioral analysis, cross-log correlation
- **MITRE ATT&CK mapping** — 14 attack types mapped to tactics & techniques
- **Automated response (SOAR)** — IP blocking, rate limiting, temp bans via playbooks
- **Incident management** — full triage workflow with notes & timeline
- **Real-time dashboard** — live alert feed, severity charts, geo distribution, system health
- **WebSocket streaming** — real-time alerts, logs, incidents, metrics channels
- **RBAC** — Admin, SOC Analyst, Viewer roles with JWT authentication
- **Tiered storage** — hot/warm/cold retention with automatic lifecycle management
- **Audit logging** — all write operations tracked

## Quick Start

```bash
# Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Configure
copy .env.example .env

# Launch
uvicorn main:app --host 0.0.0.0 --port 8443 --reload
```

Open http://localhost:8443.

Authentication flow:

- If no admin exists yet, the login page shows a first-run bootstrap form.
- Create the first admin account there, then sign in with that account.
- If `BOOTSTRAP_ADMIN_TOKEN` is configured in `.env`, the bootstrap form also requires that token.

Machine-to-machine ingest is no longer anonymous. Send logs with a bearer token configured through `INGEST_SERVICE_TOKENS`, or use an authorized JWT user.

## Project Structure

```
ThreatLoom/
├── main.py                         # FastAPI entry point
├── threatloom/
│   ├── config.py                   # Settings (from .env)
│   ├── database.py                 # Async SQLAlchemy engine
│   ├── models/                     # ORM models (logs, alerts, incidents, ...)
│   ├── schemas/                    # Pydantic request/response schemas
│   ├── auth/                       # JWT, RBAC, audit logging
│   ├── ingestion/                  # Log parsers & normalization
│   ├── detection/                  # Rules, behavioral, correlation engines
│   ├── response/                   # Automated response & SOAR playbooks
│   ├── storage/                    # Retention lifecycle manager
│   ├── websocket/                  # Real-time WebSocket streaming
│   ├── api/v1/                     # REST API routes
│   └── utils/                      # GeoIP, helpers
├── dashboard/
│   ├── templates/                  # Jinja2 HTML templates
│   └── static/                     # CSS & JavaScript
├── rules/                          # YAML detection rules
├── playbooks/                      # YAML SOAR playbooks
├── tests/                          # pytest test suite
└── docs/
    └── ARCHITECTURE.md             # Full architecture documentation
```

## API Endpoints

| Group | Base Path | Description |
|-------|-----------|-------------|
| Logs | `/api/v1/logs/` | Ingest & query firewall logs |
| Alerts | `/api/v1/alerts/` | Alert CRUD, stats, acknowledge |
| Incidents | `/api/v1/incidents/` | Incident lifecycle, notes, timeline |
| Responses | `/api/v1/responses/` | Automated response management |
| Users | `/api/v1/users/` | Authentication & user management |
| Playbooks | `/api/v1/playbooks/` | SOAR playbook CRUD & execution |
| Dashboard | `/` | Server-rendered SOC dashboard |
| WebSocket | `/ws/{channel}` | Real-time event streaming |

## Integrating with Your Firewall

```python
import httpx

async def send_log(log: dict, token: str):
    async with httpx.AsyncClient() as c:
        await c.post(
            "http://localhost:8443/api/v1/logs/ingest/json",
            json=log,
            headers={"Authorization": f"Bearer {token}"}
        )
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full integration guide.

## Tech Stack

FastAPI · SQLAlchemy (async) · Pydantic · JWT · Chart.js · Tailwind CSS · WebSockets · psutil · GeoIP2

## Testing

```bash
pytest tests/ -v
```

## License

Internal use — adapt as needed.
