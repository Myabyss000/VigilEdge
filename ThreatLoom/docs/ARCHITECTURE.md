# ThreatLoom — Architecture Documentation

## Overview

ThreatLoom is a full-featured **Security Operations Center (SOC)** platform designed specifically for custom Python firewalls and Web Application Firewalls (WAF). It provides real-time log ingestion, multi-layer threat detection, automated incident response, and an analyst-grade dashboard — all in a single deployable Python application.

---

## System Architecture

```
                    ┌─────────────────────────────────────────────────┐
                    │               ThreatLoom SOC                    │
                    │                                                 │
  Firewall Logs ──▶ │  ┌──────────┐  ┌───────────┐  ┌────────────┐  │
  (JSON/Syslog/    │  │Ingestion │─▶│ Detection │─▶│  Response   │  │
   Raw Text)       │  │ Engine   │  │  Engine   │  │  Engine     │  │
                    │  └──────────┘  └───────────┘  └────────────┘  │
                    │       │              │              │          │
                    │       ▼              ▼              ▼          │
                    │  ┌─────────────────────────────────────────┐  │
                    │  │            SQLite / PostgreSQL           │  │
                    │  │  (logs, alerts, incidents, responses)    │  │
                    │  └─────────────────────────────────────────┘  │
                    │       │              │              │          │
                    │       ▼              ▼              ▼          │
                    │  ┌──────────┐  ┌───────────┐  ┌────────────┐  │
                    │  │WebSocket │  │ REST API  │  │ Dashboard  │  │
                    │  │ (live)   │  │  (v1)     │  │ (Jinja2)   │  │
                    │  └──────────┘  └───────────┘  └────────────┘  │
                    └─────────────────────────────────────────────────┘
```

---

## Component Breakdown

### 1. Ingestion Engine (`threatloom/ingestion/`)

| Component | Purpose |
|-----------|---------|
| `engine.py` | Orchestrates parse → normalize → enrich → store pipeline |
| `parsers/json_parser.py` | Parses structured JSON firewall logs (40+ field aliases) |
| `parsers/syslog_parser.py` | Parses RFC 3164/5424 syslog with embedded KV extraction |
| `parsers/raw_parser.py` | Regex-based extraction from unstructured text logs |
| `normalizer.py` | Validates, truncates, clamps fields to canonical form |

**Ingestion flow:**
1. API receives log(s) via POST `/api/v1/logs/ingest/{format}`
2. Parser extracts fields into a normalized dict
3. Normalizer validates and constrains values
4. GeoIP resolver enriches with country/city/coordinates
5. MITRE ATT&CK mapper tags `mitre_tactic` and `mitre_technique`
6. Record stored in `firewall_logs` table
7. WebSocket broadcast to `logs` channel

### 2. Detection Engine (`threatloom/detection/`)

Three-layer detection running as an async background task (10-second scan cycle):

#### Layer 1: Rule-Based (`detection/rules/`)
- **Signature Detection** — Field-value matching with operators: `equals`, `contains`, `regex`, `in`, `gt`, `lt`, negation
- **Threshold Detection** — Count-based alerting (e.g., 10+ blocked requests from one IP in 5 minutes)
- Rules loaded from `rules/default_rules.yaml` (hot-reloadable)

#### Layer 2: Behavioral (`detection/behavioral/`)
- **Rate Analyzer** — Requests/min, blocked/min, burst detection per IP
- **Geo Analyzer** — High-risk country traffic, multi-country sessions, new country for known IPs
- **Pattern Analyzer** — Scan path detection, path diversity scoring, suspicious User-Agent matching

#### Layer 3: Correlation (`detection/correlation/`)
- **IP Correlator** — Multi-vector attacks from single IP, coordinated multi-IP targeting
- **Session Correlator** — Multi-attack sessions, severity escalation chains
- **Time Window Correlator** — Attack burst detection, recon→exploit chains

All detections are deduplicated (30-minute window per unique source+type+IP combination) before generating alerts.

### 3. MITRE ATT&CK Integration (`detection/mitre.py`)

Static mapping of 14 attack types to MITRE ATT&CK framework:

| Attack Type | Tactic | Technique |
|-------------|--------|-----------|
| SQLI | Initial Access | T1190 |
| XSS | Initial Access | T1189 |
| RCE | Execution | T1059 |
| LFI | Discovery | T1083 |
| BRUTE_FORCE | Credential Access | T1110 |
| PORT_SCAN | Discovery | T1046 |
| DDOS | Impact | T1498 |
| SSRF | Lateral Movement | T1210 |
| BOT | Reconnaissance | T1595 |
| CSRF | Privilege Escalation | T1185 |
| XXE | Collection | T1213 |
| COMMAND_INJECTION | Execution | T1059 |
| DIRECTORY_TRAVERSAL | Discovery | T1083 |
| CREDENTIAL_STUFFING | Credential Access | T1110 |

### 4. Response Engine (`threatloom/response/`)

| Component | Purpose |
|-----------|---------|
| `engine.py` | Executes, revokes, and expires automated responses |
| `actions.py` | Stub implementations for block_ip, rate_limit, temp_ban (integrate with your firewall API) |
| `playbook_runner.py` | SOAR playbook executor — evaluates trigger conditions and runs action sequences |

**Response actions available:**
- `BLOCK_IP` — Add IP to firewall blocklist
- `RATE_LIMIT` — Throttle requests from IP
- `TEMP_BAN` — Temporary ban with auto-expiry
- `NOTIFY` — Log and/or webhook notifications
- `ESCALATE` — Assign to admin for manual review

### 5. Storage & Retention (`threatloom/storage/`)

Four-tier retention policy running as a daily background task:

| Tier | Age | Description |
|------|-----|-------------|
| HOT | 0–7 days | Full queryable data |
| WARM | 7–30 days | Searchable, lower priority |
| COLD | 30–365 days | Archived, minimal queries |
| PURGE | 365+ days | Permanently deleted |

### 6. Authentication & Authorization (`threatloom/auth/`)

- **JWT HS256** tokens with configurable expiry
- **Three roles:** ADMIN, SOC_ANALYST, VIEWER
- **RBAC guards** as FastAPI dependency injection
- **Audit logging** for all write operations
- **Default admin** account created on first startup

### 7. API Layer (`threatloom/api/v1/`)

| Endpoint Group | Routes | Description |
|----------------|--------|-------------|
| `/api/v1/logs/` | Ingest + query + stats | Log ingestion (JSON/syslog/raw/batch) and search |
| `/api/v1/alerts/` | CRUD + acknowledge + stats | Alert management and triage |
| `/api/v1/incidents/` | CRUD + notes + timeline | Incident lifecycle management |
| `/api/v1/responses/` | Create + revoke + list | Automated response management |
| `/api/v1/users/` | Login + CRUD + password | User management and authentication |
| `/api/v1/playbooks/` | CRUD + run + toggle | SOAR playbook management |
| `/api/v1/dashboard/` | Server-rendered pages | Dashboard HTML views |

### 8. WebSocket Real-Time (`threatloom/websocket/`)

Multi-channel pub/sub WebSocket server:

| Channel | Events |
|---------|--------|
| `alerts` | New alert created, alert updated |
| `logs` | New log ingested |
| `incidents` | Incident created/updated |
| `metrics` | System health metrics |

### 9. Dashboard (`dashboard/`)

Server-rendered Jinja2 templates with:
- **Tailwind CSS** (CDN) for styling
- **Chart.js** for severity distribution and attack type charts
- **Alpine.js** for reactive UI components
- **WebSocket client** for live alert feed

Pages: Dashboard (main), Alerts, Incidents, Logs, Login

---

## Data Model

```
firewall_logs ──────┐
                    │ (alerts reference log IDs)
alerts ─────────────┤
                    │ (incidents aggregate alerts)
incidents ──────────┤
  └─ incident_notes │
                    │ (responses linked to alerts/incidents)
automated_responses ┤
                    │
playbooks ──────────┤
  └─ playbook_executions
                    │
users ──────────────┤
audit_logs ─────────┘
```

---

## Configuration

All settings via environment variables (see `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | ThreatLoom | Application name |
| `DATABASE_URL` | sqlite+aiosqlite:///./threatloom.db | Database connection |
| `SECRET_KEY` | (random) | JWT signing key |
| `JWT_EXPIRY_HOURS` | 24 | Token lifetime |
| `DEFAULT_ADMIN_PASSWORD` | changeme | Initial admin password |
| `GEOIP_DB_PATH` | ./GeoLite2-City.mmdb | MaxMind GeoIP database |
| `RULES_DIR` | ./rules | Detection rules directory |
| `PLAYBOOKS_DIR` | ./playbooks | SOAR playbooks directory |
| `RETENTION_HOT_DAYS` | 7 | Hot tier retention |
| `RETENTION_WARM_DAYS` | 30 | Warm tier retention |
| `RETENTION_COLD_DAYS` | 365 | Cold tier retention |

---

## Quick Start

```bash
# 1. Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/macOS

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure
copy .env.example .env
# Edit .env with your settings

# 4. Launch
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# 5. Open dashboard
# http://localhost:8000
# Default login: admin / changeme
```

---

## Integration with Your Firewall

### Sending Logs

Your firewall/WAF should POST logs to ThreatLoom:

```python
import httpx

async def send_to_soc(log_data: dict):
    async with httpx.AsyncClient() as client:
        await client.post(
            "http://localhost:8000/api/v1/logs/ingest/json",
            json=log_data,
            headers={"Authorization": f"Bearer {token}"}
        )
```

### Connecting Response Actions

Edit `threatloom/response/actions.py` to call your firewall's API:

```python
async def _execute_block_ip(self, ip: str, params: dict) -> bool:
    # Replace stub with actual firewall API call:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "http://your-firewall:8080/api/block",
            json={"ip": ip, "duration": params.get("duration_minutes", 60)}
        )
    return resp.status_code == 200
```

---

## Tech Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Backend | FastAPI | 0.115.6 |
| ORM | SQLAlchemy (async) | 2.0.36 |
| Database | SQLite (MVP) / PostgreSQL | - |
| Validation | Pydantic | 2.10.4 |
| Auth | python-jose + passlib | JWT HS256 |
| Templates | Jinja2 | - |
| Charts | Chart.js | 4.4.7 |
| CSS | Tailwind CSS (CDN) | 3.x |
| GeoIP | MaxMind GeoLite2 | - |
| Metrics | psutil | - |

---

## License

Internal / Custom — adapt as needed.
