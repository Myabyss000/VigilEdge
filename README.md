<div align="center">

# 🛡️ VigilEdge Security Platform

[![Python](https://img.shields.io/badge/python-3.13%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2B-0078D6?style=for-the-badge&logo=windows&logoColor=white)]()
[![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)]()

**Enterprise Web Application Firewall &amp; Security Operations Center**

An integrated security platform combining **VigilEdge WAF** _(real-time threat detection, blocking &amp; AI scoring)_ with **ThreatLoom SOC** _(centralized log analysis, MITRE ATT&amp;CK mapping, alerting &amp; automated incident response)_.

[Quick Start](#-quick-start) · [Architecture](#-architecture) · [Features](#-features) · [Installation](#-installation) · [Testing](#-security-testing) · [API](#-api-reference) · [Configuration](#-configuration)

---

</div>

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Architecture](#-architecture)
- [Features](#-features)
- [Installation](#-installation)
- [Project Structure](#-project-structure)
- [Security Testing](#-security-testing)
- [API Reference](#-api-reference)
- [Configuration](#-configuration)
- [Performance & Tech Stack](#-performance--tech-stack)
- [Troubleshooting](#-troubleshooting)
- [Security Notice](#-security-notice)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🚀 Quick Start

### ⚡ One-Click Launch

**Double-click `start_all.bat`** — all four servers start automatically:

| # | Service | Port | URL | Credentials |
|---|---------|------|-----|-------------|
| 1 | AI Security Chatbot | 5001 | http://localhost:5001 | — |
| 2 | ThreatLoom SOC | 8443 | http://localhost:8443 | `admin` / `changeme` |
| 3 | Vulnerable Test App | 8080 | http://localhost:8080 | ⚠️ Testing only |
| 4 | VigilEdge WAF | 5000 | http://localhost:5000/admin/dashboard | `admin` / `admin` |

### 🎯 5-Minute Demo Walkthrough

```
Step 1 → Double-click start_all.bat → wait for all terminal windows
Step 2 → Open WAF Dashboard → http://localhost:5000/admin/dashboard
Step 3 → Attack the test app → Go to http://localhost:5000/protected/admin
          → Enter username: admin' OR '1'='1'--
          → Click Login
Step 4 → See block page → "🛡️ BLOCKED BY WAF" message appears
Step 5 → Check ThreatLoom → http://localhost:8443
          → Event appears in SOC dashboard within ~10 seconds
          → Alert and Incident auto-created for HIGH/CRITICAL threats
Step 6 → Explore APIs → http://localhost:5000/docs (WAF)
                        → http://localhost:8443/api/docs (SOC)
```

---

## 🏗️ Architecture

```
                 ┌────────────────────────────────────────────────────────┐
                 │              VigilEdge Security Platform               │
                 └──────────────────────────┬─────────────────────────────┘
                                            │
          ┌─────────────────────────────────┼─────────────────────────────────┐
          │                                 │                                 │
┌─────────▼──────────┐          ┌──────────▼──────────┐          ┌───────────▼──────────┐
│   VigilEdge WAF    │          │   ThreatLoom SOC    │          │   Vulnerable App     │
│   (Port 5000)      │          │   (Port 8443)       │          │   (Port 8080)        │
│                    │          │                     │          │                      │
│ ┌────────────────┐ │          │ ┌─────────────────┐ │          │ • E-commerce demo    │
│ │ WAF Engine     │ │  Events  │ │ Ingestion Layer │ │          │ • Intentional vulns  │
│ │ • SQL Injection│ ├─────────►│ │ • JSON / Syslog │ │          │ • Login, search,     │
│ │ • XSS         │ │  (async) │ │ • Batch / Raw   │ │          │   admin panels       │
│ │ • RCE / LFI   │ │          │ └────────┬────────┘ │          │ • WAF test target    │
│ │ • DDoS / Bots │ │          │          │          │          │                      │
│ │ • Path Trav.  │ │          │ ┌────────▼────────┐ │          └──────────────────────┘
│ └────────┬───────┘ │          │ │ Detection Eng.  │ │
│          │         │          │ │ • Signature     │ │
│ ┌────────▼───────┐ │          │ │ • Threshold     │ │
│ │ Middleware     │ │          │ │ • Behavioral    │ │
│ │ • Rate Limit  │ │          │ │ • Correlation   │ │
│ │ • IP Blocking │ │          │ └────────┬────────┘ │
│ │ • AI Scoring  │ │          │          │          │
│ │ • Session Mgmt│ │          │ ┌────────▼────────┐ │
│ └────────┬───────┘ │          │ │ Alert → Incident│ │
│          │         │          │ │ • Auto-escalate │ │
│ ┌────────▼───────┐ │          │ │ • MITRE Mapping │ │
│ │ Reverse Proxy  │ │          │ │ • SOAR Playbooks│ │
│ │ → Backend App  │ │          │ └─────────────────┘ │
│ └────────────────┘ │          │                     │
└────────────────────┘          └─────────────────────┘
```

### Data Flow

1. **Incoming requests** → hit VigilEdge WAF (port 5000)
2. **WAF Engine** inspects headers, body, URL, user-agent against 100+ detection patterns
3. **Threat detected** → request blocked (403) with forensic logging
4. **Clean request** → proxied to backend app via reverse proxy
5. **Every security event** → forwarded asynchronously to ThreatLoom SOC
6. **ThreatLoom** runs 3-layer detection (signature + behavioral + correlation)
7. **HIGH/CRITICAL detections** → auto-escalated to incidents
8. **SOC Dashboard** → live alert feed, severity charts, incident management

---

## ✨ Features

### 🛡️ VigilEdge WAF — Web Application Firewall

| Feature | Description | Status |
|---------|-------------|--------|
| **SQL Injection Protection** | 100+ patterns — classic, UNION, boolean, error-based, polyglot, JSON/XML, DB-specific | ✅ Active |
| **XSS Prevention** | Script tags, event handlers, `javascript:` protocol, DOM-based | ✅ Active |
| **Command Injection** | OS command detection and blocking | ✅ Active |
| **Path Traversal / LFI** | Directory traversal and local file inclusion prevention | ✅ Active |
| **DDoS Protection** | Traffic analysis with automatic mitigation | ✅ Active |
| **Rate Limiting** | Configurable per-IP (default: 100 req/min), auto-block after threshold | ✅ Active |
| **IP Blocking** | Dynamic blacklist with CRUD API, auto-block for repeat offenders | ✅ Active |
| **Bot Detection** | User-agent behavioral analysis and crawler identification | ✅ Active |
| **AI Threat Scoring** | Heuristic + LM Studio integration for intelligent threat classification | ✅ Active |
| **Reverse Proxy** | Transparent protection for any backend application | ✅ Active |
| **Real-time Dashboard** | Live metrics, event stream via WebSocket, animated charts | ✅ Active |
| **Session Authentication** | HTTP-only secure cookies, prevents URL-based bypass | ✅ Active |
| **Windows Defender** | Native Windows security event integration | ✅ Active |
| **CSRF Protection** | Token-based cross-site request forgery prevention | 🔄 Optional |
| **File Upload Scanning** | Malware detection in uploaded files | 🔄 Optional |

### 🔍 ThreatLoom SOC — Security Operations Center

| Feature | Description | Status |
|---------|-------------|--------|
| **Multi-format Ingestion** | JSON, syslog (RFC 3164/5424), raw text, batch ingestion | ✅ Active |
| **3-Layer Detection Engine** | Signature rules, behavioral analysis, cross-log correlation | ✅ Active |
| **MITRE ATT&CK Mapping** | 14+ attack types mapped to tactics & techniques automatically | ✅ Active |
| **Alert Management** | Severity-based alerting (LOW → CRITICAL) with acknowledgment workflow | ✅ Active |
| **Auto-Escalation** | HIGH/CRITICAL alerts auto-create incidents for investigation | ✅ Active |
| **Incident Response** | Full triage workflow — create, investigate, mitigate, close, reopen | ✅ Active |
| **Automated Playbooks (SOAR)** | YAML-defined response automation — IP blocks, rate limits, temp bans | ✅ Active |
| **GeoIP Enrichment** | Country, city, ASN lookup for all source IPs | ✅ Active |
| **RBAC** | Admin, SOC Analyst, Viewer roles with JWT authentication | ✅ Active |
| **WebSocket Streaming** | Real-time channels: alerts, logs, incidents, system metrics | ✅ Active |
| **Tiered Storage** | Hot/warm/cold retention with automatic lifecycle management | ✅ Active |
| **Audit Logging** | All write operations tracked with user attribution | ✅ Active |
| **Real-time Dashboard** | Live alert feed, severity charts, geo distribution, top attackers | ✅ Active |

### 🤖 AI Security Chatbot

| Feature | Description |
|---------|-------------|
| **Security Q&A** | Natural language queries about detected threats |
| **Threat Explanation** | AI-powered analysis of attack patterns |
| **Recommendation Engine** | Suggested mitigations for detected vulnerabilities |

---

## 📦 Installation

### Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **Python** | 3.13+ | 3.13+ |
| **OS** | Windows 10 | Windows 11 |
| **RAM** | 2 GB | 4+ GB |
| **Storage** | 200 MB | 500 MB |
| **Network** | 10 Mbps | 100+ Mbps |

### Step 1 — Clone

```bash
git clone https://github.com/yourusername/vigiledge-security-platform.git
cd vigiledge-security-platform
```

### Step 2 — Install Dependencies

```bash
# Option A: Single unified install
pip install -r requirements.txt

# Option B: Component virtual environments (recommended for development)
# WAF
cd project-null-2.0/vigiledge-collage-project--main/VigilEdge/waf
python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt

# ThreatLoom
cd ../../../../ThreatLoom
python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt
```

### Step 3 — Launch

```bash
# One-click launch (Windows)
start_all.bat

# Manual launch (4 terminals)
# Terminal 1: ThreatLoom SOC
cd ThreatLoom && venv\Scripts\activate
uvicorn main:app --host 0.0.0.0 --port 8443 --reload

# Terminal 2: Vulnerable Test App
cd project-null-2.0/.../VigilEdge/vulnerable-app
python app.py

# Terminal 3: VigilEdge WAF
cd project-null-2.0/.../VigilEdge/waf && venv\Scripts\activate
python -m uvicorn app:app --host 0.0.0.0 --port 5000 --reload

# Terminal 4: AI Chatbot
python chatbot_server.py
```

### Step 4 — Verify

| Check | Expected |
|-------|----------|
| http://localhost:5000/health | `{"status": "healthy"}` |
| http://localhost:5000/admin/dashboard | WAF Dashboard loads |
| http://localhost:8443 | ThreatLoom SOC Dashboard loads |
| http://localhost:5000/protected/ | E-commerce app via WAF |

> **Note:** Each component manages its own virtual environment. The `start_all.bat` script handles venv activation automatically.

---

## 📁 Project Structure

```
vigiledge-security-platform/
│
├── start_all.bat                    # ⚡ One-click launcher (all 4 servers)
├── start_both.bat                   # Legacy launcher (WAF + vulnerable app only)
├── requirements.txt                 # 📦 Unified dependencies (both components)
├── README.md                        # 📖 This file
├── chatbot_server.py                # 🤖 AI security chatbot server
│
├── project-null-2.0/
│   └── vigiledge-collage-project--main/
│       ├── LICENSE                   # MIT License
│       └── VigilEdge/               # 🛡️ WAF Component
│           ├── waf/                 #    Core WAF application
│           │   ├── app.py           #    FastAPI application factory
│           │   ├── main.py          #    Legacy entry point
│           │   ├── requirements.txt #    WAF-specific dependencies
│           │   ├── vigiledge/       #    WAF engine package
│           │   │   ├── config.py    #      Configuration (env vars)
│           │   │   ├── core/        #      WAF engine, middleware
│           │   │   │   └── waf_engine.py  # Threat detection core
│           │   │   └── models/      #      Database models
│           │   ├── services/        #    Integration services
│           │   │   └── threatloom_integration.py  # SOC forwarder
│           │   ├── routes/          #    API & dashboard routes
│           │   ├── templates/       #    Dashboard HTML (Jinja2)
│           │   └── static/         #    CSS, JS, images
│           │
│           ├── vulnerable-app/      # 🎯 Test target application
│           │   ├── app.py          #    Intentionally vulnerable e-commerce
│           │   └── vulnerable.db   #    SQLite database
│           │
│           ├── scripts/             # 🔧 Utility scripts
│           │   ├── setup.bat       #    Environment setup
│           │   └── clear_ports.bat #    Port cleanup
│           │
│           ├── docs/                # 📚 Documentation
│           │   ├── PROJECT_REPORT_CHAPTERS.md
│           │   ├── TESTING_README.md
│           │   └── WAF_TESTING_GUIDE.md
│           │
│           └── tests/               # 🧪 WAF test suite
│               ├── test_waf.py
│               ├── test_auth.py
│               └── quick_test.py
│
├── ThreatLoom/                      # 🔍 SOC Component
│   ├── main.py                     #    FastAPI entry point
│   ├── requirements.txt            #    SOC-specific dependencies
│   ├── .env.example                #    Environment template
│   ├── threatloom/                  #    Core SOC package
│   │   ├── config.py              #      Settings (from .env)
│   │   ├── database.py            #      Async SQLAlchemy engine
│   │   ├── models/                #      ORM models
│   │   │   ├── logs.py            #        Firewall logs + enums
│   │   │   ├── alerts.py          #        Alert model + severity
│   │   │   ├── incidents.py       #        Incident lifecycle
│   │   │   ├── responses.py       #        Automated responses
│   │   │   └── playbooks.py       #        SOAR playbooks
│   │   ├── schemas/               #      Pydantic request/response
│   │   ├── auth/                  #      JWT, RBAC, audit
│   │   ├── ingestion/             #      Log parsers & normalization
│   │   ├── detection/             #      Detection engine
│   │   │   ├── engine.py          #        Main detection loop
│   │   │   ├── rules/             #        Signature & threshold
│   │   │   ├── behavioral/        #        Rate, geo, pattern analysis
│   │   │   └── correlation/       #        IP, session, time-window
│   │   ├── response/              #      SOAR & playbook runner
│   │   ├── storage/               #      Retention lifecycle
│   │   ├── websocket/             #      Real-time streaming
│   │   ├── api/v1/                #      REST API routes
│   │   └── utils/                 #      GeoIP, helpers
│   ├── dashboard/                  #    SOC dashboard
│   │   ├── templates/             #      Jinja2 HTML templates
│   │   └── static/                #      CSS & JavaScript
│   ├── rules/                      #    Detection rules (YAML)
│   │   └── default_rules.yaml     #      18 pre-configured rules
│   ├── playbooks/                  #    SOAR playbooks (YAML)
│   └── tests/                      #    SOC test suite
│
└── logs/                            # 📝 Application logs
```

---

## 🧪 Security Testing

### SQL Injection

#### Classic Injection
```
URL:      http://localhost:5000/protected/admin
Username: admin' OR '1'='1'--
Password: anything
→ Result: ⛔ Blocked by WAF (403)
```

#### UNION-based Injection
```
URL:      http://localhost:5000/protected/search
Search:   ' UNION SELECT * FROM users--
→ Result: ⛔ Blocked — UNION SELECT pattern detected
```

#### Boolean-based Injection
```
Username: admin' AND '1'='1
→ Result: ⛔ Blocked immediately
```

### XSS (Cross-Site Scripting)

#### Script Tag Injection
```
Input:    <script>alert('XSS')</script>
→ Result: ⛔ Blocked — script tag detected
```

#### Event Handler XSS
```
Input:    <img src=x onerror="alert('XSS')">
→ Result: ⛔ Blocked — onerror pattern detected
```

#### JavaScript Protocol
```
Input:    <a href="javascript:alert('XSS')">Click</a>
→ Result: ⛔ Blocked — javascript: protocol detected
```

### Rate Limiting / DDoS

```bash
# Send 150 requests rapidly (limit = 100/min)
for i in {1..150}; do curl http://localhost:5000/protected/; done

# Expected:
#   Requests 1-100:   ✅ 200 OK
#   Requests 101-150: ⛔ 429 Too Many Requests
#   IP auto-blocked for 5 minutes
```

### Bot Detection

```bash
curl -H "User-Agent: BadBot/1.0" http://localhost:5000/protected/
→ Result: ⛔ Flagged as bot traffic
```

### Authentication Bypass

```
1. Login at http://localhost:5000/protected/admin (password: admin123)
2. Copy the full URL from the address bar
3. Open a new incognito/private window
4. Paste the URL
→ Result: ⛔ Redirected to login (session-based, not URL-based)
```

### Verifying End-to-End Flow

After running any test:

| Dashboard | URL | What to Look For |
|-----------|-----|-----------------|
| **WAF Dashboard** | http://localhost:5000/admin/dashboard | Event appears instantly via WebSocket |
| **ThreatLoom SOC** | http://localhost:8443 | Event forwarded, alert created (~10s), incident auto-escalated for HIGH/CRITICAL |

---

## 📝 API Reference

### VigilEdge WAF — Port 5000

**Interactive docs:** http://localhost:5000/docs

#### Blocked IPs

```bash
# List all blocked IPs
GET /api/v1/blocked-ips
# Response: [{"ip": "10.0.0.5", "reason": "SQL Injection", "blocked_at": "..."}]

# Block an IP
POST /api/v1/blocked-ips
# Body: {"ip": "192.168.1.100", "reason": "Suspicious activity"}

# Unblock an IP
DELETE /api/v1/blocked-ips/192.168.1.100

# Clear all blocked IPs
DELETE /api/v1/blocked-ips
```

#### Event Logs

```bash
# Get security event logs
GET /api/v1/event-logs?limit=100&offset=0&threat_type=sql_injection
# Response: [{"id": 1, "timestamp": "...", "ip": "...", "threat_type": "SQL Injection", "blocked": true}]

# Get event statistics
GET /api/v1/event-logs/stats
# Response: {"total_events": 1543, "blocked_threats": 1456, "threat_types": {...}}
```

#### System

```bash
GET /api/v1/metrics        # WAF performance metrics
GET /api/v1/statistics      # Threat statistics
GET /health                 # Health check
```

### ThreatLoom SOC — Port 8443

**Interactive docs:** http://localhost:8443/api/docs

#### Log Ingestion

```bash
# Ingest single log (JSON)
POST /api/v1/logs/ingest/json
# Body: {"timestamp": "...", "src_ip": "10.0.0.1", "action": "BLOCKED", "attack_type": "SQLI", ...}

# Batch ingestion
POST /api/v1/logs/ingest/batch
# Body: {"logs": [{...}, {...}]}

# Syslog format
POST /api/v1/logs/ingest/syslog
# Body: {"raw": "<134>Feb 14 19:00:00 waf: BLOCKED src=10.0.0.1 ..."}
```

#### Querying

```bash
GET /api/v1/logs/                 # Query logs with filters
GET /api/v1/logs/stats/summary    # Log statistics
GET /api/v1/alerts/               # List alerts with filters
GET /api/v1/incidents/            # List incidents
GET /api/v1/responses/            # Automated response history
GET /api/v1/playbooks/            # SOAR playbook CRUD
```

#### Authentication

```bash
POST /api/v1/users/login          # Get JWT token
# Body: {"username": "admin", "password": "changeme"}
# Response: {"access_token": "eyJ...", "token_type": "bearer"}

# Use token in headers:
Authorization: Bearer eyJ...
```

#### WebSocket Channels

```bash
ws://localhost:8443/ws/alerts      # Real-time alert stream
ws://localhost:8443/ws/logs        # Live log feed
ws://localhost:8443/ws/incidents   # Incident updates
ws://localhost:8443/ws/metrics     # System metrics
```

#### Integration Example (Python)

```python
import httpx

async def forward_event(event: dict):
    """Send a security event from any firewall to ThreatLoom."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8443/api/v1/logs/ingest/json",
            json={
                "timestamp": event["timestamp"],
                "src_ip": event["source_ip"],
                "protocol": "HTTP",
                "action": "BLOCKED",
                "attack_type": "SQLI",
                "severity": "HIGH",
                "http_method": "POST",
                "http_path": "/admin",
                "payload_snippet": event.get("payload", "")[:500],
                "raw_log": str(event)[:2000],
            },
        )
        return response.status_code  # 201 = success
```

---

## ⚙️ Configuration

### VigilEdge WAF Environment Variables

Create `.env` in the WAF directory (`project-null-2.0/.../VigilEdge/waf/.env`):

```env
# ── Server ──────────────────────────────────────
HOST=0.0.0.0
PORT=5000
DEBUG=False
ENVIRONMENT=production

# ── Security Features ───────────────────────────
SQL_INJECTION_PROTECTION=True
XSS_PROTECTION=True
DDOS_PROTECTION=True
RATE_LIMIT_ENABLED=True
RATE_LIMIT_REQUESTS=100
IP_BLOCKING_ENABLED=True
BOT_DETECTION_ENABLED=True

# ── ThreatLoom Integration ──────────────────────
THREATLOOM_ENABLED=True
THREATLOOM_API_URL=http://localhost:8443
THREATLOOM_API_KEY=

# ── Session & Auth ──────────────────────────────
SECRET_KEY=change-me-in-production
ACCESS_TOKEN_EXPIRE_MINUTES=30

# ── Protected Application ───────────────────────
VULNERABLE_APP_URL=http://localhost:8080
VULNERABLE_APP_ENABLED=True
VULNERABLE_APP_PROXY_PATH=/protected

# ── Logging ─────────────────────────────────────
LOG_LEVEL=INFO
LOG_FILE=./logs/vigiledge.log
LOG_FORMAT=json

# ── Database ────────────────────────────────────
DATABASE_URL=sqlite:///./vigiledge.db
```

### ThreatLoom SOC Configuration

Copy `.env.example` → `.env` in the `ThreatLoom/` directory. Key settings:

```env
DATABASE_URL=sqlite+aiosqlite:///./threatloom.db
SECRET_KEY=change-me-in-production
DEFAULT_ADMIN_PASSWORD=changeme
GEOIP_DB_PATH=./data/GeoLite2-City.mmdb
RETENTION_HOT_DAYS=7
RETENTION_WARM_DAYS=30
RETENTION_COLD_DAYS=90
```

### WAF Detection Rules

Edit `project-null-2.0/.../VigilEdge/waf/config/waf_rules.yaml`:

```yaml
sql_injection:
  enabled: true
  severity: high
  patterns:
    - "union.*select"
    - "drop.*table"
    - "' or '1'='1"
    - "1=1--"

xss:
  enabled: true
  severity: high
  patterns:
    - "<script"
    - "javascript:"
    - "onerror="

rate_limiting:
  enabled: true
  requests_per_minute: 100
  burst_size: 150
  block_duration: 300  # seconds
```

### ThreatLoom Detection Rules

Edit `ThreatLoom/rules/default_rules.yaml` — 18 pre-configured rules:

```yaml
rules:
  # Signature rule example
  - id: sig-sqli-blocked
    name: "SQL Injection Attempt Blocked"
    enabled: true
    severity: HIGH
    type: signature
    mitre_tactic: "Initial Access"
    mitre_technique: "T1190"
    conditions:
      - field: attack_type
        operator: equals
        value: "SQLI"
      - field: action
        operator: equals
        value: "BLOCKED"

  # Threshold rule example
  - id: thr-brute-force-5min
    name: "Brute Force — 10+ blocked in 5 min"
    enabled: true
    severity: HIGH
    type: threshold
    threshold:
      field: src_ip
      count: 10
      window_seconds: 300
      filter:
        action: "BLOCKED"
```

---

## ⚡ Performance & Tech Stack

### Performance Metrics

| Metric | Value |
|--------|-------|
| Request Processing | < 10 ms latency |
| Threat Detection | < 5 ms pattern matching |
| Dashboard Updates | Real-time (WebSocket) |
| Concurrent Connections | 1000+ |
| Log Forwarding | Async, non-blocking |
| Memory Usage (idle) | ~100–150 MB per component |
| CPU Usage (idle) | < 5% |
| Database Queries | < 2 ms (SQLite) |
| Detection Scan Cycle | Every 10 seconds |
| Alert Auto-Escalation | Immediate for HIGH/CRITICAL |

### Technology Stack

| Layer | Technologies |
|-------|-------------|
| **Backend** | FastAPI, Uvicorn (ASGI), Python 3.13+ |
| **Database** | SQLite (aiosqlite), SQLAlchemy 2.0 (async), Alembic |
| **Frontend** | HTML5, CSS3, JavaScript (ES6+), WebSockets, Chart.js |
| **Security** | Custom WAF Engine, MITRE ATT&CK, JWT (python-jose), bcrypt |
| **Networking** | httpx (async HTTP), websockets, aiofiles |
| **Analysis** | GeoIP2, psutil, structlog |
| **Config** | Pydantic Settings, PyYAML, python-dotenv |

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 2 cores @ 2.0 GHz | 4+ cores @ 2.5 GHz+ |
| **RAM** | 2 GB | 4+ GB |
| **Storage** | 200 MB | 500 MB (logs grow over time) |
| **OS** | Windows 10+ | Windows 11 |
| **Python** | 3.13+ | 3.13+ |

---

## 🛠️ Troubleshooting

<details>
<summary><b>❌ Port Already in Use (Error 10048)</b></summary>

```powershell
# Find processes using the ports
netstat -ano | findstr :5000
netstat -ano | findstr :8080
netstat -ano | findstr :8443

# Kill specific process
taskkill /PID <PID> /F

# Or kill all Python processes
taskkill /IM python.exe /F

# Or use the cleanup script
cd project-null-2.0\vigiledge-collage-project--main\VigilEdge\scripts
clear_ports.bat
```

</details>

<details>
<summary><b>❌ ModuleNotFoundError</b></summary>

```bash
# Verify Python version
python --version  # Should be 3.13+

# Install from unified requirements
pip install -r requirements.txt

# Or install per-component
pip install -r project-null-2.0/.../VigilEdge/waf/requirements.txt
pip install -r ThreatLoom/requirements.txt
```

</details>

<details>
<summary><b>❌ ThreatLoom Not Receiving Events</b></summary>

```bash
# 1. Check WAF terminal for forwarding messages:
#    🔗 ThreatLoom: event queued for forwarding
#    ✅ ThreatLoom: event ingested (201)

# 2. Verify ThreatLoom is running on port 8443
curl http://localhost:8443/health

# 3. Check .env has integration enabled:
#    THREATLOOM_ENABLED=True
#    THREATLOOM_API_URL=http://localhost:8443
```

</details>

<details>
<summary><b>❌ Dashboard Shows No Data / Alerts = 0</b></summary>

```bash
# Normal on fresh start — no attacks detected yet.
# 1. Trigger an attack through the WAF:
#    http://localhost:5000/protected/admin → admin' OR '1'='1'--
# 2. Wait ~10 seconds (detection engine scan interval)
# 3. Refresh http://localhost:8443

# If still no alerts, delete the database and restart:
del ThreatLoom\threatloom.db
# Restart ThreatLoom
```

</details>

<details>
<summary><b>❌ Database Errors</b></summary>

```bash
# SQLite databases auto-recreate on startup.
# Delete and restart:
del ThreatLoom\threatloom.db
del project-null-2.0\...\VigilEdge\waf\vigiledge.db
del project-null-2.0\...\VigilEdge\vulnerable-app\vulnerable.db
# Restart all services
```

</details>

<details>
<summary><b>❌ Template Not Found</b></summary>

```bash
# WAF must be run FROM the waf/ directory (templates use relative paths)
cd project-null-2.0\vigiledge-collage-project--main\VigilEdge\waf
python main.py
# start_all.bat handles this automatically.
```

</details>

<details>
<summary><b>❌ WAF Not Blocking Attacks</b></summary>

```bash
# Make sure you access via WAF proxy:
# ✅ Correct: http://localhost:5000/protected/admin
# ❌ Wrong:   http://localhost:8080/admin (bypasses WAF)

# Check waf_rules.yaml has protection enabled:
#   sql_injection.enabled: true
```

</details>

### Diagnostic Commands

```powershell
# Check if ports are accessible
Test-NetConnection -ComputerName localhost -Port 5000
Test-NetConnection -ComputerName localhost -Port 8080
Test-NetConnection -ComputerName localhost -Port 8443

# Test APIs
curl http://localhost:5000/health
curl http://localhost:8443/health
curl http://localhost:5000/api/v1/event-logs

# Check installed packages
pip list | findstr fastapi
pip list | findstr uvicorn
```

---

## 🔒 Security Notice

> [!CAUTION]
> The `vulnerable-app/` directory contains **intentional security vulnerabilities** for testing and educational purposes. **NEVER deploy it to production or expose it to the public internet.**

### ⚠️ Before Production Deployment

- [ ] Change **all** default passwords (`admin`, `admin123`, `changeme`)
- [ ] Generate new `SECRET_KEY` values for both WAF and SOC
- [ ] Enable **HTTPS/TLS** on all endpoints
- [ ] Review and customize WAF detection rules
- [ ] **Remove or isolate** the vulnerable test application
- [ ] Configure proper log rotation and retention
- [ ] Set up external monitoring and alerting
- [ ] Implement database backup strategies
- [ ] Conduct a thorough security audit
- [ ] Test in a staging environment first
- [ ] Do **not** run services as root/administrator
- [ ] Do **not** expose raw SQLite databases

### 📋 Responsible Disclosure

If you discover a security vulnerability in the WAF or SOC components:

1. **DO NOT** open a public GitHub issue
2. Email details to: `security@vigiledge.example.com`
3. Include proof of concept if available
4. Allow 90 days for resolution before public disclosure

---

## 🤝 Contributing

We welcome contributions! Here's how:

### Process

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Code** — follow PEP 8, add docstrings, include type hints
4. **Test** — run existing tests: `python -m pytest tests/ -v`
5. **Commit** — use conventional format: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`
6. **Push** — `git push origin feature/amazing-feature`
7. **PR** — open a Pull Request with a clear description

### Commit Format

```
feat: Add IP reputation checking
fix: Resolve SQL injection bypass in pattern matching
docs: Update API documentation with new endpoints
test: Add integration tests for ThreatLoom ingestion
refactor: Extract detection engine into separate module
```

### Ways to Contribute

- 🐛 **Report bugs** — open issues for WAF/SOC bugs (not intentional vulnerable-app flaws)
- ✨ **Suggest features** — propose new security features or detection rules
- 📝 **Improve docs** — fix typos, add examples, clarify instructions
- 🧪 **Add tests** — write unit/integration tests
- 🔧 **Submit code** — fix bugs or implement features
- 🌍 **Add detection rules** — contribute new YAML signature/threshold rules

---

## 📚 Additional Documentation

| Document | Location | Description |
|----------|----------|-------------|
| Project Report | `VigilEdge/docs/PROJECT_REPORT_CHAPTERS.md` | Full architecture report |
| Testing Guide | `VigilEdge/docs/TESTING_README.md` | Comprehensive testing procedures |
| WAF Testing | `VigilEdge/docs/WAF_TESTING_GUIDE.md` | WAF-specific security testing |
| SOC Architecture | `ThreatLoom/docs/ARCHITECTURE.md` | ThreatLoom design documentation |
| WAF API Docs | http://localhost:5000/docs | Interactive OpenAPI/Swagger |
| SOC API Docs | http://localhost:8443/api/docs | Interactive OpenAPI/Swagger |

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](project-null-2.0/vigiledge-collage-project--main/LICENSE) for details.

---

## 👥 Authors & Acknowledgments

- **VigilEdge Team** — Core WAF development
- **ThreatLoom Team** — SOC platform development
- **OWASP** — Security guidelines and best practices
- **FastAPI** — High-performance async web framework
- **Open-source security community** — Detection patterns and research

---

<div align="center">

### ⚡ VigilEdge Security Platform

**Enterprise WAF + SOC — Detect, Block, Analyze, Respond**

Made with ❤️ and ☕

[⬆️ Back to Top](#️-vigiledge-security-platform)

</div>
