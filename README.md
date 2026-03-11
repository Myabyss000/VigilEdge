# VigilEdge Security Platform

This workspace is a local security lab made of four runnable parts:

- VigilEdge WAF: a FastAPI-based web application firewall and dashboard
- ThreatLoom: a FastAPI SOC platform for ingestion, detection, alerting, and incident tracking
- Demo Website: an intentionally insecure demo target used to exercise the WAF
- Chatbot Server: a Flask bridge that reads WAF data and queries LM Studio for WAF-focused explanations

The repository is Windows-first. The main launch flow is driven by batch files in the workspace root, and the VigilEdge code is nested under `project-null-2.0/vigiledge-collage-project--main/VigilEdge/`.

## What Actually Runs

| Component | Framework | Port | Main entrypoint | Primary URL | Default access |
|---|---|---:|---|---|---|
| VigilEdge WAF | FastAPI | 5000 | `project-null-2.0/vigiledge-collage-project--main/VigilEdge/waf/app.py` | `http://localhost:5000/login` | `admin` / `admin` |
| ThreatLoom SOC | FastAPI | 8443 | `ThreatLoom/main.py` | `http://localhost:8443/` | `admin` / `changeme` |
| Vulnerable App | FastAPI | 8080 | `project-null-2.0/vigiledge-collage-project--main/VigilEdge/vulnerable-app/app.py` | `http://localhost:8080/` | Demo user data in app DB |
| Chatbot Server | Flask | 5001 | `chatbot_server.py` | `http://localhost:5001/health` | No login |

Important credential boundary:

- WAF dashboard login is separate from the vulnerable app's demo admin account.
- The vulnerable app seeds `admin` / `admin123` inside its own SQLite database.
- The demo website can still be reached through the WAF at `http://localhost:5000/protected`.
- The main productized flow is now a custom upstream website protected through the WAF at `http://localhost:5000/`, with `/protected` kept as a compatibility path.

## Architecture

Request flow:

1. Browser traffic hits the VigilEdge WAF on port 5000.
2. Requests sent to `/` or `/protected` can be inspected by the WAF and proxied to the selected upstream website.
3. Security events are stored in the WAF runtime and may be forwarded asynchronously to ThreatLoom on port 8443.
4. ThreatLoom ingests those events, applies signature, behavioral, and correlation analysis, then creates alerts and incidents.
5. The chatbot reads recent WAF event statistics from SQLite and sends tightly scoped prompts to LM Studio on port 1234.

Operational notes from the code:

- `start_demo.bat` launches the original full demo stack: chatbot, ThreatLoom, demo website, and the WAF.
- `start_custom_website.bat` launches chatbot, ThreatLoom, and the WAF, then points the WAF at your custom website URL.
- The WAF startup path clears in-memory state and deletes rows from its `security_events` table for a fresh session.
- WAF OpenAPI docs are only enabled when `DEBUG=True`.
- ThreatLoom exposes API docs at `/api/docs`, but it does not currently expose a generic `/health` route.

## Repository Layout

```text
vigiledge part 3/
├── README.md
├── requirements.txt
├── start_custom_website.bat
├── start_demo.bat
├── start_chatbot.bat
├── chatbot_server.py
├── ThreatLoom/
│   ├── main.py
│   ├── requirements.txt
│   ├── dashboard/
│   ├── rules/
│   ├── playbooks/
│   ├── tests/
│   └── threatloom/
│       ├── api/v1/
│       ├── auth/
│       ├── detection/
│       ├── ingestion/
│       ├── models/
│       ├── notifications/
│       ├── response/
│       ├── storage/
│       └── websocket/
└── project-null-2.0/
    └── vigiledge-collage-project--main/
        └── VigilEdge/
            ├── README.md
            ├── docs/
            ├── tests/
            ├── vulnerable-app/
            └── waf/
                ├── app.py
                ├── routes/
                ├── services/
                ├── static/
                ├── templates/
                └── vigiledge/
                    ├── api/
                    ├── config.py
                    ├── core/
                    ├── middleware/
                    ├── models/
                    └── utils/
```

## Verified Capabilities

### VigilEdge WAF

Implemented in code:

- Reverse proxy protection for a selected upstream website at `/`, `/protected`, or both
- Pattern-based detection for SQL injection, XSS, command injection, path traversal, and related payload families
- Rate limiting, dynamic IP blocking, request metrics, and event logging
- Admin dashboard pages for threats, analytics, AI analysis, network monitoring, blocked IPs, event logs, and settings
- Session-cookie login for the WAF dashboard
- 2FA bootstrap and TOTP-backed password reset pages
- AI threat scoring with heuristic scoring, optional LM Studio scoring, and a hybrid mode
- ThreatLoom integration hooks for forwarding WAF events to the SOC
- Network-monitoring and activity telemetry endpoints
- Windows integration hooks under `waf/services/windows_defender_integration.py`

Useful WAF routes:

- Dashboard login: `http://localhost:5000/login`
- Admin dashboard: `http://localhost:5000/admin/dashboard`
- Root website path: `http://localhost:5000/`
- Protected compatibility path: `http://localhost:5000/protected`
- Health check: `http://localhost:5000/api/v1/health`
- Optional docs when `DEBUG=True`: `http://localhost:5000/docs`

### ThreatLoom SOC

Implemented in code:

- JSON, batch, syslog, and raw log ingestion
- Detection engine with rule-based, behavioral, and correlation layers
- MITRE ATT&CK mapping for known attack families
- Alerts, incidents, responses, playbooks, users, and firewall status APIs
- JWT authentication and RBAC
- Server-rendered dashboard pages plus WebSocket streaming
- Retention manager and audit-oriented backend structure

Useful ThreatLoom routes:

- Dashboard: `http://localhost:8443/`
- API docs: `http://localhost:8443/api/docs`
- Login API: `POST http://localhost:8443/api/v1/users/login`
- Firewall connectivity status: `GET http://localhost:8443/api/v1/firewall/status`

### Demo Website

Implemented in code:
# VigilEdge Security Platform

VigilEdge Security Platform is a local-first defensive stack for protecting and monitoring web applications without depending on a cloud WAF. This workspace combines a reverse-proxy web application firewall, a lightweight SOC layer, an optional AI analysis path, and a demo target for local security testing.

It is designed around a practical use case: small and medium teams that need inspection, visibility, and explainability on their own infrastructure, while keeping traffic and security data under local control.

## Overview

This repository contains four main parts:

| Component | Role | Framework | Default Port |
|---|---|---|---:|
| VigilEdge WAF | Reverse-proxy firewall, request inspection, admin dashboard | FastAPI | 5000 |
| ThreatLoom | SOC-style ingestion, detection, incidents, dashboard | FastAPI | 8443 |
| Chatbot Server | AI-assisted explanation layer for WAF activity | Flask | 5001 |
| Demo Website | Intentionally insecure test target for validation | FastAPI | 8080 |

The main productized mode is to place your own website behind the WAF. The demo website is optional and should only be used for testing.

## Why This Project Exists

Most smaller teams cannot justify the cost or operational model of enterprise edge products. This project aims to provide:

- local traffic inspection and visibility
- deployable protection for a custom upstream website
- explainable AI-assisted threat context without mandatory cloud APIs
- a bundled SOC component for alerts and incident tracking
- a demo environment for validation and training

## Core Capabilities

### VigilEdge WAF

- Reverse-proxy protection for a selected upstream website at `/`, `/protected`, or both
- Detection for SQL injection, XSS, command injection, path traversal, suspicious payloads, and rate abuse
- Dynamic blocking, request metrics, event logging, and administrative dashboards
- Authentication for the WAF dashboard with 2FA setup and password reset flows
- Optional forwarding of WAF events into ThreatLoom
- Custom upstream routing support for either a real website or the bundled demo target

### ThreatLoom

- Log and event ingestion pipelines
- Rule-based, behavioral, and correlation-based detection layers
- Alert and incident management
- JWT and RBAC-backed APIs
- Web dashboard plus WebSocket-backed live updates

### AI Features

The AI layer is intentionally local-first and assistive.

- Heuristic AI scoring is available directly inside the WAF request analysis pipeline
- Optional LM Studio integration adds model-backed scoring and operator-facing explanations
- The chatbot is restricted to WAF and security-analysis use cases rather than acting as a general assistant
- AI output is used to enrich context and prioritization; core firewall rules still remain the primary enforcement path
- If LM Studio is not available, the platform continues operating with heuristic scoring and guidance-only fallback behavior

### Demo Website

- Local e-commerce-style test surface for attack simulation
- Useful for validating proxying, blocking, dashboards, and AI explanations
- Intentionally insecure and not suitable for internet exposure

## AI Architecture

The AI implementation in this workspace is split into two practical layers:

| AI Layer | Purpose | Dependency | Behavior |
|---|---|---|---|
| Heuristic scorer | Fast inline risk scoring during request analysis | Built into VigilEdge | Always available when AI is enabled |
| LM Studio integration | Local model-backed explanation and enhanced scoring | LM Studio on port 1234 | Optional |
| Chatbot interface | WAF-focused operator assistance and threat explanation | Chatbot server + LM Studio | Optional |

Current AI behavior, based on the implemented code:

- heuristic scoring remains the baseline path
- multi-encoded payloads are normalized before scoring
- AI-related event fields are written into WAF event details for later analysis
- model availability is optional and the system degrades gracefully when local model services are offline
- chatbot responses are scoped to recent WAF data and security-oriented prompts

This means the platform can still inspect and protect traffic without a running LLM, while offering richer explanations when a local model is available.

## Request Flow

1. A browser sends traffic to VigilEdge WAF on port 5000.
2. The WAF inspects the request before forwarding it to the selected upstream website.
3. Events are logged locally and can be forwarded to ThreatLoom.
4. ThreatLoom performs downstream analysis, alerting, and incident handling.
5. The chatbot can query recent WAF event context and send narrowly scoped prompts to LM Studio.

## Repository Layout

```text
vigiledge part 3/
├── README.md
├── chatbot_server.py
├── start_demo.bat
├── start_custom_website.bat
├── ThreatLoom/
└── project-null-2.0/
    └── vigiledge-collage-project--main/
        └── VigilEdge/
            ├── vulnerable-app/
            ├── waf/
            ├── docs/
            └── tests/
```

Key implementation areas:

- WAF application: `project-null-2.0/vigiledge-collage-project--main/VigilEdge/waf/`
- ThreatLoom service: `ThreatLoom/`
- Chatbot bridge: `chatbot_server.py`
- Demo target: `project-null-2.0/vigiledge-collage-project--main/VigilEdge/vulnerable-app/`

## Getting Started

### Prerequisites

- Windows 10 or 11
- Python 3.13+
- Free ports: 5000, 5001, 8080, 8443
- LM Studio on port 1234 if you want local model-backed AI features

### Environment Setup

The launcher scripts expect these virtual environments:

- `project-null-2.0/vigiledge-collage-project--main/VigilEdge/venv`
- `ThreatLoom/venv`

Create them from the workspace root:

```powershell
cd "project-null-2.0\vigiledge-collage-project--main\VigilEdge"
python -m venv venv
.\venv\Scripts\python.exe -m pip install --upgrade pip
.\venv\Scripts\python.exe -m pip install -r waf\requirements.txt

cd "..\..\..\ThreatLoom"
python -m venv venv
.\venv\Scripts\python.exe -m pip install --upgrade pip
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Launch Modes

For the original demo stack:

```powershell
start_demo.bat
```

For protecting your own website:

```powershell
start_custom_website.bat
```

Launcher behavior:

1. `start_demo.bat` starts the chatbot, ThreatLoom, demo website, and WAF.
2. `start_custom_website.bat` asks for your upstream URL, then starts the chatbot, ThreatLoom, and WAF.
3. Both launchers check for port conflicts before starting services.

### Manual Start

If you prefer to launch services yourself:

```powershell
# Terminal 1
cd "ThreatLoom"
.\venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8443 --reload

# Terminal 2
cd "project-null-2.0\vigiledge-collage-project--main\VigilEdge\waf"
..\venv\Scripts\python.exe -m uvicorn app:app --host 0.0.0.0 --port 5000 --reload

# Terminal 3
cd "path\to\your-custom-website"
python your_app.py

# Terminal 4
cd "."
project-null-2.0\vigiledge-collage-project--main\VigilEdge\venv\Scripts\python.exe chatbot_server.py
```

## Default Access

| Service | URL | Notes |
|---|---|---|
| WAF login | `http://localhost:5000/login` | Default credentials currently exist in local config |
| WAF dashboard | `http://localhost:5000/admin/dashboard` | Main operator UI |
| Protected website via root | `http://localhost:5000/` | Active when root mode is enabled |
| Protected website via subpath | `http://localhost:5000/protected` | Compatibility path |
| ThreatLoom | `http://localhost:8443/` | SOC dashboard |
| Chatbot health | `http://localhost:5001/health` | Confirms chatbot process is up |
| WAF health | `http://localhost:5000/api/v1/health` | Implemented WAF health endpoint |

Current local defaults in the codebase:

- WAF: `admin` / `admin`
- ThreatLoom: `admin` / `changeme`
- Demo app admin data is separate from WAF credentials

These defaults are suitable for local evaluation only and should be changed before any serious deployment.

## Configuration

### WAF Configuration Sources

- environment variables defined in `waf/vigiledge/config.py`
- persisted settings in `waf/config/waf_settings.json`
- launcher-provided environment overrides for upstream target selection

Important WAF settings include:

- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `RATE_LIMIT_ENABLED`
- `RATE_LIMIT_REQUESTS`
- `SQL_INJECTION_PROTECTION`
- `XSS_PROTECTION`
- `DDOS_PROTECTION`
- `THREATLOOM_ENABLED`
- `THREATLOOM_API_URL`
- `UPSTREAM_PUBLIC_MODE`
- `UPSTREAM_USE_DEMO_TARGET`
- `UPSTREAM_CUSTOM_TARGET_URL`
- `UPSTREAM_DEMO_TARGET_URL`

### AI Configuration

Optional AI integrations depend on LM Studio:

- chatbot requests use `http://localhost:1234/v1/chat/completions`
- model availability checks use `http://localhost:1234/v1/models`

Without LM Studio:

- WAF heuristic scoring still works
- the platform still logs and inspects requests
- chatbot flows return guidance instead of model-backed answers

## Testing

Relevant test locations:

- `ThreatLoom/tests/`
- `project-null-2.0/vigiledge-collage-project--main/VigilEdge/tests/`
- root-level VigilEdge validation scripts under `project-null-2.0/vigiledge-collage-project--main/VigilEdge/`

Examples:

```powershell
pytest ThreatLoom\tests -v
python project-null-2.0\vigiledge-collage-project--main\VigilEdge\test_attack_detection.py
python project-null-2.0\vigiledge-collage-project--main\VigilEdge\test_ai_queries.py
```

## Current Project Status

This repository is a strong local prototype and demo platform, but it should not yet be described as production-ready.

What is already real:

- local reverse-proxy WAF behavior
- working operator dashboard
- local event capture and forwarding
- SOC-style analysis component
- optional AI assistance without mandatory cloud dependency

What still needs hardening for production use:

- stronger authentication and session handling
- secret management and first-run setup
- authenticated control-plane APIs and ingestion paths
- TLS and deployment defaults
- production-grade persistence and operational monitoring

## Troubleshooting

### Port Binding Errors

If you see an error like `[Errno 10048] error while attempting to bind on address ('0.0.0.0', 5000)`, the problem is that the port is already in use, not that `0.0.0.0` is invalid.

Quick checks:

```powershell
netstat -ano | findstr :5000
netstat -ano | findstr :5001
netstat -ano | findstr :8080
netstat -ano | findstr :8443
```

PowerShell alternative:

```powershell
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in 5000,5001,8080,8443 } |
Select-Object LocalAddress,LocalPort,OwningProcess
```

### AI Responses Fail

Make sure LM Studio is running locally on port 1234 with a loaded model. If LM Studio is offline, the system will fall back to non-LLM behavior where supported.

### Launcher Stops Immediately

Check that:

- both expected virtual environments exist
- the required ports are free
- your custom upstream website is already running if you use custom mode

### WAF Docs Are Missing

That is expected unless `DEBUG=True` is enabled.

## Security Notice

The bundled demo website is intentionally vulnerable and exists only for local testing. Do not expose it to the public internet.

Before any serious deployment:

- change all default credentials
- replace default secrets
- disable or isolate the demo application
- review WAF and ThreatLoom configuration
- deploy behind proper TLS and operational monitoring

## Additional Documentation

- `ThreatLoom/docs/ARCHITECTURE.md`
- `project-null-2.0/vigiledge-collage-project--main/VigilEdge/docs/TESTING_README.md`
- `project-null-2.0/vigiledge-collage-project--main/VigilEdge/docs/WAF_TESTING_GUIDE.md`
- `project-null-2.0/vigiledge-collage-project--main/VigilEdge/AI_FEATURES_DEMO.md`
- `project-null-2.0/vigiledge-collage-project--main/VigilEdge/CHATBOT_SETUP.md`

## License

This workspace includes MIT-licensed components. See the root `LICENSE` file and the nested project licenses for details.
