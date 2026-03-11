# VigilEdge Security Platform

This workspace is a local security lab made of four runnable parts:

- VigilEdge WAF: a FastAPI-based web application firewall and dashboard
- ThreatLoom: a FastAPI SOC platform for ingestion, detection, alerting, and incident tracking
- Vulnerable App: an intentionally insecure demo target used to exercise the WAF
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
- The protected vulnerable app is reached through the WAF at `http://localhost:5000/protected`.

## Architecture

Request flow:

1. Browser traffic hits the VigilEdge WAF on port 5000.
2. Requests sent to `/protected` are inspected by the WAF and proxied to the vulnerable app on port 8080.
3. Security events are stored in the WAF runtime and may be forwarded asynchronously to ThreatLoom on port 8443.
4. ThreatLoom ingests those events, applies signature, behavioral, and correlation analysis, then creates alerts and incidents.
5. The chatbot reads recent WAF event statistics from SQLite and sends tightly scoped prompts to LM Studio on port 1234.

Operational notes from the code:

- `start_all.bat` launches ThreatLoom before the WAF.
- The WAF startup path clears in-memory state and deletes rows from its `security_events` table for a fresh session.
- WAF OpenAPI docs are only enabled when `DEBUG=True`.
- ThreatLoom exposes API docs at `/api/docs`, but it does not currently expose a generic `/health` route.

## Repository Layout

```text
vigiledge part 3/
├── README.md
├── requirements.txt
├── start_all.bat
├── start_both.bat
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

- Reverse proxy protection for `/protected` traffic
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
- Protected app: `http://localhost:5000/protected`
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

### Vulnerable App

Implemented in code:

- Intentionally vulnerable e-commerce-style demo surface
- Session-backed demo login flow
- Search and form surfaces that are useful for WAF testing
- Activity logging back into the WAF for live monitoring views

Treat it as test-only. Do not expose it publicly.

### Chatbot Server

Implemented in code:

- Flask API on port 5001
- Reads WAF event stats from the local SQLite database
- Sends narrowly scoped prompts to LM Studio at `http://localhost:1234`
- Refuses general-purpose assistant behavior and limits itself to WAF-related explanations

## Quick Start

### Prerequisites

- Windows 10 or 11
- Python 3.13+
- Ports 5000, 5001, 8080, and 8443 free
- LM Studio on port 1234 if you want AI chatbot answers or LM-based WAF scoring

### Recommended Setup For The Batch Launchers

`start_all.bat` expects these virtual environments to already exist:

- `project-null-2.0/vigiledge-collage-project--main/VigilEdge/venv`
- `ThreatLoom/venv`

Create them like this from the workspace root:

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

If you want a single shared environment for ad hoc work, the root `requirements.txt` can also be installed separately, but the launchers still expect the two component-local venv paths above.

### Start Everything

```powershell
start_all.bat
```

What the launcher does:

1. Requests administrator privileges.
2. Starts the chatbot on port 5001 using the VigilEdge venv.
3. Starts ThreatLoom on port 8443.
4. Starts the vulnerable app on port 8080.
5. Starts the WAF on port 5000.
6. Opens the WAF dashboard, protected app, and ThreatLoom dashboard in the browser.

### Manual Start

If you do not want to use the batch launcher:

```powershell
# Terminal 1
cd "ThreatLoom"
.\venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8443 --reload

# Terminal 2
cd "project-null-2.0\vigiledge-collage-project--main\VigilEdge\vulnerable-app"
..\venv\Scripts\python.exe app.py

# Terminal 3
cd "project-null-2.0\vigiledge-collage-project--main\VigilEdge\waf"
..\venv\Scripts\python.exe -m uvicorn app:app --host 0.0.0.0 --port 5000 --reload

# Terminal 4
cd "."
project-null-2.0\vigiledge-collage-project--main\VigilEdge\venv\Scripts\python.exe chatbot_server.py
```

## Default URLs And Access

| Service | URL | Notes |
|---|---|---|
| WAF login | `http://localhost:5000/login` | Login required before `/admin/dashboard` |
| WAF admin dashboard | `http://localhost:5000/admin/dashboard` | Uses WAF credentials, not vulnerable app credentials |
| Protected demo app | `http://localhost:5000/protected` | Traffic inspected by WAF |
| Direct vulnerable app | `http://localhost:8080/` | Bypasses the WAF |
| ThreatLoom dashboard | `http://localhost:8443/` | SOC UI |
| ThreatLoom API docs | `http://localhost:8443/api/docs` | Always enabled in current code |
| Chatbot health | `http://localhost:5001/health` | Confirms chatbot process is up |
| WAF health | `http://localhost:5000/api/v1/health` | Current implemented health route |

## Configuration

### WAF

Sources of configuration:

- Environment variables loaded by `project-null-2.0/vigiledge-collage-project--main/VigilEdge/waf/vigiledge/config.py`
- Persisted UI settings in `project-null-2.0/vigiledge-collage-project--main/VigilEdge/waf/config/waf_settings.json`

Key settings include:

- `ADMIN_USERNAME`, `ADMIN_PASSWORD`
- `RATE_LIMIT_REQUESTS`, `RATE_LIMIT_ENABLED`
- `SQL_INJECTION_PROTECTION`, `XSS_PROTECTION`, `DDOS_PROTECTION`
- `THREATLOOM_ENABLED`, `THREATLOOM_API_URL`
- `VULNERABLE_APP_URL`, `VULNERABLE_APP_PROXY_PATH`
- `DEBUG` for enabling `/docs`

### ThreatLoom

ThreatLoom reads `.env` from the `ThreatLoom/` directory. Important settings include:

- `APP_PORT=8443`
- `DATABASE_URL=sqlite+aiosqlite:///./threatloom.db`
- `DEFAULT_ADMIN_USER=admin`
- `DEFAULT_ADMIN_PASS=changeme`
- `FIREWALL_HEALTH_URL=http://localhost:5000`
- `FIREWALL_WEBHOOK_ENABLED=false` by default

### LM Studio

Optional but used by AI features:

- Chatbot server expects LM Studio at `http://localhost:1234/v1/chat/completions`
- The WAF AI scorer checks LM Studio model availability at `http://localhost:1234/v1/models`

Without LM Studio, the chatbot returns connection guidance and the WAF falls back to heuristic scoring.

## Testing And Validation

Code-backed test surfaces in the repository:

- ThreatLoom pytest suite: `ThreatLoom/tests/`
- VigilEdge test and demo scripts: `project-null-2.0/vigiledge-collage-project--main/VigilEdge/`
- Additional WAF tests: `project-null-2.0/vigiledge-collage-project--main/VigilEdge/tests/`

Examples:

```powershell
pytest ThreatLoom\tests -v
python project-null-2.0\vigiledge-collage-project--main\VigilEdge\test_attack_detection.py
python project-null-2.0\vigiledge-collage-project--main\VigilEdge\test_ai_queries.py
```

For manual validation:

1. Open `http://localhost:5000/protected` and browse the demo app through the WAF.
2. Sign into the WAF at `http://localhost:5000/login` using `admin` / `admin`.
3. Open ThreatLoom at `http://localhost:8443/` using `admin` / `changeme`.
4. Trigger test traffic through `/protected` and confirm it appears in the WAF views and later in ThreatLoom alerts/incidents.

## Known Gaps And Documentation Corrections

This README reflects the current codebase and corrects several stale assumptions found elsewhere in the workspace:

- ThreatLoom runs on port 8443, not 8000.
- The WAF dashboard entry is `/admin/dashboard`, not `/dashboard`.
- WAF default credentials are `admin` / `admin`; the vulnerable app's demo admin password is `admin123`.
- The WAF is launched with `uvicorn app:app`, not `python main.py`.
- The implemented WAF health route is `/api/v1/health`.
- WAF docs are conditional on `DEBUG=True`.
- `file_upload_scanning` exists as a config flag, but a complete end-to-end upload scanning workflow is not evident from the current code.
- Windows Defender integration exists in the WAF service layer, but this workspace should treat it as integration/logging support rather than a separately documented enforcement plane.

## Troubleshooting

### Port Conflicts

```powershell
netstat -ano | findstr :5000
netstat -ano | findstr :5001
netstat -ano | findstr :8080
netstat -ano | findstr :8443
```

### WAF Starts But Docs Are Missing

That is expected unless `DEBUG=True` is set for the WAF.

### ThreatLoom Looks Up But Health Checks Fail

ThreatLoom does not currently publish a generic `/health` route. Use the root dashboard or `/api/docs` to confirm the service is up.

### Chatbot Answers Fail

Make sure LM Studio is running locally on port 1234 with a loaded model.

### Batch Launcher Fails Immediately

Check that both expected virtual environments exist:

- `project-null-2.0/vigiledge-collage-project--main/VigilEdge/venv`
- `ThreatLoom/venv`

## Additional Documentation

- `ThreatLoom/docs/ARCHITECTURE.md`
- `project-null-2.0/vigiledge-collage-project--main/VigilEdge/docs/TESTING_README.md`
- `project-null-2.0/vigiledge-collage-project--main/VigilEdge/docs/WAF_TESTING_GUIDE.md`
- `project-null-2.0/vigiledge-collage-project--main/VigilEdge/README.md`
- `ThreatLoom/README.md`

## Security Notice

The vulnerable app is intentionally insecure and exists for local testing only. Do not deploy it to the public internet or bundle it into any production environment.

Before any serious deployment work:

- change all default passwords
- replace all default secret keys
- disable or isolate the vulnerable app
- review WAF and ThreatLoom environment settings
- add proper TLS, monitoring, and backups

## License

This workspace includes MIT-licensed components. See the root `LICENSE` and the nested project licenses for details.
