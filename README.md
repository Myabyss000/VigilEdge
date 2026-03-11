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
| VigilEdge WAF | FastAPI | 5000 | `project-null-2.0/vigiledge-collage-project--main/VigilEdge/waf/app.py` | `http://localhost:5000/login` | First-run bootstrap or persisted local admin |
| ThreatLoom SOC | FastAPI | 8443 | `ThreatLoom/main.py` | `http://localhost:8443/` | First-run bootstrap or existing admin |
| Vulnerable App | FastAPI | 8080 | `project-null-2.0/vigiledge-collage-project--main/VigilEdge/vulnerable-app/app.py` | `http://localhost:8080/` | Demo user data in app DB |
| Chatbot Server | Flask | 5001 | `chatbot_server.py` | `http://localhost:5001/health` | No login |

Important credential boundary:

- WAF dashboard login is separate from the vulnerable app's demo admin account.
- The vulnerable app seeds `admin` / `admin123` inside its own SQLite database.
- WAF and ThreatLoom no longer rely on documented default admin credentials; both now support first-run bootstrap for the first privileged account.
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
- ThreatLoom exposes API docs at `/api/docs` only when debug mode is enabled, and it does not currently expose a generic `/health` route.

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
- Signed JWT-backed admin session cookies for the WAF dashboard
- First-run WAF admin bootstrap with optional bootstrap token
- Google Authenticator compatible 2FA enrollment and TOTP-backed password reset pages
- CSRF protection for WAF bootstrap, login, password reset, and 2FA setup forms
- Authenticated WAF control-plane APIs and protected dashboard WebSocket channels
- Trusted reverse-proxy-aware client IP handling for forwarded IP headers
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
- First-run ThreatLoom admin bootstrap and authenticated ingest endpoints
- ThreatLoom firewall status route protection and docs gated by debug mode
- Server-rendered dashboard pages plus WebSocket streaming
- Retention manager and audit-oriented backend structure

Useful ThreatLoom routes:

- Dashboard: `http://localhost:8443/`
- API docs when debug is enabled: `http://localhost:8443/api/docs`
- Login API: `POST http://localhost:8443/api/v1/users/login`
- Bootstrap status API: `GET http://localhost:8443/api/v1/users/bootstrap/status`
- Firewall connectivity status: `GET http://localhost:8443/api/v1/firewall/status`

### Demo Website

Implemented in code:

- Local e-commerce-style test surface for attack simulation and WAF validation
- Reachable directly on port 8080 or through the WAF on `/protected`
- Separate application credentials and data model from the WAF and ThreatLoom control planes
- Intentionally insecure behavior for testing WAF detections and dashboards

## Security Highlights

Recent security work now reflected in the codebase includes:

- Signed JWT-backed WAF admin sessions instead of a placeholder auth cookie
- CSRF protection on WAF bootstrap, login, password reset, and 2FA setup forms
- Automatic WAF session invalidation when the admin password changes
- Protected WAF dashboard WebSocket and control-plane APIs using either admin session auth or configured service tokens
- Authenticated ThreatLoom ingest endpoints using bearer service tokens or authorized JWT users
- First-run bootstrap for both VigilEdge and ThreatLoom instead of public default admin credentials
- ThreatLoom docs hidden unless debug mode is enabled
- Trusted reverse-proxy-aware client IP handling so `X-Forwarded-For` is only honored from configured proxy peers

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

## HTTPS and Reverse Proxy Guide

For real deployments, do not expose the WAF directly on plain HTTP to the public internet. The simplest safe model is:

1. Run VigilEdge WAF on a local interface or private network port.
2. Put a TLS terminator or reverse proxy in front of it.
3. Configure `TRUSTED_REVERSE_PROXIES` so the WAF only honors forwarded client IP headers from that proxy.

Recommended one-path deployment for most users:

- public entry: Caddy, Nginx, or Traefik on ports `80` and `443`
- internal app: VigilEdge WAF on `127.0.0.1:5000`
- optional internal SOC: ThreatLoom on `127.0.0.1:8443`

### Recommended Default: Caddy in Front of VigilEdge

This is the easiest path for non-expert users because Caddy can obtain and renew TLS certificates automatically.

Example Caddyfile:

```caddy
example.com {
    reverse_proxy 127.0.0.1:5000
}
```

Then set the WAF environment so the proxy is trusted:

```env
TRUSTED_REVERSE_PROXIES=127.0.0.1,::1
```

Recommended operating model:

- bind Caddy publicly on `:80` and `:443`
- bind the WAF only on localhost or a private interface
- access the WAF through `https://example.com`
- keep ThreatLoom private unless you intentionally publish it behind its own proxy

### Nginx Example

If you already use Nginx, a minimal reverse-proxy block looks like this:

```nginx
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

With Nginx on the same host, set:

```env
TRUSTED_REVERSE_PROXIES=127.0.0.1,::1
```

### Traefik Example

If you already run Traefik, point a router at the WAF and trust the proxy network in the WAF config.

Conceptually:

- Traefik handles certificates and public `https`
- Traefik forwards to `http://127.0.0.1:5000`
- the WAF trusts only the Traefik host IP or Docker network CIDR via `TRUSTED_REVERSE_PROXIES`

Example setting when Traefik runs on a Docker bridge network:

```env
TRUSTED_REVERSE_PROXIES=127.0.0.1,::1,172.18.0.0/16
```

### Local TLS Terminator Option

If you already have another local TLS terminator, the same rule applies:

- terminate HTTPS there
- forward to the WAF over localhost or a private subnet
- add only that proxy IP or subnet to `TRUSTED_REVERSE_PROXIES`

### Important Reverse Proxy Notes

- Leave `TRUSTED_REVERSE_PROXIES` empty if the WAF is not behind a proxy.
- Do not trust `0.0.0.0/0` or broad internet ranges.
- Only trust the exact proxy IPs or local CIDRs you control.
- If this setting is wrong, rate limiting, blocking, and logs may show the proxy IP instead of the real client IP.
- If this setting is too broad, clients may spoof `X-Forwarded-For` and bypass IP-based controls.

## Access and Authentication

| Service | URL | Notes |
|---|---|---|
| WAF login | `http://localhost:5000/login` | Uses the persisted local admin account or redirects to first-run bootstrap when uninitialized |
| WAF dashboard | `http://localhost:5000/admin/dashboard` | Main operator UI |
| Protected website via root | `http://localhost:5000/` | Active when root mode is enabled |
| Protected website via subpath | `http://localhost:5000/protected` | Compatibility path |
| ThreatLoom | `http://localhost:8443/` | SOC dashboard with first-run bootstrap when no admin exists |
| Chatbot health | `http://localhost:5001/health` | Confirms chatbot process is up |
| WAF health | `http://localhost:5000/api/v1/health` | Implemented WAF health endpoint |

Current authentication model:

- WAF: local admin credentials come from persisted WAF settings or first-run bootstrap
- WAF 2FA: Google Authenticator compatible TOTP enrollment and password-recovery flow remain available
- ThreatLoom: the first privileged account is created through bootstrap, not a public default password
- Demo app admin data is separate from WAF and ThreatLoom credentials

## Configuration

### WAF Configuration Sources

- environment variables defined in `waf/vigiledge/config.py`
- persisted settings in `waf/config/waf_settings.json`
- launcher-provided environment overrides for upstream target selection

Important WAF settings include:

- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `CONTROL_PLANE_API_TOKENS`
- `BOOTSTRAP_ADMIN_TOKEN`
- `CORS_ORIGINS`
- `TRUSTED_REVERSE_PROXIES`
- `RATE_LIMIT_ENABLED`
- `RATE_LIMIT_REQUESTS`
- `SQL_INJECTION_PROTECTION`
- `XSS_PROTECTION`
- `DDOS_PROTECTION`
- `THREATLOOM_ENABLED`
- `THREATLOOM_API_URL`
- `THREATLOOM_API_KEY`
- `UPSTREAM_PUBLIC_MODE`
- `UPSTREAM_USE_DEMO_TARGET`
- `UPSTREAM_CUSTOM_TARGET_URL`
- `UPSTREAM_DEMO_TARGET_URL`

Important ThreatLoom settings include:

- `INGEST_SERVICE_TOKENS`
- `BOOTSTRAP_ADMIN_TOKEN`
- `JWT_SECRET`
- `APP_DEBUG`

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

This repository is a strong local-first prototype and demo platform with materially improved control-plane security, but it should still not be described as production-ready.

What is already real:

- local reverse-proxy WAF behavior for a real upstream website or the bundled demo target
- working operator dashboard and live WebSocket updates
- signed WAF admin sessions with CSRF-protected form flows
- authenticated WAF control-plane APIs and authenticated ThreatLoom ingest
- first-run bootstrap flows for both products
- local event capture, ThreatLoom forwarding, SOC-style analysis, and optional AI assistance

What still needs hardening for production use:

- end-to-end TLS termination and deployment defaults
- more formal secret rotation and secure secret storage
- production-grade persistence, backup, and recovery procedures
- broader automated tests for auth, proxy trust, and operational edge cases
- deployment guidance for real reverse proxies, containers, and observability

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

### Wrong Client IP Is Recorded

If the WAF is behind a real reverse proxy, set `TRUSTED_REVERSE_PROXIES` to the proxy IPs or CIDR ranges. If this value is empty, the WAF intentionally ignores `X-Forwarded-For` and uses the socket peer IP.

## Security Notice

The bundled demo website is intentionally vulnerable and exists only for local testing. Do not expose it to the public internet.

Before any serious deployment:

- replace local secrets and bootstrap tokens
- isolate or disable the demo application
- review WAF and ThreatLoom configuration, including trusted reverse proxies
- deploy behind proper TLS and operational monitoring
- verify that service tokens are configured for machine-to-machine flows

## Additional Documentation

- `ThreatLoom/docs/ARCHITECTURE.md`
- `project-null-2.0/vigiledge-collage-project--main/VigilEdge/docs/TESTING_README.md`
- `project-null-2.0/vigiledge-collage-project--main/VigilEdge/docs/WAF_TESTING_GUIDE.md`
- `project-null-2.0/vigiledge-collage-project--main/VigilEdge/AI_FEATURES_DEMO.md`
- `project-null-2.0/vigiledge-collage-project--main/VigilEdge/CHATBOT_SETUP.md`

## License

This workspace includes MIT-licensed components. See the root `LICENSE` file and the nested project licenses for details.
