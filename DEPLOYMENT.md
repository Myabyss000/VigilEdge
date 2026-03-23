# VigilEdge + ThreatLoom Deployment Guide

This document covers deployment in two tracks:

- Local autonomous deployment on Windows (recommended for non-technical users)
- Production deployment on Ubuntu with systemd + Caddy

## Track A: Local Autonomous Deployment (Windows)

### Goal

Provide a one-step, zero-configuration local deployment that installs and runs the platform automatically.

### Entrypoints

- PowerShell: `deploy_oneclick.ps1`
- Double-click wrapper: `run_oneclick.bat`

### Default behavior

When run without arguments, deployment starts in full-demo mode:

- WAF (`5000`)
- ThreatLoom SOC (`8443`)
- Demo app (`8080`)
- Chatbot (`5001`, optional and enabled by default)

### What the script automates

1. self-elevates to Administrator
2. validates required paths and Python availability
3. checks for port conflicts
4. creates Windows firewall rules for ports `5000`, `5001`, `8080`, `8443`
     - inbound TCP
     - `Private` profile only
5. creates missing virtual environments:
     - `project-null-2.0/vigiledge-collage-project--main/VigilEdge/venv`
     - `ThreatLoom/venv`
6. installs dependencies
7. falls back to offline package install if online pip fails
8. creates missing `.env` files from `.env.example`
9. generates secure random values for placeholder secrets when needed
10. runs ThreatLoom Alembic migration if `APP_ENV=production`
11. starts services in separate PowerShell windows
12. verifies listening ports and prints final URLs

### Quick run

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy_oneclick.ps1
```

or double-click:

```bat
run_oneclick.bat
```

### Custom upstream mode

Interactive URL prompt:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy_oneclick.ps1 -Mode custom
```

Argument-driven URL:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy_oneclick.ps1 -Mode custom -UpstreamUrl "http://localhost:3000"
```

### Optional flags

- skip chatbot:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy_oneclick.ps1 -SkipChatbot
```

- force local offline package directory:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy_oneclick.ps1 -LocalPackageDir .\offline_packages
```

Auto-detected offline directories (if present):

- `offline_packages`
- `offline-packages`
- `packages`
- `wheels`

### Local deployment output URLs

- WAF: `http://localhost:5000`
- SOC: `http://localhost:8443`
- Demo: `http://localhost:8080` (full mode)
- Chatbot: `http://localhost:5001` (unless skipped)

## Track B: Production Deployment (Ubuntu + Caddy)

Reference topology:

```text
Internet
    -> Caddy (:80/:443, TLS)
            -> VigilEdge WAF (127.0.0.1:5000)
            -> ThreatLoom SOC (127.0.0.1:8443)
```

### 1) Install prerequisites

```bash
apt-get update && apt-get upgrade -y
apt-get install -y \
    python3.11 python3.11-venv python3.11-dev \
    build-essential libpq-dev \
    postgresql postgresql-client git curl
```

Install Caddy from the official repository:

```bash
apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
    | tee /etc/apt/sources.list.d/caddy-stable.list
apt-get update && apt-get install -y caddy
```

### 2) Clone repository

```bash
APP_ROOT=/opt/vigiledge
git clone <your-repo-url> "$APP_ROOT"
```

### 3) Create virtual environments

WAF side:

```bash
VE_DIR="$APP_ROOT/project-null-2.0/vigiledge-collage-project--main/VigilEdge"
WAF_DIR="$VE_DIR/waf"

python3.11 -m venv "$VE_DIR/venv"
"$VE_DIR/venv/bin/pip" install --upgrade pip
"$VE_DIR/venv/bin/pip" install -r "$WAF_DIR/requirements.txt"
```

ThreatLoom side:

```bash
TL_DIR="$APP_ROOT/ThreatLoom"
python3.11 -m venv "$TL_DIR/venv"
"$TL_DIR/venv/bin/pip" install --upgrade pip
"$TL_DIR/venv/bin/pip" install -r "$TL_DIR/requirements.txt"
```

### 4) Configure PostgreSQL for ThreatLoom

```bash
sudo -u postgres psql <<'SQL'
CREATE USER threatloom WITH PASSWORD 'CHANGE_ME_STRONG_PASSWORD';
CREATE DATABASE threatloom OWNER threatloom;
GRANT ALL PRIVILEGES ON DATABASE threatloom TO threatloom;
SQL
```

### 5) Configure environment files

Create production `.env` files for both services. Minimum required values:

- strong `SECRET_KEY`
- strong `JWT_SECRET` (ThreatLoom)
- production `DATABASE_URL` for ThreatLoom (`postgresql+asyncpg`)
- debug disabled in production

### 6) Run DB migrations

```bash
cd "$TL_DIR"
APP_ENV=production DATABASE_URL="postgresql+asyncpg://threatloom:CHANGE_ME_STRONG_PASSWORD@127.0.0.1:5432/threatloom" \
    "$TL_DIR/venv/bin/alembic" upgrade head
```

### 7) Install and start systemd services

```bash
cp "$APP_ROOT/deploy/vigiledge-waf.service" /etc/systemd/system/
cp "$APP_ROOT/deploy/threatloom.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vigiledge-waf
systemctl enable --now threatloom
```

### 8) Configure Caddy

```bash
cp "$APP_ROOT/deploy/Caddyfile" /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile
systemctl reload caddy
```

## Verification Checklist

Local checks:

```bash
systemctl status vigiledge-waf
systemctl status threatloom
journalctl -fu vigiledge-waf
journalctl -fu threatloom
```

HTTP checks:

```bash
curl http://127.0.0.1:5000/
curl http://127.0.0.1:8443/
```

Public TLS checks (if exposed):

```bash
curl https://your.domain.example/
```

## Backup and Restore

Recommended backups:

- PostgreSQL ThreatLoom database (`pg_dump`)
- WAF runtime config (`waf/config/waf_settings.json`)
- `.env` files (encrypted at rest)

Restore sequence:

1. stop services
2. restore PostgreSQL dump
3. run Alembic migrations
4. restore WAF config and env files
5. restart services

## Upgrade Procedure

```bash
cd /opt/vigiledge
git pull

cd /opt/vigiledge/ThreatLoom
APP_ENV=production DATABASE_URL="postgresql+asyncpg://threatloom:CHANGE_ME@127.0.0.1:5432/threatloom" \
    venv/bin/alembic upgrade head

systemctl restart vigiledge-waf
systemctl restart threatloom
```

## Troubleshooting

Common checks:

- service failures: `journalctl -xe -u <service>`
- migration errors: verify DB credentials and schema state
- Caddy cert issues: verify DNS + public port `80` reachability
- local startup failures: verify free ports `5000`, `5001`, `8080`, `8443`

Windows local port check:

```powershell
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in 5000,5001,8080,8443 }
```
