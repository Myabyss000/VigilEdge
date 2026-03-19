# VigilEdge + ThreatLoom — Production Deployment Guide

This guide walks you through a complete, tested installation on a fresh
**Ubuntu 22.04 LTS** virtual machine using the canonical topology:

```
Internet
   │
   ▼
Caddy  :80 / :443   (TLS termination, reverse proxy)
   ├── / → VigilEdge WAF   127.0.0.1:5000
   └── /soc/* → ThreatLoom   127.0.0.1:8443
```

---

## 1. System prerequisites

```bash
# As root or via sudo
apt-get update && apt-get upgrade -y

# Runtime dependencies
apt-get install -y \
    python3.11 python3.11-venv python3.11-dev \
    build-essential libpq-dev \
    postgresql postgresql-client \
    git curl

# Caddy (official package)
apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    | tee /etc/apt/sources.list.d/caddy-stable.list
apt-get update && apt-get install -y caddy
```

---

## 2. Service accounts

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin vigiledge
useradd --system --no-create-home --shell /usr/sbin/nologin threatloom
```

---

## 3. Deploy application code

```bash
# Choose an install root; /opt is conventional for managed services
APP_ROOT=/opt/vigiledge
git clone <your-repo-url> "$APP_ROOT"
chown -R root:root "$APP_ROOT"
```

### 3a. WAF virtual environment

```bash
WAF_DIR="$APP_ROOT/project-null-2.0/vigiledge-collage-project--main/VigilEdge/waf"

python3.11 -m venv "$WAF_DIR/.venv"
"$WAF_DIR/.venv/bin/pip" install --upgrade pip
"$WAF_DIR/.venv/bin/pip" install -r "$WAF_DIR/requirements.txt"

# Runtime directories
mkdir -p "$WAF_DIR/logs" "$WAF_DIR/config"
chown -R vigiledge:vigiledge "$WAF_DIR/logs"
```

### 3b. ThreatLoom virtual environment

```bash
TL_DIR="$APP_ROOT/ThreatLoom"

python3.11 -m venv "$TL_DIR/.venv"
"$TL_DIR/.venv/bin/pip" install --upgrade pip
"$TL_DIR/.venv/bin/pip" install -r "$TL_DIR/requirements.txt"

mkdir -p "$TL_DIR/logs"
chown -R threatloom:threatloom "$TL_DIR/logs"
```

---

## 4. PostgreSQL database

```bash
# Switch to the postgres system user
sudo -u postgres psql <<'SQL'
CREATE USER threatloom WITH PASSWORD 'CHANGE_ME_STRONG_PASSWORD';
CREATE DATABASE threatloom OWNER threatloom;
GRANT ALL PRIVILEGES ON DATABASE threatloom TO threatloom;
SQL
```

Verify connectivity:

```bash
psql -U threatloom -h 127.0.0.1 -d threatloom -c '\l'
```

### 4a. Alembic schema migration

```bash
cd "$TL_DIR"

APP_ENV=production \
DATABASE_URL="postgresql+asyncpg://threatloom:CHANGE_ME_STRONG_PASSWORD@127.0.0.1:5432/threatloom" \
  .venv/bin/alembic upgrade head
```

Expected output:

```
INFO  [alembic.runtime.migration] Running upgrade  -> 001, initial schema
```

> **Important:** re-run `alembic upgrade head` after every future migration
> before restarting the ThreatLoom service.  The service will refuse to run
> with `APP_ENV=production` if `create_all` would otherwise mutate the schema.

---

## 5. Environment files

### WAF — `$WAF_DIR/.env`

```ini
SECRET_KEY=<openssl rand -hex 32>
DEBUG=false
ENVIRONMENT=production
HOST=127.0.0.1
PORT=5000
```

Permissions:

```bash
chmod 640 "$WAF_DIR/.env"
chown root:vigiledge "$WAF_DIR/.env"
```

### ThreatLoom — `$TL_DIR/.env`

```ini
APP_ENV=production
APP_HOST=127.0.0.1
APP_PORT=8443
APP_DEBUG=false

SECRET_KEY=<openssl rand -hex 32>
JWT_SECRET=<openssl rand -hex 32>

DATABASE_URL=postgresql+asyncpg://threatloom:CHANGE_ME_STRONG_PASSWORD@127.0.0.1:5432/threatloom

LOG_LEVEL=INFO
LOG_FILE=./logs/threatloom.log

# FIREWALL_WEBHOOK_ENABLED=true
# FIREWALL_WEBHOOK_URL=http://127.0.0.1:5000/api/v1/webhook/threatloom
# FIREWALL_WEBHOOK_SECRET=<shared webhook secret>
```

Permissions:

```bash
chmod 640 "$TL_DIR/.env"
chown root:threatloom "$TL_DIR/.env"
```

---

## 6. Systemd service units

Copy the unit files from `deploy/`:

```bash
cp "$APP_ROOT/deploy/vigiledge-waf.service" /etc/systemd/system/
cp "$APP_ROOT/deploy/threatloom.service"     /etc/systemd/system/

systemctl daemon-reload

systemctl enable --now vigiledge-waf
systemctl enable --now threatloom
```

Check status:

```bash
systemctl status vigiledge-waf
systemctl status threatloom

# Tail live logs
journalctl -fu vigiledge-waf
journalctl -fu threatloom
```

---

## 7. Caddy reverse proxy

Copy `deploy/Caddyfile` to `/etc/caddy/Caddyfile` and reload:

```bash
cp "$APP_ROOT/deploy/Caddyfile" /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile   # dry-run check
systemctl reload caddy
```

Caddy obtains a Let's Encrypt TLS certificate automatically on first
request once DNS for your domain points to the server.

---

## 8. Verify the deployment

```bash
# Liveness
curl http://127.0.0.1:5000/health
curl http://127.0.0.1:8443/health

# Readiness
curl http://127.0.0.1:5000/readiness
curl http://127.0.0.1:8443/readiness

# Via Caddy (public HTTPS)
curl https://your.domain.example/health
curl https://your.domain.example/soc/health
```

Both readiness endpoints return `{"status":"ready",...}` when all checks
pass and HTTP 503 with `"status":"not_ready"` if any check fails.

---

## 9. Backup and restore

### 9a. PostgreSQL backup

Daily automated backup (add to root crontab with `crontab -e`):

```bash
# /etc/cron.daily/threatloom-backup
#!/usr/bin/env bash
set -euo pipefail
BACKUP_DIR=/var/backups/threatloom
mkdir -p "$BACKUP_DIR"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
pg_dump -U threatloom -h 127.0.0.1 --format=custom threatloom \
    | gzip > "$BACKUP_DIR/threatloom-${STAMP}.pgdump.gz"
# Retain last 30 days
find "$BACKUP_DIR" -name "*.pgdump.gz" -mtime +30 -delete
```

Make it executable:

```bash
chmod +x /etc/cron.daily/threatloom-backup
```

Test it:

```bash
/etc/cron.daily/threatloom-backup
ls -lh /var/backups/threatloom/
```

### 9b. Restore from backup

```bash
# Stop the service first
systemctl stop threatloom

# Drop and recreate the DB (destructive!)
sudo -u postgres psql -c "DROP DATABASE IF EXISTS threatloom;"
sudo -u postgres psql -c "CREATE DATABASE threatloom OWNER threatloom;"

# Restore
gunzip -c /var/backups/threatloom/threatloom-<STAMP>.pgdump.gz \
    | pg_restore -U threatloom -h 127.0.0.1 -d threatloom

# Re-run migrations to ensure schema matches current code
cd /opt/vigiledge/ThreatLoom
APP_ENV=production .venv/bin/alembic upgrade head

systemctl start threatloom
```

### 9c. WAF config backup

The WAF stores its runtime config in `waf/config/waf_settings.json`.
Include this file in your server snapshot or a simple cron cp:

```bash
cp /opt/vigiledge/project-null-2.0/vigiledge-collage-project--main/VigilEdge/waf/config/waf_settings.json \
   /var/backups/waf_settings_$(date +%Y%m%d).json
```

---

## 10. Log rotation

Both services use `TimedRotatingFileHandler` (midnight UTC, 30-day
retention).  Log files are written to:

| Service | File |
|---------|------|
| WAF | `waf/logs/vigiledge.log` |
| ThreatLoom | `ThreatLoom/logs/threatloom.log` |

Archived files get a `.YYYY-MM-DD` suffix automatically.  No additional
`logrotate` configuration is required, but you may add one for compression:

```
# /etc/logrotate.d/vigiledge
/opt/vigiledge/*/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

---

## 11. Upgrading

```bash
cd /opt/vigiledge
git pull

# ThreatLoom — apply any new migrations
cd ThreatLoom
APP_ENV=production \
DATABASE_URL="postgresql+asyncpg://threatloom:CHANGE_ME@127.0.0.1:5432/threatloom" \
  .venv/bin/alembic upgrade head

# Restart services
systemctl restart vigiledge-waf
systemctl restart threatloom
```

---

## 12. Troubleshooting

| Symptom | Check |
|---------|-------|
| `systemctl status` shows `failed` | `journalctl -xe -u <service>` |
| `GET /readiness` returns 503 | Check the `checks` object in the JSON response |
| ThreatLoom won't start in production | Ensure `DATABASE_URL` points to PostgreSQL (SQLite is rejected in production mode) |
| Alembic `alembic upgrade head` fails | Verify PostgreSQL credentials and that the DB exists |
| Caddy TLS cert not issued | Ensure port 80 is publicly reachable and DNS points to the server |
