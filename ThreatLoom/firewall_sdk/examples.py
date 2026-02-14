"""
============================================================================
EXAMPLE: Integrating your firewall with ThreatLoom SOC
============================================================================

Copy `firewall_sdk/threatloom_sdk.py` into your firewall project.
Then pick ONE of the patterns below depending on your firewall's architecture.

Prerequisites:
    pip install httpx
============================================================================
"""

# ══════════════════════════════════════════════════════════════════════════
# PATTERN 1 — Simple synchronous (works anywhere)
# ══════════════════════════════════════════════════════════════════════════

from threatloom_sdk import ThreatLoomClient

soc = ThreatLoomClient(
    soc_url="http://localhost:8443",
    username="admin",
    password="changeme",
)


def on_request_processed(request, response, verdict):
    """
    Call this after your firewall processes every request.
    'verdict' is your firewall's decision dict.
    """
    soc.send_log({
        # ── Required ──
        "src_ip":       request.client_ip,

        # ── Recommended ──
        "dst_ip":       request.server_ip,
        "src_port":     request.client_port,
        "dst_port":     request.server_port,
        "protocol":     "TCP",

        # ── HTTP fields ──
        "http_method":  request.method,           # GET, POST, PUT …
        "http_path":    request.path,             # /api/users
        "http_status":  response.status_code,     # 200, 403, 502 …
        "user_agent":   request.headers.get("User-Agent", ""),

        # ── Firewall verdict ──
        "action":       verdict["action"],        # ALLOWED | BLOCKED | RATE_LIMITED | DROPPED
        "attack_type":  verdict.get("attack"),    # SQLI | XSS | RCE | BRUTE_FORCE | NONE …
        "severity":     verdict.get("severity"),  # INFO | LOW | MEDIUM | HIGH | CRITICAL
        "rule_id":      verdict.get("rule_id"),   # your firewall rule that matched

        # ── Optional extras ──
        "raw_message":  verdict.get("raw_log"),   # original log line if you have one
    })


# ══════════════════════════════════════════════════════════════════════════
# PATTERN 2 — Fire-and-forget background thread (non-blocking)
# ══════════════════════════════════════════════════════════════════════════

def start_firewall_with_soc():
    soc = ThreatLoomClient(
        soc_url="http://localhost:8443",
        username="admin",
        password="changeme",
        batch_size=50,          # send every 50 logs
        flush_interval=5.0,    # or every 5 seconds
    )
    soc.start_background()     # spawns a daemon thread

    # In your request handler loop:
    # soc.queue_log({ ... })   # non-blocking, never slows your firewall

    # On shutdown:
    # soc.stop_background()


# ══════════════════════════════════════════════════════════════════════════
# PATTERN 3 — Async firewall (if you use asyncio / aiohttp / FastAPI)
# ══════════════════════════════════════════════════════════════════════════

import asyncio
from threatloom_sdk import AsyncThreatLoomClient


async def async_firewall_loop():
    soc = AsyncThreatLoomClient(
        soc_url="http://localhost:8443",
        username="admin",
        password="changeme",
    )

    # Every time your firewall processes a request:
    await soc.send_log({
        "src_ip": "192.168.1.100",
        "action": "BLOCKED",
        "attack_type": "SQLI",
        "http_method": "POST",
        "http_path": "/api/data",
        "http_status": 403,
        "severity": "HIGH",
    })

    await soc.close()


# ══════════════════════════════════════════════════════════════════════════
# PATTERN 4 — Poll ThreatLoom for block lists (sync the blocklist back)
# ══════════════════════════════════════════════════════════════════════════

def sync_blocklist():
    """
    Call periodically (e.g. every 30s) to pull active blocks from ThreatLoom
    and apply them in your firewall.
    """
    soc = ThreatLoomClient(soc_url="http://localhost:8443")
    active = soc.get_active_blocks()

    blocked_ips = set()
    for response in active:
        if response.get("action") in ("IP_BLOCK", "TEMP_BAN"):
            ip = response.get("target_ip")
            if ip:
                blocked_ips.add(ip)

    # Apply to your firewall:
    # my_firewall.update_blocklist(blocked_ips)
    print(f"Synced {len(blocked_ips)} blocked IPs from ThreatLoom")


# ══════════════════════════════════════════════════════════════════════════
# PATTERN 5 — Webhook receiver (ThreatLoom pushes TO your firewall)
# ══════════════════════════════════════════════════════════════════════════
#
# Configure FIREWALL_WEBHOOK_URL in ThreatLoom's .env:
#   FIREWALL_WEBHOOK_URL=http://your-firewall:9090/soc-webhook
#   FIREWALL_WEBHOOK_SECRET=shared-secret-key
#
# Then add this endpoint to your firewall:

"""
from fastapi import FastAPI, Request, HTTPException

firewall_app = FastAPI()

WEBHOOK_SECRET = "shared-secret-key"

@firewall_app.post("/soc-webhook")
async def soc_webhook(request: Request):
    # Verify secret
    if request.headers.get("X-ThreatLoom-Secret") != WEBHOOK_SECRET:
        raise HTTPException(status_code=403, detail="Invalid secret")

    payload = await request.json()
    action = payload["action"]     # "BLOCK_IP", "RATE_LIMIT", "UNBLOCK_IP", ...
    target = payload["target_ip"]
    reason = payload.get("reason", "")
    duration = payload.get("duration_minutes", 60)

    if action == "BLOCK_IP":
        my_firewall.block_ip(target, duration_minutes=duration)
    elif action == "UNBLOCK_IP":
        my_firewall.unblock_ip(target)
    elif action == "RATE_LIMIT":
        rps = payload.get("rate_limit_rps", 10)
        my_firewall.rate_limit(target, rps=rps, duration_minutes=duration)

    return {"status": "applied", "action": action, "target": target}
"""


# ══════════════════════════════════════════════════════════════════════════
# FIELD REFERENCE — What fields ThreatLoom accepts
# ══════════════════════════════════════════════════════════════════════════
#
# Field              Type      Example              Notes
# ─────────────────  ────────  ───────────────────  ──────────────────────────
# src_ip             str       "192.168.1.100"      REQUIRED — attacker IP
# dst_ip             str       "10.0.0.1"           destination/server IP
# src_port           int       54321                source port
# dst_port           int       443                  destination port
# protocol           str       "TCP"                TCP | UDP | HTTP | HTTPS
# http_method        str       "POST"               GET | POST | PUT | DELETE …
# http_path          str       "/api/login"         request path
# http_status        int       403                  HTTP response status
# user_agent         str       "Mozilla/..."        User-Agent header
# action             str       "BLOCKED"            ALLOWED | BLOCKED | RATE_LIMITED | DROPPED
# attack_type        str       "SQLI"               NONE | SQLI | XSS | RCE | LFI | BRUTE_FORCE
#                                                   PORT_SCAN | DDOS | SSRF | BOT | CSRF | XXE
#                                                   COMMAND_INJECTION | DIRECTORY_TRAVERSAL
#                                                   CREDENTIAL_STUFFING
# severity           str       "HIGH"               INFO | LOW | MEDIUM | HIGH | CRITICAL
# rule_id            str       "waf-rule-042"       your firewall rule ID
# raw_message        str       "full log line"      original log text
# geo_country        str       "US"                 auto-resolved if missing
# timestamp          str       ISO 8601             auto-set to now if missing
