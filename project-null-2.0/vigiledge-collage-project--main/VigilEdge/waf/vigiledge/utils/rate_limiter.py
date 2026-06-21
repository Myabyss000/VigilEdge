"""
VigilEdge WAF - Centralized API Rate Limiter
Uses slowapi to enforce per-endpoint rate limits across all API routes.

Rate limit tiers:
  - STRICT:  Brute-force sensitive endpoints (login, bootstrap, password reset)
  - WRITE:   State-changing operations (block IP, save settings, clear data)
  - READ:    Data retrieval endpoints (metrics, events, logs)
  - RELAXED: Dashboard polling endpoints that auto-refresh frequently
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# Single shared limiter instance — imported by all route modules
limiter = Limiter(key_func=get_remote_address)

# ── Named rate limit tiers ──────────────────────────────────────────
# These strings are passed to @limiter.limit() decorators.

STRICT = "5/minute"       # Login, bootstrap, password reset
WRITE = "30/minute"       # Block/unblock IP, save settings, toggle rules
READ = "60/minute"        # Events, metrics, threats, analytics
RELAXED = "120/minute"    # Dashboard auto-refresh polling, health checks
