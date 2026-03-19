"""
Health and readiness endpoints for ThreatLoom.

GET /health    — liveness: process is up and can serve requests.
GET /readiness — readiness: DB, background workers, and key resources are ready.

Both are intentionally unauthenticated so reverse proxies and process managers
(Caddy, systemd-healthcheck, Kubernetes probes) can reach them without tokens.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from threatloom.database import check_db_connection

router = APIRouter(tags=["Ops"])


@router.get("/health", include_in_schema=False)
async def health() -> dict:
    """Liveness probe — returns 200 as long as the process is running."""
    return {
        "status": "ok",
        "service": "threatloom",
        "ts": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/readiness", include_in_schema=False)
async def readiness(request: Request) -> JSONResponse:
    """
    Readiness probe — returns 200 when all critical dependencies are usable,
    503 otherwise.

    Checks:
      • database reachable
      • detection engine background task running
      • retention manager background task running
    """
    checks: dict[str, str] = {}
    overall_ok = True

    # ── database ──────────────────────────────────────────────────────────────
    db_ok = await check_db_connection()
    checks["database"] = "ok" if db_ok else "unreachable"
    if not db_ok:
        overall_ok = False

    # ── detection engine ──────────────────────────────────────────────────────
    engine = getattr(request.app.state, "detection_engine", None)
    if engine is not None:
        checks["detection_engine"] = "ok"
    else:
        checks["detection_engine"] = "not_started"
        overall_ok = False

    # ── retention manager ─────────────────────────────────────────────────────
    retention = getattr(request.app.state, "retention_manager", None)
    if retention is not None:
        checks["retention_manager"] = "ok"
    else:
        checks["retention_manager"] = "not_started"
        overall_ok = False

    status_code = 200 if overall_ok else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "ready" if overall_ok else "not_ready",
            "service": "threatloom",
            "ts": datetime.now(timezone.utc).isoformat(),
            "checks": checks,
        },
    )
