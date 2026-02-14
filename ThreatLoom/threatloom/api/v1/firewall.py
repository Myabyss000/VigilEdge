"""
Firewall status endpoint - checks connectivity with the external firewall/WAF.
"""
import logging
from datetime import datetime

import httpx
from fastapi import APIRouter, Request

from threatloom.config import settings

router = APIRouter()
logger = logging.getLogger("threatloom.api.firewall")


@router.get("/status")
async def firewall_status(request: Request):
    """
    Check the current connectivity status with the external firewall.
    Returns health info and webhook config status.
    """
    result = {
        "webhook_enabled": settings.FIREWALL_WEBHOOK_ENABLED,
        "webhook_url": settings.FIREWALL_WEBHOOK_URL or None,
        "health_url": settings.FIREWALL_HEALTH_URL,
        "connected": False,
        "response_time_ms": None,
        "firewall_status_code": None,
        "checked_at": datetime.utcnow().isoformat(),
        "error": None,
    }

    if not settings.FIREWALL_WEBHOOK_ENABLED:
        result["error"] = "Firewall webhook integration is disabled"
        return result

    try:
        start = datetime.utcnow()
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(settings.FIREWALL_HEALTH_URL)
        elapsed = (datetime.utcnow() - start).total_seconds() * 1000

        result["connected"] = resp.status_code < 500
        result["response_time_ms"] = round(elapsed, 1)
        result["firewall_status_code"] = resp.status_code
    except httpx.ConnectError:
        result["error"] = f"Cannot connect to firewall at {settings.FIREWALL_HEALTH_URL}"
    except httpx.TimeoutException:
        result["error"] = "Firewall health check timed out"
    except Exception as e:
        result["error"] = str(e)

    return result
