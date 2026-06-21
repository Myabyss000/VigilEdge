"""
Event Logs API Routes for VigilEdge WAF
Handles security event log retrieval.
"""

import logging
from fastapi import APIRouter, Request, Depends

from .auth import require_control_plane_access
from vigiledge.utils.rate_limiter import limiter, READ

router = APIRouter(prefix="/api/v1", tags=["Event Logs"], dependencies=[Depends(require_control_plane_access)])


def get_waf_engine():
    """Get WAF engine from app state."""
    from app import waf_engine
    return waf_engine


@router.get("/event-logs")
@limiter.limit(READ)
async def api_get_event_logs(request: Request, limit: int = 50):
    """API endpoint to get recent security event logs."""
    # Enforce hard cap to prevent resource exhaustion attacks
    limit = min(max(1, limit), 1000)
    
    try:
        waf_engine = get_waf_engine()
        events = await waf_engine.get_recent_events(limit=limit)
        
        return {
            "success": True,
            "events": events,
            "total": len(events)
        }
    except Exception as e:
        logging.error(f"Error getting event logs: {e}")
        return {
            "success": False,
            "error": "An internal server error occurred while processing your request.",
            "events": [],
            "total": 0
        }
