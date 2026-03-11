"""
Event Logs API Routes for VigilEdge WAF
Handles security event log retrieval.
"""

import logging
from fastapi import APIRouter, Depends

from .auth import require_control_plane_access

router = APIRouter(prefix="/api/v1", tags=["Event Logs"], dependencies=[Depends(require_control_plane_access)])


def get_waf_engine():
    """Get WAF engine from app state."""
    from app import waf_engine
    return waf_engine


@router.get("/event-logs")
async def api_get_event_logs(limit: int = 50):
    """API endpoint to get recent security event logs."""
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
            "error": str(e),
            "events": [],
            "total": 0
        }
