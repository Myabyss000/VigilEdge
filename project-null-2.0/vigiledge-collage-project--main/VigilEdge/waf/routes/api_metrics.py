"""
Metrics API Routes for VigilEdge WAF
Handles WAF performance metrics and threat statistics.
"""

import logging
from collections import Counter
from fastapi import APIRouter, Depends

from .auth import require_control_plane_access

router = APIRouter(prefix="/api/v1", tags=["Metrics"], dependencies=[Depends(require_control_plane_access)])


def get_waf_engine():
    """Get WAF engine from app state."""
    from app import waf_engine
    return waf_engine


def get_ws_manager():
    """Get WebSocket manager from app state."""
    from services.websocket_manager import manager
    return manager


@router.get("/threats")
async def api_get_threats():
    """API endpoint to get threat statistics by type."""
    try:
        waf_engine = get_waf_engine()
        threat_counts = Counter()
        
        for event in waf_engine.security_events:
            threat_type = event.threat_type
            if threat_type and threat_type != "none":
                threat_counts[threat_type] += 1
        
        # Format as required by frontend
        threat_data = {}
        for threat_type, count in threat_counts.items():
            threat_data[threat_type] = {"count": count}
        
        return {
            "success": True,
            "threat_counts": threat_data,
            "total_threats": sum(threat_counts.values())
        }
    except Exception as e:
        logging.error(f"Error getting threat statistics: {e}")
        return {"success": False, "threat_counts": {}, "total_threats": 0}


@router.get("/metrics")
async def api_get_metrics():
    """API endpoint to get WAF performance metrics."""
    try:
        waf_engine = get_waf_engine()
        manager = get_ws_manager()
        metrics = waf_engine.metrics
        
        # Calculate average response time
        avg_response = metrics.avg_response_time if hasattr(metrics, 'avg_response_time') else 0.012
        
        return {
            "success": True,
            "total_requests": metrics.total_requests,
            "blocked_requests": metrics.blocked_requests,
            "allowed_requests": metrics.allowed_requests,
            "threats_detected": metrics.threats_detected,
            "avg_response_time": avg_response,
            "uptime_seconds": metrics.uptime_seconds if hasattr(metrics, 'uptime_seconds') else 0,
            "incoming_bytes": metrics.incoming_bytes if hasattr(metrics, 'incoming_bytes') else 0,
            "outgoing_bytes": metrics.outgoing_bytes if hasattr(metrics, 'outgoing_bytes') else 0,
            "active_connections": len(manager.active_connections)
        }
    except Exception as e:
        logging.error(f"Error getting metrics: {e}")
        return {
            "success": False,
            "total_requests": 0,
            "blocked_requests": 0,
            "allowed_requests": 0,
            "threats_detected": 0,
            "avg_response_time": 0,
            "uptime_seconds": 0
        }
