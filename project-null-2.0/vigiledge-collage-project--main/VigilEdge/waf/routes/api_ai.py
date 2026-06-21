"""
AI Analysis API Routes for VigilEdge WAF
Handles AI-powered threat analysis statistics and events.
"""

import os
import json
import sqlite3
import logging
import traceback
from fastapi import APIRouter, Request, Depends

from .auth import require_control_plane_access
from vigiledge.utils.rate_limiter import limiter, WRITE, READ, RELAXED

router = APIRouter(prefix="/api/v1", tags=["AI Analysis"], dependencies=[Depends(require_control_plane_access)])


def get_db_path():
    """Get the path to the vulnerable.db database."""
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), "vulnerable.db")


@router.get("/ai-test")
def ai_test():
    """Test endpoint to verify API is working."""
    db_path = get_db_path()
    return {
        "status": "ok",
        "db_path": db_path,
        "db_exists": os.path.exists(db_path)
    }


@router.get("/ai-stats")
@limiter.limit(READ)
def get_ai_stats(request: Request):
    """Get AI analysis statistics."""
    try:
        db_path = get_db_path()
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Total AI scored events
        cursor.execute('SELECT COUNT(*) FROM security_events WHERE json_extract(details, "$.ai") IS NOT NULL')
        total_scored = cursor.fetchone()[0]
        
        # High risk events (score > 0.7)
        cursor.execute('''
            SELECT COUNT(*) FROM security_events 
            WHERE CAST(json_extract(details, "$.ai.ai_score") AS REAL) > 0.7
        ''')
        high_risk = cursor.fetchone()[0]
        
        # Flagged events
        cursor.execute('''
            SELECT COUNT(*) FROM security_events 
            WHERE json_extract(details, "$.ai.flagged") = 1
        ''')
        flagged_count = cursor.fetchone()[0]
        
        # Average AI score
        cursor.execute('''
            SELECT AVG(CAST(json_extract(details, "$.ai.ai_score") AS REAL))
            FROM security_events 
            WHERE json_extract(details, "$.ai") IS NOT NULL
        ''')
        avg_score = cursor.fetchone()[0] or 0
        
        # Score distribution
        cursor.execute('''
            SELECT 
                COUNT(CASE WHEN CAST(json_extract(details, "$.ai.ai_score") AS REAL) <= 0.3 THEN 1 END) as low,
                COUNT(CASE WHEN CAST(json_extract(details, "$.ai.ai_score") AS REAL) > 0.3 
                          AND CAST(json_extract(details, "$.ai.ai_score") AS REAL) <= 0.7 THEN 1 END) as medium,
                COUNT(CASE WHEN CAST(json_extract(details, "$.ai.ai_score") AS REAL) > 0.7 THEN 1 END) as high
            FROM security_events
            WHERE json_extract(details, "$.ai") IS NOT NULL
        ''')
        distribution = cursor.fetchone()
        
        # Timeline data (last 24 hours)
        cursor.execute('''
            SELECT 
                strftime('%H:00', timestamp) as hour,
                AVG(CAST(json_extract(details, "$.ai.ai_score") AS REAL)) as avg_score
            FROM security_events
            WHERE json_extract(details, "$.ai") IS NOT NULL
                AND datetime(timestamp) >= datetime('now', '-24 hours')
            GROUP BY hour
            ORDER BY timestamp
            LIMIT 24
        ''')
        timeline_data = cursor.fetchall()
        
        conn.close()
        
        return {
            "total_scored": total_scored,
            "high_risk": high_risk,
            "flagged_count": flagged_count,
            "avg_score": avg_score,
            "score_distribution": {
                "low": distribution[0],
                "medium": distribution[1],
                "high": distribution[2]
            },
            "timeline": {
                "labels": [row[0] for row in timeline_data],
                "scores": [row[1] for row in timeline_data]
            }
        }
    except Exception as e:
        error_details = traceback.format_exc()
        logging.error(f"AI Stats error: {e}\n{error_details}")
        return {
            "total_scored": 0,
            "high_risk": 0,
            "flagged_count": 0,
            "avg_score": 0,
            "score_distribution": {"low": 0, "medium": 0, "high": 0},
            "timeline": {"labels": [], "scores": []}
        }


@router.get("/ai-events")
@limiter.limit(READ)
def get_ai_events(request: Request, limit: int = 20, offset: int = 0):
    """Get events with AI analysis data."""
    try:
        db_path = get_db_path()
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT event_id, timestamp, threat_type, threat_level, ip, url, user_agent, action, blocked, details
            FROM security_events
            WHERE json_extract(details, "$.ai") IS NOT NULL
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        ''', (limit, offset))
        
        events = []
        for row in cursor.fetchall():
            events.append({
                "event_id": row[0],
                "timestamp": row[1],
                "threat_type": row[2],
                "threat_level": row[3],
                "ip": row[4],
                "url": row[5],
                "user_agent": row[6],
                "action": row[7],
                "blocked": bool(row[8]),
                "details": json.loads(row[9]) if row[9] else {}
            })
        
        conn.close()
        
        return {"events": events, "total": len(events), "limit": limit, "offset": offset}
    except Exception as e:
        logging.error(f"AI Events error: {e}\n{traceback.format_exc()}")
        return {"events": [], "total": 0, "limit": limit, "offset": offset}


# ==================== AI SCORER SWITCHING ENDPOINTS ====================

@router.get("/ai-scorer/config")
@limiter.limit(READ)
def get_scorer_config(request: Request):
    """Get current AI scorer configuration and status."""
    try:
        from vigiledge.core.ai_scoring import get_unified_scorer
        scorer = get_unified_scorer()
        config = scorer.get_config()
        return {
            "success": True,
            "config": config,
            "available_scorers": ["heuristic", "lm_studio", "hybrid"],
            "descriptions": {
                "heuristic": "Fast rule-based scoring (no external dependencies)",
                "lm_studio": "AI-powered scoring using local LLM (requires LM Studio)",
                "hybrid": "Combines both methods for best accuracy"
            }
        }
    except Exception as e:
        logging.error(f"Get scorer config error: {e}")
        return {"success": False, "error": str(e)}


@router.post("/ai-scorer/switch")
@limiter.limit(WRITE)
def switch_scorer(request: Request, data: dict):
    """Switch between AI scoring methods.
    
    Body: {"scorer_type": "heuristic" | "lm_studio" | "hybrid"}
    """
    try:
        from vigiledge.core.ai_scoring import get_unified_scorer
        scorer_type = data.get("scorer_type", "heuristic")
        
        scorer = get_unified_scorer()
        result = scorer.set_active_scorer(scorer_type)
        
        if result.get("success"):
            return {
                "success": True,
                "message": f"Switched to {scorer_type} scorer",
                "active_scorer": scorer_type,
                "config": scorer.get_config()
            }
        else:
            return {"success": False, "error": result.get("error")}
    except Exception as e:
        logging.error(f"Switch scorer error: {e}")
        return {"success": False, "error": str(e)}


@router.get("/ai-scorer/check-lm-studio")
@limiter.limit(RELAXED)
def check_lm_studio(request: Request):
    """Check if LM Studio is available and running."""
    try:
        from vigiledge.core.ai_scoring import get_unified_scorer
        scorer = get_unified_scorer()
        is_available = scorer.check_lm_studio()
        
        return {
            "success": True,
            "lm_studio_available": is_available,
            "message": "LM Studio is running and ready" if is_available else "LM Studio is not available. Please start it on port 1234.",
            "endpoint": "http://localhost:1234"
        }
    except Exception as e:
        logging.error(f"Check LM Studio error: {e}")
        return {"success": False, "lm_studio_available": False, "error": str(e)}


@router.post("/ai-scorer/test")
@limiter.limit(WRITE)
def test_scorer(request: Request, data: dict):
    """Test the current scorer with a sample event.
    
    Body: {"threat_type": "sql_injection", "url": "/test?id=1", ...}
    """
    try:
        from vigiledge.core.ai_scoring import get_unified_scorer
        
        # Create a mock event from the data
        class MockEvent:
            def __init__(self, data):
                self.threat_type = data.get("threat_type", "test")
                self.source_ip = data.get("source_ip", "127.0.0.1")
                self.url = data.get("url", "/test")
                self.user_agent = data.get("user_agent", "Test-Agent")
                self.method = data.get("method", "GET")
                self.blocked = data.get("blocked", False)
                self.details = data.get("details", {})
        
        event = MockEvent(data)
        scorer = get_unified_scorer()
        result = scorer.score_event(event)
        
        return {
            "success": True,
            "score_result": result,
            "active_scorer": scorer.get_active_scorer()
        }
    except Exception as e:
        logging.error(f"Test scorer error: {e}")
        return {"success": False, "error": str(e)}
