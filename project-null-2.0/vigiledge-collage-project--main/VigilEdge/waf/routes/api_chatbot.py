"""
Chatbot API Routes for VigilEdge WAF
Provides read-only API endpoints for chatbot integration and AI chat functionality.
"""

import os
import sqlite3
import logging
import traceback
from typing import List
from fastapi import APIRouter
from pydantic import BaseModel
import httpx

router = APIRouter(tags=["Chatbot"])


def get_waf_engine():
    """Get WAF engine from app state."""
    from app import waf_engine
    return waf_engine


def get_ws_manager():
    """Get WebSocket manager from app state."""
    from services.websocket_manager import manager
    return manager


def get_db_path():
    """Get the path to the database."""
    waf_engine = get_waf_engine()
    return waf_engine.db_path


class ChatRequest(BaseModel):
    """Chat message request model."""
    message: str
    conversation_history: List[dict] = []


# ==================== CHATBOT READ-ONLY ENDPOINTS ====================

@router.get("/api/waf/stats")
async def get_waf_stats():
    """Get current WAF statistics for chatbot."""
    try:
        waf_engine = get_waf_engine()
        manager = get_ws_manager()
        
        conn = sqlite3.connect(waf_engine.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                COUNT(*) as total_events,
                SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked_count,
                COUNT(DISTINCT threat_type) as unique_threats,
                COUNT(DISTINCT ip) as unique_ips
            FROM security_events
            WHERE timestamp > datetime('now', '-24 hours')
        """)
        stats = cursor.fetchone()
        
        active_connections = len(manager.active_connections)
        conn.close()
        
        return {
            "success": True,
            "data": {
                "threats_blocked": stats[1] or 0,
                "active_scans": active_connections,
                "requests_allowed": (stats[0] or 0) - (stats[1] or 0),
                "total_events": stats[0] or 0,
                "unique_threats": stats[2] or 0,
                "unique_ips": stats[3] or 0,
                "total_requests": waf_engine.metrics.total_requests,
                "blocked_requests": waf_engine.metrics.blocked_requests
            }
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/api/waf/threats")
async def get_recent_threats():
    """Get recent threat events for chatbot."""
    try:
        waf_engine = get_waf_engine()
        conn = sqlite3.connect(waf_engine.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                event_id, timestamp, threat_type, threat_level, 
                ip, url, action, blocked, details
            FROM security_events
            WHERE blocked = 1
            ORDER BY timestamp DESC
            LIMIT 20
        """)
        
        threats = []
        for row in cursor.fetchall():
            threats.append({
                "event_id": row[0],
                "timestamp": row[1],
                "threat_type": row[2],
                "threat_level": row[3],
                "ip": row[4],
                "url": row[5],
                "action": row[6],
                "blocked": row[7],
                "details": row[8]
            })
        
        conn.close()
        return {"success": True, "data": threats}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/api/waf/blocked_ips")
async def get_blocked_ips_api():
    """Get list of blocked IPs for chatbot."""
    try:
        waf_engine = get_waf_engine()
        conn = sqlite3.connect(waf_engine.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT DISTINCT ip, COUNT(*) as block_count
            FROM security_events
            WHERE blocked = 1
            GROUP BY ip
            ORDER BY block_count DESC
        """)
        
        blocked_ips = []
        for row in cursor.fetchall():
            blocked_ips.append({
                "ip": row[0],
                "block_count": row[1]
            })
        
        conn.close()
        
        return {
            "success": True,
            "data": {
                "blocked_ips": blocked_ips,
                "total_count": len(blocked_ips)
            }
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/api/waf/security_rules")
async def get_security_rules_api():
    """Get active security rules for chatbot."""
    try:
        waf_engine = get_waf_engine()
        rules = waf_engine.rules_config.get("rules", [])
        
        active_rules = [
            {
                "id": rule.get("id"),
                "name": rule.get("name"),
                "category": rule.get("category"),
                "severity": rule.get("severity"),
                "enabled": rule.get("enabled", True),
                "description": rule.get("description", "")
            }
            for rule in rules if rule.get("enabled", True)
        ]
        
        return {
            "success": True,
            "data": {
                "rules": active_rules,
                "total_active": len(active_rules),
                "total_rules": len(rules)
            }
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/api/waf/events")
async def get_recent_events_api():
    """Get recent security events for chatbot."""
    try:
        waf_engine = get_waf_engine()
        conn = sqlite3.connect(waf_engine.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                event_id, timestamp, threat_type, threat_level,
                ip, url, user_agent, action, blocked, details
            FROM security_events
            ORDER BY timestamp DESC
            LIMIT 50
        """)
        
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
                "blocked": row[8],
                "details": row[9]
            })
        
        conn.close()
        return {"success": True, "data": events}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/api/waf/network_monitor")
async def get_network_monitor_data():
    """Get network monitor data for chatbot."""
    try:
        waf_engine = get_waf_engine()
        manager = get_ws_manager()
        active_ws_count = len(manager.active_connections)
        
        conn = sqlite3.connect(waf_engine.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip, COUNT(*) as requests, MAX(timestamp) as last_seen
            FROM security_events
            WHERE timestamp > datetime('now', '-1 hour')
            GROUP BY ip
            ORDER BY requests DESC
            LIMIT 20
        """)
        
        active_conns = []
        for row in cursor.fetchall():
            active_conns.append({
                "ip": row[0],
                "requests": row[1],
                "last_seen": row[2],
                "status": "active"
            })
        
        conn.close()
        
        return {
            "success": True,
            "data": {
                "active_connections": active_conns,
                "total_active": len(active_conns),
                "websocket_connections": active_ws_count
            }
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/api/waf/threat_summary")
async def get_threat_summary():
    """Get threat summary statistics for chatbot."""
    try:
        waf_engine = get_waf_engine()
        conn = sqlite3.connect(waf_engine.db_path)
        cursor = conn.cursor()
        
        # Get threat breakdown
        cursor.execute("""
            SELECT threat_type, COUNT(*) as count
            FROM security_events
            WHERE blocked = 1 AND timestamp > datetime('now', '-24 hours')
            GROUP BY threat_type
            ORDER BY count DESC
        """)
        
        threat_breakdown = []
        for row in cursor.fetchall():
            threat_breakdown.append({
                "threat_type": row[0],
                "count": row[1]
            })
        
        # Get hourly trend
        cursor.execute("""
            SELECT 
                strftime('%H', timestamp) as hour,
                COUNT(*) as count
            FROM security_events
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY hour
            ORDER BY hour DESC
        """)
        
        hourly_data = []
        for row in cursor.fetchall():
            hourly_data.append({
                "hour": row[0],
                "count": row[1]
            })
        
        conn.close()
        
        return {
            "success": True,
            "data": {
                "threat_breakdown": threat_breakdown,
                "hourly_trend": hourly_data
            }
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ==================== AI CHAT ENDPOINTS ====================

@router.get("/api/v1/chat-test")
async def chat_test():
    """Simple test endpoint."""
    return {"status": "ok", "message": "Chat endpoint is working!"}


@router.post("/api/v1/chat-test-post")
async def chat_test_post(data: dict):
    """Test if POST works."""
    return {"status": "ok", "received": data}


@router.post("/api/v1/chat")
async def chat_with_ai(chat_req: ChatRequest):
    """AI Security Assistant powered by LM Studio."""
    try:
        waf_engine = get_waf_engine()
        
        # Query database for context
        db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vulnerable.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get recent security stats
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked,
                COUNT(DISTINCT threat_type) as threat_types
            FROM security_events
            WHERE timestamp > datetime('now', '-24 hours')
        """)
        stats = cursor.fetchone()
        
        # Get recent high-risk events
        cursor.execute("""
            SELECT threat_type, COUNT(*) as count
            FROM security_events
            WHERE blocked = 1 AND timestamp > datetime('now', '-24 hours')
            GROUP BY threat_type
            ORDER BY count DESC
            LIMIT 5
        """)
        threats = cursor.fetchall()
        conn.close()
        
        # Build system context
        system_context = f"""You are VigilEdge AI Security Assistant, an expert in cybersecurity and web application firewalls.

Current System Status:
- Total events (24h): {stats[0] if stats else 0}
- Blocked attacks (24h): {stats[1] if stats else 0}
- Active threat types: {stats[2] if stats else 0}

Recent Threats: {', '.join([f"{t[0]}({t[1]})" for t in threats]) if threats else "None"}

Your capabilities:
1. Explain security concepts (XSS, SQL injection, CSRF, etc.)
2. Analyze attack patterns and provide insights
3. Answer questions about the firewall's AI scoring system
4. Provide security recommendations

Be concise, technical, and helpful. Use emojis sparingly for emphasis."""

        # Call LM Studio API
        lm_studio_url = "http://localhost:1234/v1/chat/completions"
        
        messages = [{"role": "system", "content": system_context}]
        messages.extend(chat_req.conversation_history[-5:])
        messages.append({"role": "user", "content": chat_req.message})
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                lm_studio_url,
                json={
                    "messages": messages,
                    "temperature": 0.7,
                    "max_tokens": 500,
                    "stream": False
                },
                timeout=120.0
            )
        
        if response.status_code == 200:
            result = response.json()
            ai_response = result["choices"][0]["message"]["content"]
            
            return {
                "success": True,
                "response": ai_response,
                "stats": {
                    "total_events": stats[0] if stats else 0,
                    "blocked": stats[1] if stats else 0
                }
            }
        else:
            return {
                "success": False,
                "error": "LM Studio not responding. Please ensure it's running on port 1234.",
                "response": "I'm currently offline. Please start LM Studio and load a model."
            }
            
    except httpx.ConnectError as e:
        return {
            "success": False,
            "error": "Cannot connect to LM Studio",
            "response": "⚠️ I can't connect to LM Studio. Please:\n1. Open LM Studio\n2. Load a model (Phi-3 recommended)\n3. Start the Local Server (port 1234)\n\nThen try again!"
        }
    except httpx.ReadTimeout as e:
        return {
            "success": False,
            "error": "LM Studio taking too long",
            "response": "⏱️ The model is taking too long to respond. This might mean:\n1. Model is still loading\n2. Prompt is too complex\n3. System is under load\n\nTry a simpler question or wait a moment."
        }
    except Exception as e:
        logging.error(f"Chat error: {type(e).__name__} - {e}\n{traceback.format_exc()}")
        return {
            "success": False,
            "error": str(e),
            "response": "An error occurred while processing your request."
        }
