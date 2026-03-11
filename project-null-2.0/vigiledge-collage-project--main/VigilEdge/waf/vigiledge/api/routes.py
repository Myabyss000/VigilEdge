"""
API Routes for VigilEdge WAF
Defines REST API endpoints for managing the WAF
"""

from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.responses import JSONResponse
from typing import Dict, List, Any, Optional
from datetime import datetime
import json

# Import types (will work once dependencies are installed)
try:
    from fastapi.security import HTTPAuthorizationCredentials
except ImportError:
    HTTPAuthorizationCredentials = None

from ..core.waf_engine import WAFEngine, ThreatLevel, ActionType
from ..core.security_manager import SecurityRule
from routes.auth import require_control_plane_access


def setup_routes(app, waf_engine: WAFEngine, websocket_manager):
    """Setup all API routes"""
    
    # Create API router
    api_v1 = APIRouter(prefix="/api/v1", tags=["WAF API"], dependencies=[Depends(require_control_plane_access)])
    
    @api_v1.get("/metrics")
    async def get_metrics():
        """Get WAF performance metrics"""
        try:
            metrics = await waf_engine.get_metrics()
            return JSONResponse(content=metrics)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.get("/events")
    async def get_recent_events(limit: int = 100):
        """Get recent security events"""
        try:
            events = await waf_engine.get_recent_events(limit=limit)
            # Return events directly as array for dashboard compatibility
            return JSONResponse(content=events)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.get("/blocked-ips")
    async def get_blocked_ips():
        """Get list of blocked IP addresses"""
        try:
            blocked_ips = await waf_engine.get_blocked_ips()
            return JSONResponse(content={"blocked_ips": blocked_ips, "count": len(blocked_ips)})
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.get("/threats")
    async def get_threats():
        """Get threat statistics and recent threats"""
        try:
            # Query database for threat counts by type
            import sqlite3
            conn = sqlite3.connect(waf_engine.db_path)
            cursor = conn.cursor()
            
            # Count threats by type
            cursor.execute("""
                SELECT threat_type, threat_level, COUNT(*) as count
                FROM security_events
                WHERE blocked = 1
                GROUP BY threat_type, threat_level
            """)
            threat_counts = {}
            for threat_type, threat_level, count in cursor.fetchall():
                threat_counts[threat_type] = {
                    "count": count,
                    "level": threat_level
                }
            
            # Get recent threats with details
            cursor.execute("""
                SELECT event_id, timestamp, threat_type, threat_level, ip, url, details
                FROM security_events
                WHERE blocked = 1
                ORDER BY timestamp DESC
                LIMIT 10
            """)
            recent_threats = []
            for row in cursor.fetchall():
                recent_threats.append({
                    "event_id": row[0],
                    "timestamp": row[1],
                    "threat_type": row[2],
                    "threat_level": row[3],
                    "ip": row[4],
                    "url": row[5],
                    "details": json.loads(row[6]) if row[6] else {}
                })
            
            conn.close()
            
            return JSONResponse(content={
                "threat_counts": threat_counts,
                "recent_threats": recent_threats,
                "total_blocked": sum(t["count"] for t in threat_counts.values())
            })
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.get("/analytics")
    async def get_analytics():
        """Get analytics data for charts and visualizations"""
        try:
            import sqlite3
            from collections import defaultdict
            
            conn = sqlite3.connect(waf_engine.db_path)
            cursor = conn.cursor()
            
            # Traffic over time (hourly for last 24 hours)
            cursor.execute("""
                SELECT strftime('%H:00', timestamp) as hour, 
                       COUNT(*) as total_requests,
                       SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked_requests
                FROM security_events
                WHERE timestamp >= datetime('now', '-24 hours')
                GROUP BY hour
                ORDER BY hour
            """)
            traffic_by_hour = [{"hour": row[0], "total": row[1], "blocked": row[2]} for row in cursor.fetchall()]
            
            # Attack types distribution
            cursor.execute("""
                SELECT threat_type, COUNT(*) as count
                FROM security_events
                WHERE blocked = 1
                GROUP BY threat_type
                ORDER BY count DESC
            """)
            attack_types = [{"type": row[0], "count": row[1]} for row in cursor.fetchall()]
            
            # Top attacking IPs
            cursor.execute("""
                SELECT ip, COUNT(*) as attack_count
                FROM security_events
                WHERE blocked = 1 AND ip IS NOT NULL
                GROUP BY ip
                ORDER BY attack_count DESC
                LIMIT 10
            """)
            top_ips = [{"ip": row[0], "count": row[1]} for row in cursor.fetchall()]
            
            # Threat severity distribution
            cursor.execute("""
                SELECT threat_level, COUNT(*) as count
                FROM security_events
                WHERE blocked = 1
                GROUP BY threat_level
            """)
            severity_dist = [{"level": row[0], "count": row[1]} for row in cursor.fetchall()]
            
            conn.close()
            
            return JSONResponse(content={
                "traffic_by_hour": traffic_by_hour,
                "attack_types": attack_types,
                "top_attacking_ips": top_ips,
                "severity_distribution": severity_dist
            })
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.get("/event-logs")
    async def get_event_logs(limit: int = 100, offset: int = 0, threat_type: str = None, blocked_only: bool = False):
        """Get detailed event logs with filtering and pagination"""
        try:
            import sqlite3
            conn = sqlite3.connect(waf_engine.db_path)
            cursor = conn.cursor()
            
            # Build query with filters
            query = "SELECT event_id, timestamp, threat_type, threat_level, ip, url, user_agent, action, blocked, details FROM security_events WHERE 1=1"
            params = []
            
            if threat_type:
                query += " AND threat_type = ?"
                params.append(threat_type)
            
            if blocked_only:
                query += " AND blocked = 1"
            
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
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
            
            # Get total count for pagination
            count_query = "SELECT COUNT(*) FROM security_events WHERE 1=1"
            count_params = []
            if threat_type:
                count_query += " AND threat_type = ?"
                count_params.append(threat_type)
            if blocked_only:
                count_query += " AND blocked = 1"
            
            cursor.execute(count_query, count_params)
            total_count = cursor.fetchone()[0]
            
            conn.close()
            
            return JSONResponse(content={
                "events": events,
                "total": total_count,
                "limit": limit,
                "offset": offset
            })
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.get("/network-connections")
    async def get_network_connections():
        """Get active network connections (simulated from recent activity)"""
        try:
            import sqlite3
            conn = sqlite3.connect(waf_engine.db_path)
            cursor = conn.cursor()
            
            # Get recent active IPs (last 5 minutes)
            cursor.execute("""
                SELECT DISTINCT ip, 
                       MAX(timestamp) as last_seen,
                       COUNT(*) as request_count,
                       SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked_count
                FROM security_events
                WHERE timestamp >= datetime('now', '-5 minutes')
                AND ip IS NOT NULL
                GROUP BY ip
                ORDER BY last_seen DESC
                LIMIT 20
            """)
            
            connections = []
            for row in cursor.fetchall():
                ip, last_seen, request_count, blocked_count = row
                connections.append({
                    "ip": ip,
                    "last_seen": last_seen,
                    "request_count": request_count,
                    "blocked_count": blocked_count,
                    "status": "blocked" if blocked_count > 0 else "active",
                    "connection_type": "HTTP"
                })
            
            conn.close()
            
            return JSONResponse(content={
                "connections": connections,
                "active_count": len(connections)
            })
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.post("/block-ip")
    async def block_ip(request_data: dict):
        """Block an IP address"""
        try:
            ip = request_data.get("ip")
            reason = request_data.get("reason", "Manual block")
            
            if not ip:
                raise HTTPException(status_code=400, detail="IP address is required")
            
            success = await waf_engine.block_ip(ip, reason)
            if success:
                # Send WebSocket notification
                await websocket_manager.broadcast(json.dumps({
                    "type": "alert",
                    "message": f"🚫 IP {ip} has been blocked: {reason}"
                }))
                return JSONResponse(content={"status": "success", "message": f"IP {ip} blocked"})
            else:
                raise HTTPException(status_code=400, detail="Invalid IP address")
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.post("/unblock-ip")
    async def unblock_ip(request_data: dict):
        """Unblock an IP address"""
        try:
            ip = request_data.get("ip")
            
            if not ip:
                raise HTTPException(status_code=400, detail="IP address is required")
            
            success = await waf_engine.unblock_ip(ip)
            if success:
                # Send WebSocket notification
                await websocket_manager.broadcast(json.dumps({
                    "type": "alert",
                    "message": f"✅ IP {ip} has been unblocked"
                }))
                return JSONResponse(content={"status": "success", "message": f"IP {ip} unblocked"})
            else:
                raise HTTPException(status_code=404, detail="IP not found in blocklist")
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.get("/security/summary")
    async def get_security_summary():
        """Get security configuration summary"""
        try:
            summary = await waf_engine.security_manager.get_security_summary()
            return JSONResponse(content=summary)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.get("/security/rules")
    async def get_security_rules():
        """Get all security rules"""
        try:
            rules = await waf_engine.security_manager.export_rules()
            return JSONResponse(content={"rules": rules, "count": len(rules)})
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.post("/security/rules")
    async def create_security_rule(rule_data: dict):
        """Create a new security rule"""
        try:
            rule = SecurityRule(
                id=rule_data.get("id"),
                name=rule_data.get("name"),
                description=rule_data.get("description"),
                pattern=rule_data.get("pattern"),
                threat_type=rule_data.get("threat_type"),
                severity=rule_data.get("severity"),
                enabled=rule_data.get("enabled", True)
            )
            
            success = await waf_engine.security_manager.add_security_rule(rule)
            if success:
                return JSONResponse(content={"status": "success", "message": "Rule created"})
            else:
                raise HTTPException(status_code=400, detail="Invalid rule pattern")
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.delete("/security/rules/{rule_id}")
    async def delete_security_rule(rule_id: str):
        """Delete a security rule"""
        try:
            success = await waf_engine.security_manager.remove_security_rule(rule_id)
            if success:
                return JSONResponse(content={"status": "success", "message": "Rule deleted"})
            else:
                raise HTTPException(status_code=404, detail="Rule not found")
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.put("/security/rules/{rule_id}/enable")
    async def enable_security_rule(rule_id: str):
        """Enable a security rule"""
        try:
            success = await waf_engine.security_manager.enable_rule(rule_id)
            if success:
                return JSONResponse(content={"status": "success", "message": "Rule enabled"})
            else:
                raise HTTPException(status_code=404, detail="Rule not found")
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.put("/security/rules/{rule_id}/disable")
    async def disable_security_rule(rule_id: str):
        """Disable a security rule"""
        try:
            success = await waf_engine.security_manager.disable_rule(rule_id)
            if success:
                return JSONResponse(content={"status": "success", "message": "Rule disabled"})
            else:
                raise HTTPException(status_code=404, detail="Rule not found")
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.get("/security/reputation/{ip}")
    async def check_ip_reputation(ip: str):
        """Check IP reputation"""
        try:
            reputation = await waf_engine.security_manager.check_ip_reputation(ip)
            return JSONResponse(content=reputation)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.post("/security/whitelist")
    async def add_to_whitelist(request_data: dict):
        """Add IP to whitelist"""
        try:
            ip = request_data.get("ip")
            if not ip:
                raise HTTPException(status_code=400, detail="IP address is required")
            
            success = await waf_engine.security_manager.add_to_whitelist(ip)
            if success:
                return JSONResponse(content={"status": "success", "message": f"IP {ip} added to whitelist"})
            else:
                raise HTTPException(status_code=400, detail="Invalid IP address")
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.post("/security/blacklist") 
    async def add_to_blacklist(request_data: dict):
        """Add IP to blacklist"""
        try:
            ip = request_data.get("ip")
            if not ip:
                raise HTTPException(status_code=400, detail="IP address is required")
            
            success = await waf_engine.security_manager.add_to_blacklist(ip)
            if success:
                # Send WebSocket notification
                await websocket_manager.broadcast(json.dumps({
                    "type": "alert", 
                    "message": f"🚫 IP {ip} added to permanent blacklist"
                }))
                return JSONResponse(content={"status": "success", "message": f"IP {ip} added to blacklist"})
            else:
                raise HTTPException(status_code=400, detail="Invalid IP address")
                
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.post("/admin/reset-metrics")
    async def reset_metrics():
        """Reset WAF metrics"""
        try:
            await waf_engine.reset_metrics()
            return JSONResponse(content={"status": "success", "message": "Metrics reset"})
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.post("/admin/clear-events")
    async def clear_events():
        """Clear security events history"""
        try:
            await waf_engine.clear_events()
            return JSONResponse(content={"status": "success", "message": "Events cleared"})
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @api_v1.get("/admin/config")
    async def get_config():
        """Get current WAF configuration"""
        try:
            from ..config import get_settings
            settings = get_settings()
            config = {
                "app_name": settings.app_name,
                "version": settings.app_version,
                "environment": settings.environment,
                "security_features": {
                    "sql_injection_protection": settings.sql_injection_protection,
                    "xss_protection": settings.xss_protection,
                    "ddos_protection": settings.ddos_protection,
                    "ip_blocking_enabled": settings.ip_blocking_enabled,
                    "bot_detection_enabled": settings.bot_detection_enabled,
                    "rate_limit_enabled": settings.rate_limit_enabled,
                },
                "rate_limiting": {
                    "requests": settings.rate_limit_requests,
                    "window": settings.rate_limit_window,
                },
                "monitoring": {
                    "metrics_enabled": settings.metrics_enabled,
                    "health_check_interval": settings.health_check_interval,
                }
            }
            return JSONResponse(content=config)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    # Test endpoints for demo purposes
    @api_v1.get("/test/trigger-sql-injection")
    async def test_sql_injection():
        """Test endpoint to trigger SQL injection detection"""
        # This will be caught by the WAF
        test_payload = "' UNION SELECT * FROM users--"
        return JSONResponse(content={"message": "This should be blocked", "payload": test_payload})
    
    @api_v1.get("/test/trigger-xss")
    async def test_xss():
        """Test endpoint to trigger XSS detection"""
        # This will be caught by the WAF
        test_payload = "<script>alert('XSS')</script>"
        return JSONResponse(content={"message": "This should be blocked", "payload": test_payload})
    
    @api_v1.get("/flagged-events")
    async def get_flagged_events(limit: int = 100, offset: int = 0):
        """Get events flagged by the AI scorer (observe-only) with pagination"""
        try:
            import sqlite3
            conn = sqlite3.connect(waf_engine.db_path)
            cursor = conn.cursor()

            # Select events where details.ai.flagged is true (JSON1 extension)
            query = """
                SELECT event_id, timestamp, threat_type, threat_level, ip, url, user_agent, action, blocked, details
                FROM security_events
                WHERE json_extract(details, '$.ai.flagged') = 1
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """
            cursor.execute(query, (limit, offset))

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

            # Total count for pagination
            count_query = "SELECT COUNT(*) FROM security_events WHERE json_extract(details, '$.ai.flagged') = 1"
            cursor.execute(count_query)
            total_count = cursor.fetchone()[0]

            conn.close()

            return JSONResponse(content={
                "events": events,
                "total": total_count,
                "limit": limit,
                "offset": offset
            })
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @api_v1.get("/auto-block/pending")
    async def get_pending_auto_blocks(limit: int = 100, offset: int = 0):
        """Get AI-flagged events that have not been blocked yet (pending review)"""
        try:
            import sqlite3
            conn = sqlite3.connect(waf_engine.db_path)
            cursor = conn.cursor()

            query = """
                SELECT event_id, timestamp, threat_type, threat_level, ip, url, user_agent, action, blocked, details
                FROM security_events
                WHERE json_extract(details, '$.ai.flagged') = 1 AND blocked = 0
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """
            cursor.execute(query, (limit, offset))

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

            count_query = "SELECT COUNT(*) FROM security_events WHERE json_extract(details, '$.ai.flagged') = 1 AND blocked = 0"
            cursor.execute(count_query)
            total_count = cursor.fetchone()[0]

            conn.close()

            return JSONResponse(content={
                "events": events,
                "total": total_count,
                "limit": limit,
                "offset": offset
            })
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @api_v1.post("/auto-block/review")
    async def review_auto_block(request_data: dict):
        """Approve or reject an AI-suggested block. Body: {ip, action: 'approve'|'reject', event_id?, note?}"""
        try:
            ip = request_data.get("ip")
            action = request_data.get("action")
            event_id = request_data.get("event_id")
            note = request_data.get("note", "")

            if not ip or action not in ("approve", "reject"):
                raise HTTPException(status_code=400, detail="ip and action('approve'|'reject') are required")

            if action == "approve":
                # perform manual block via waf_engine
                success = await waf_engine.block_ip(ip, f"Approved by reviewer: {note}", reason_type="approved")
                if success:
                    # audit log
                    try:
                        await waf_engine.log_auto_block(ip, {"action": "approved", "note": note, "event_id": event_id})
                    except Exception:
                        pass
                    # broadcast notification
                    try:
                        await websocket_manager.broadcast(json.dumps({"type": "alert", "message": f"⛔ Auto-block approved for {ip}"}))
                    except Exception:
                        pass
                    return JSONResponse(content={"status": "success", "message": f"IP {ip} blocked"})
                else:
                    raise HTTPException(status_code=400, detail="Failed to block IP")

            # reject path: mark event(s) as reviewed/rejected
            import sqlite3
            conn = sqlite3.connect(waf_engine.db_path)
            cursor = conn.cursor()
            if event_id:
                update_query = "UPDATE security_events SET details = json_set(details, '$.ai.reviewed', 1, '$.ai.review_decision', 'rejected') WHERE event_id = ?"
                cursor.execute(update_query, (event_id,))
            else:
                update_query = "UPDATE security_events SET details = json_set(details, '$.ai.reviewed', 1, '$.ai.review_decision', 'rejected') WHERE json_extract(details, '$.ai.flagged') = 1 AND ip = ? AND blocked = 0"
                cursor.execute(update_query, (ip,))
            conn.commit()
            conn.close()

            try:
                await waf_engine.log_auto_block(ip, {"action": "rejected", "note": note, "event_id": event_id})
            except Exception:
                pass

            return JSONResponse(content={"status": "success", "message": f"AI flag for {ip} marked rejected"})

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @api_v1.get("/ai-suggestions")
    async def get_ai_suggestions(limit: int = 100, offset: int = 0, min_confidence: float = 0.0):
        """Return recent events where model produced a prediction (suggested severity), with optional confidence filter"""
        try:
            import sqlite3
            conn = sqlite3.connect(waf_engine.db_path)
            cursor = conn.cursor()

            query = """
                SELECT event_id, timestamp, threat_type, threat_level, ip, url, user_agent, action, blocked, details
                FROM security_events
                WHERE json_extract(details, '$.ai.model') IS NOT NULL
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """
            cursor.execute(query, (limit, offset))

            events = []
            for row in cursor.fetchall():
                details = json.loads(row[9]) if row[9] else {}
                model = details.get('ai', {}).get('model') if details else None
                mc = None
                suggestion = None
                if isinstance(model, dict):
                    mc = model.get('model_confidence') or model.get('model_score')
                    suggestion = model.get('suggested_severity') or model.get('predicted_label')

                # apply min_confidence filter
                try:
                    if min_confidence and (mc is None or float(mc) < float(min_confidence)):
                        continue
                except Exception:
                    pass

                events.append({
                    "event_id": row[0],
                    "timestamp": row[1],
                    "ip": row[4],
                    "url": row[5],
                    "predicted": suggestion,
                    "model_confidence": mc,
                    "details": details
                })

            # total count (without confidence filter for simplicity)
            count_query = "SELECT COUNT(*) FROM security_events WHERE json_extract(details, '$.ai.model') IS NOT NULL"
            cursor.execute(count_query)
            total_count = cursor.fetchone()[0]

            conn.close()

            return JSONResponse(content={"events": events, "total": total_count, "limit": limit, "offset": offset})
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # Include API router in the main app
    app.include_router(api_v1)
