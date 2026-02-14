"""
Blocked IPs API Routes for VigilEdge WAF
Handles IP blocking/unblocking operations.
"""

import logging
import ipaddress
from fastapi import APIRouter, Request

router = APIRouter(prefix="/api/v1", tags=["Blocked IPs"])


def get_waf_engine():
    """Get WAF engine from app state."""
    from app import waf_engine
    return waf_engine


@router.get("/blocked-ips")
async def api_get_blocked_ips():
    """API endpoint to get all blocked IPs with full details."""
    try:
        waf_engine = get_waf_engine()
        blocked_ips = await waf_engine.get_blocked_ips()
        
        stats = {
            'total_blocked': len(blocked_ips),
            'blocked_today': sum(1 for ip in blocked_ips if ip.get('is_today', False)),
            'automatic_blocks': sum(1 for ip in blocked_ips if ip.get('reason_type') in ['malicious', 'suspicious', 'bot']),
            'manual_blocks': sum(1 for ip in blocked_ips if ip.get('reason_type') == 'manual')
        }
        
        return {
            "success": True,
            "blocked_ips": blocked_ips,
            "count": len(blocked_ips),
            "stats": stats
        }
    except Exception as e:
        logging.error(f"Error getting blocked IPs: {e}")
        return {"success": False, "error": str(e), "blocked_ips": [], "count": 0}


@router.post("/blocked-ips")
async def api_block_ip(request: Request):
    """API endpoint to manually block an IP address."""
    try:
        waf_engine = get_waf_engine()
        data = await request.json()
        ip_address = data.get('ip')
        reason = data.get('reason', 'Manual block')
        reason_type = data.get('reason_type', 'manual')
        notes = data.get('notes', '')
        
        if not ip_address:
            return {"success": False, "error": "IP address is required"}
        
        # Validate IP format
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return {"success": False, "error": "Invalid IP address format"}
        
        # Block the IP with full details
        full_reason = f"{reason}" + (f" - {notes}" if notes else "")
        result = await waf_engine.block_ip(ip_address, full_reason, reason_type)
        
        if result:
            return {
                "success": True,
                "message": f"IP {ip_address} has been blocked",
                "ip": ip_address,
                "reason": reason
            }
        else:
            return {"success": False, "error": "Failed to block IP"}
            
    except Exception as e:
        logging.error(f"Error blocking IP: {e}")
        return {"success": False, "error": str(e)}


@router.delete("/blocked-ips/{ip_address}")
async def api_unblock_ip(ip_address: str):
    """API endpoint to unblock an IP address."""
    try:
        waf_engine = get_waf_engine()
        result = await waf_engine.unblock_ip(ip_address)
        
        if result:
            return {
                "success": True,
                "message": f"IP {ip_address} has been unblocked",
                "ip": ip_address
            }
        else:
            return {"success": False, "error": "Failed to unblock IP or IP not found"}
            
    except Exception as e:
        logging.error(f"Error unblocking IP: {e}")
        return {"success": False, "error": str(e)}


@router.post("/blocked-ips/clear")
async def api_clear_blocked_ips():
    """API endpoint to clear all blocked IPs."""
    try:
        waf_engine = get_waf_engine()
        result = await waf_engine.clear_all_blocked_ips()
        
        if result:
            return {
                "success": True,
                "message": "All blocked IPs have been cleared"
            }
        else:
            return {"success": False, "error": "Failed to clear blocked IPs"}
            
    except Exception as e:
        logging.error(f"Error clearing blocked IPs: {e}")
        return {"success": False, "error": str(e)}
