"""
Network Monitoring API Routes for VigilEdge WAF
Handles active connections, logs, IP activity, system uptime, speed testing, and real network monitoring.
"""

import os
import time
import logging
import asyncio
import subprocess
import threading
import socket
from datetime import datetime
from typing import Dict, Optional, List
from fastapi import APIRouter, Request, BackgroundTasks, Depends
import httpx
from vigiledge.config import get_settings
from vigiledge.utils.client_ip import get_effective_client_ip
from .auth import require_control_plane_access
from vigiledge.utils.rate_limiter import limiter, WRITE, READ, RELAXED

# Import psutil for real network monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logging.warning("psutil not installed - some network monitoring features will be limited")

# ============= USER ACTIVITY TRACKING =============
# Track real user actions on the vulnerable app
USER_ACTIVITY_LOG: List[Dict] = []
MAX_ACTIVITY_LOG = 100  # Keep last 100 activities

# ============= SPEED TEST STATE =============
SPEED_TEST_RESULT: Dict = {
    "status": "idle",  # idle, running, completed, error
    "download": 0,
    "upload": 0,
    "ping": 0,
    "server": "",
    "timestamp": None,
    "progress": 0,
    "message": ""
}
SPEED_TEST_LOCK = threading.Lock()

# Real-time speed tracking
SPEED_TRACKER: Dict = {
    "download_speed": 0,  # Mbps
    "upload_speed": 0,    # Mbps
    "last_in_bytes": 0,
    "last_out_bytes": 0,
    "last_update": time.time()
}

router = APIRouter(prefix="/api/v1", tags=["Network Monitoring"], dependencies=[Depends(require_control_plane_access)])

# ============= SERVER-SIDE GEOLOCATION CACHE =============
# Efficient IP geolocation with caching to avoid rate limits
# Supports up to 100,000 concurrent users
IP_LOCATION_CACHE: Dict[str, dict] = {}
CACHE_TTL = 86400  # Cache locations for 24 hours (reduces API calls for large user base)
MAX_USERS = 100000  # Maximum tracked users
CLEANUP_BATCH = 10000  # Remove this many oldest users when limit reached

# Track all connected users with their locations
CONNECTED_USERS: Dict[str, dict] = {}

# Cache for server's public IP
SERVER_PUBLIC_IP: Optional[str] = None


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/local."""
    return ip.startswith(('127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                          '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                          '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
                          'localhost', '0.0.0.0', '::1'))


async def get_server_public_ip() -> Optional[str]:
    """Get the server's public IP address for geolocation of private IPs."""
    global SERVER_PUBLIC_IP
    
    if SERVER_PUBLIC_IP:
        return SERVER_PUBLIC_IP
    
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # Use ip-api to get our public IP
            resp = await client.get("http://ip-api.com/json/?fields=query")
            if resp.status_code == 200:
                data = resp.json()
                SERVER_PUBLIC_IP = data.get('query')
                return SERVER_PUBLIC_IP
    except Exception as e:
        logging.error(f"Failed to get server public IP: {e}")
    
    return None


async def get_ip_location(ip: str, use_public_fallback: bool = True) -> Optional[dict]:
    """
    Get geolocation for an IP address using server-side lookup.
    Uses caching to avoid rate limits and improve performance.
    For private IPs, falls back to server's public IP location.
    """
    original_ip = ip
    is_private = is_private_ip(ip)
    
    # For private IPs, use server's public IP instead
    if is_private and use_public_fallback:
        public_ip = await get_server_public_ip()
        if public_ip:
            ip = public_ip
        else:
            return None
    elif is_private:
        return None
    
    # Check cache first
    if ip in IP_LOCATION_CACHE:
        cached = IP_LOCATION_CACHE[ip]
        if time.time() - cached.get('cached_at', 0) < CACHE_TTL:
            location = cached.get('location').copy()
            if is_private:
                location['source'] = 'server-public-ip'
                location['note'] = f'Private IP ({original_ip}) - using server location'
            return location
    
    # Fetch from ip-api.com (free, 45 req/min limit)
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=status,lat,lon,city,regionName,country,isp")
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success':
                    location = {
                        'lat': data.get('lat'),
                        'lng': data.get('lon'),
                        'city': data.get('city'),
                        'region': data.get('regionName'),
                        'country': data.get('country'),
                        'isp': data.get('isp'),
                        'source': 'server-public-ip' if is_private else 'server-geoip'
                    }
                    if is_private:
                        location['note'] = f'Private IP ({original_ip}) - using server location'
                    
                    # Cache the result
                    IP_LOCATION_CACHE[ip] = {
                        'location': location,
                        'cached_at': time.time()
                    }
                    return location
    except Exception as e:
        logging.error(f"Geolocation lookup failed for {ip}: {e}")
    
    return None


def track_user_connection(ip: str, user_agent: str, url: str, location: Optional[dict] = None):
    """Track a user connection with location data. Supports up to 100,000 users."""
    now = datetime.now()
    
    if ip not in CONNECTED_USERS:
        CONNECTED_USERS[ip] = {
            'ip': ip,
            'first_seen': now.isoformat(),
            'last_seen': now.isoformat(),
            'request_count': 0,
            'user_agent': user_agent,
            'urls': set(),
            'location': location
        }
    
    user = CONNECTED_USERS[ip]
    user['last_seen'] = now.isoformat()
    user['request_count'] += 1
    user['urls'].add(url)
    if location and not user.get('location'):
        user['location'] = location
    
    # Keep only last MAX_USERS users to prevent memory issues
    if len(CONNECTED_USERS) > MAX_USERS:
        # Remove oldest users in batch for efficiency
        sorted_users = sorted(CONNECTED_USERS.items(), key=lambda x: x[1]['last_seen'])
        for old_ip, _ in sorted_users[:CLEANUP_BATCH]:
            del CONNECTED_USERS[old_ip]


def get_waf_engine():
    """Get WAF engine from app state."""
    from app import waf_engine
    return waf_engine


@router.get("/connections/active")
@limiter.limit(READ)
async def get_active_connections(request: Request):
    """Get currently active connections with geolocation."""
    waf_engine = get_waf_engine()
    connections = []
    
    # Process each connection and add geolocation
    for ip, data in waf_engine.connection_table.items():
        conn_data = {
            "ip": ip,
            "first_seen": data["first_seen"].isoformat() if hasattr(data["first_seen"], "isoformat") else str(data["first_seen"]),
            "request_count": data["request_count"],
            "methods": list(data["methods"]),
            "unique_urls": len(data["unique_urls"]),
            "user_agents": list(data["user_agents"])[:3],
            "location": None
        }
        
        # Add cached location if available
        if ip in IP_LOCATION_CACHE:
            conn_data["location"] = IP_LOCATION_CACHE[ip].get('location')
        
        connections.append(conn_data)
    
    return {"connections": connections, "total": len(connections)}


@router.get("/connections/geolocate")
@limiter.limit(READ)
async def geolocate_all_connections(request: Request):
    """
    Get all active connections with real-time geolocation.
    This endpoint fetches location for ALL connected IPs efficiently.
    """
    waf_engine = get_waf_engine()
    connections_with_location = []
    
    # Batch process all IPs
    tasks = []
    ip_list = list(waf_engine.connection_table.keys())
    
    for ip in ip_list:
        if ip not in IP_LOCATION_CACHE or (time.time() - IP_LOCATION_CACHE.get(ip, {}).get('cached_at', 0) > CACHE_TTL):
            tasks.append(get_ip_location(ip))
        else:
            tasks.append(asyncio.coroutine(lambda: IP_LOCATION_CACHE[ip].get('location'))())
    
    # Fetch all locations concurrently (with rate limit consideration)
    # Process in batches of 10 to avoid overwhelming ip-api.com
    batch_size = 10
    all_locations = []
    
    for i in range(0, len(ip_list), batch_size):
        batch_ips = ip_list[i:i+batch_size]
        batch_locations = await asyncio.gather(*[get_ip_location(ip) for ip in batch_ips])
        all_locations.extend(batch_locations)
        
        # Small delay between batches to respect rate limits
        if i + batch_size < len(ip_list):
            await asyncio.sleep(0.5)
    
    # Build response
    for idx, ip in enumerate(ip_list):
        data = waf_engine.connection_table[ip]
        location = all_locations[idx] if idx < len(all_locations) else None
        
        connections_with_location.append({
            "ip": ip,
            "first_seen": data["first_seen"].isoformat() if hasattr(data["first_seen"], "isoformat") else str(data["first_seen"]),
            "request_count": data["request_count"],
            "methods": list(data["methods"]),
            "unique_urls": len(data["unique_urls"]),
            "user_agents": list(data["user_agents"])[:3],
            "location": location
        })
    
    return {
        "connections": connections_with_location,
        "total": len(connections_with_location),
        "geolocated": sum(1 for c in connections_with_location if c.get('location'))
    }


@router.get("/users/live")
@limiter.limit(RELAXED)
async def get_live_users(request: Request):
    """
    Get all live/active users with their locations.
    This is the main endpoint for the Network Monitor map.
    """
    waf_engine = get_waf_engine()
    users = []
    
    for ip, data in waf_engine.connection_table.items():
        user_data = {
            "ip": ip,
            "timestamp": data["first_seen"].isoformat() if hasattr(data["first_seen"], "isoformat") else str(data["first_seen"]),
            "request_count": data["request_count"],
            "ua": list(data["user_agents"])[0] if data["user_agents"] else "Unknown",
            "location": None
        }
        
        # Get cached location or fetch new one
        if ip in IP_LOCATION_CACHE:
            user_data["location"] = IP_LOCATION_CACHE[ip].get('location')
        else:
            # Fetch location asynchronously
            location = await get_ip_location(ip)
            if location:
                user_data["location"] = location
        
        if user_data["location"]:
            users.append(user_data)
    
    return {
        "users": users,
        "total": len(waf_engine.connection_table),
        "geolocated": len(users)
    }


@router.get("/connections/logs")
@limiter.limit(READ)
async def get_connection_logs(request: Request, limit: int = 50):
    """Get recent security events/logs."""
    waf_engine = get_waf_engine()
    events = waf_engine.security_events[-limit:]  # Get last N events
    logs = []
    for event in reversed(events):
        logs.append({
            "id": event.id,
            "timestamp": event.timestamp.isoformat() if hasattr(event.timestamp, "isoformat") else str(event.timestamp),
            "ip": event.source_ip,
            "url": event.target_url,
            "threat_type": event.threat_type,
            "threat_level": event.threat_level.value if hasattr(event.threat_level, "value") else str(event.threat_level),
            "action": event.action_taken.value if hasattr(event.action_taken, "value") else str(event.action_taken),
            "blocked": event.blocked,
            "user_agent": event.user_agent,
            "details": event.details
        })
    return {"logs": logs, "total": len(logs)}


@router.get("/ips/activity")
@limiter.limit(READ)
async def get_ip_activity(request: Request):
    """Get IP activity statistics."""
    waf_engine = get_waf_engine()
    ip_stats = {}
    
    # Aggregate from connection table
    for ip, data in waf_engine.connection_table.items():
        ip_stats[ip] = {
            "requests": data["request_count"],
            "first_seen": data["first_seen"].isoformat() if hasattr(data["first_seen"], "isoformat") else str(data["first_seen"]),
            "methods": list(data["methods"]),
            "unique_urls": len(data["unique_urls"])
        }
    
    # Add blocked/allowed stats from events
    for event in waf_engine.security_events[-200:]:  # Last 200 events
        ip = event.source_ip
        if ip not in ip_stats:
            ip_stats[ip] = {"requests": 0, "blocked": 0, "allowed": 0}
        
        if "blocked" not in ip_stats[ip]:
            ip_stats[ip]["blocked"] = 0
        if "allowed" not in ip_stats[ip]:
            ip_stats[ip]["allowed"] = 0
            
        if event.blocked:
            ip_stats[ip]["blocked"] += 1
        else:
            ip_stats[ip]["allowed"] += 1
    
    # Convert to list and sort by request count
    ip_list = [{"ip": ip, **stats} for ip, stats in ip_stats.items()]
    ip_list.sort(key=lambda x: x.get("requests", 0), reverse=True)
    
    return {"ips": ip_list[:50], "total": len(ip_list)}  # Top 50 IPs


@router.get("/system/uptime")
@limiter.limit(RELAXED)
async def get_system_uptime(request: Request):
    """Get WAF uptime and health metrics."""
    try:
        import psutil
        waf_engine = get_waf_engine()
        
        process = psutil.Process(os.getpid())
        uptime_seconds = time.time() - process.create_time()
        
        return {
            "uptime_seconds": int(uptime_seconds),
            "uptime_formatted": f"{int(uptime_seconds // 3600)}h {int((uptime_seconds % 3600) // 60)}m",
            "total_requests": waf_engine.metrics.total_requests,
            "blocked_requests": waf_engine.metrics.blocked_requests,
            "threats_detected": waf_engine.metrics.threats_detected,
            "cpu_percent": process.cpu_percent(),
            "memory_mb": process.memory_info().rss / 1024 / 1024,
            "status": "healthy"
        }
    except ImportError:
        waf_engine = get_waf_engine()
        return {
            "uptime_seconds": 0,
            "uptime_formatted": "N/A",
            "total_requests": waf_engine.metrics.total_requests,
            "blocked_requests": waf_engine.metrics.blocked_requests,
            "threats_detected": waf_engine.metrics.threats_detected,
            "cpu_percent": 0,
            "memory_mb": 0,
            "status": "healthy"
        }

@router.get("/victims")
async def api_get_victims():
    """
    Fetch victim list - combines data from vulnerable app AND server-side tracking.
    Server-side tracking ensures location is always available.
    """
    settings = get_settings()
    target_url = settings.vulnerable_app_url.rstrip('/')
    
    # Start with our server-side tracked users
    victims_by_ip = {}
    
    # Add data from CONNECTED_USERS (server-side tracking)
    for ip, user_data in CONNECTED_USERS.items():
        victims_by_ip[ip] = {
            "ip": ip,
            "timestamp": user_data.get("last_seen", user_data.get("first_seen")),
            "ua": user_data.get("user_agent", "Unknown"),
            "location": user_data.get("location"),
            "request_count": user_data.get("request_count", 1),
            "source": "server-tracking"
        }
    
    # Also fetch from vulnerable app and merge
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            if not target_url:
                target_url = "http://localhost:8080"
                
            resp = await client.get(f"{target_url}/api/victims")
            if resp.status_code == 200:
                app_data = resp.json()
                for victim in app_data.get("victims", []):
                    ip = victim.get("ip", "unknown")
                    if ip in victims_by_ip:
                        # Merge - prefer GPS location from client if available
                        if victim.get("location", {}).get("source") == "gps":
                            victims_by_ip[ip]["location"] = victim.get("location")
                    else:
                        victims_by_ip[ip] = victim
    except Exception as e:
        logging.error(f"Failed to fetch victims from vulnerable app: {e}")
    
    # Convert to list
    victims_list = list(victims_by_ip.values())
    
    return {
        "victims": victims_list,
        "total": len(victims_list),
        "geolocated": sum(1 for v in victims_list if v.get("location"))
    }


@router.post("/log-victim")
async def api_log_victim(request: Request):
    """
    Receive victim logs and perform server-side geolocation.
    This endpoint is called by the vulnerable app JavaScript.
    """
    settings = get_settings()
    target_url = settings.vulnerable_app_url.rstrip('/')
    
    try:
        body = await request.body()
        import json
        victim_data = json.loads(body) if body else {}
        
        client_ip = get_effective_client_ip(request, settings_obj=getattr(request.app.state, "settings", None))
        
        # Track this user in our system
        user_agent = request.headers.get("User-Agent", "Unknown")
        
        # Check if client already provided GPS location
        client_location = victim_data.get("location")
        
        # If no GPS location or it's from IP lookup, do server-side geolocation
        if not client_location or (not client_location.get("lat")):
            server_location = await get_ip_location(client_ip)
            if server_location:
                victim_data["location"] = server_location
                victim_data["location"]["source"] = "server-geoip"
        else:
            # Client provided GPS - mark it
            victim_data["location"]["source"] = "gps"
        
        # Store in WAF's tracking system
        waf_engine = get_waf_engine()
        
        # Also track in our CONNECTED_USERS for real-time monitoring
        track_user_connection(
            ip=client_ip,
            user_agent=user_agent,
            url=victim_data.get("url", "/protected/"),
            location=victim_data.get("location")
        )
        
        # Forward to vulnerable app for storage
        async with httpx.AsyncClient(timeout=5.0) as client:
            if not target_url:
                target_url = "http://localhost:8080"
            
            # Add server-enriched data
            victim_data["ip"] = client_ip
            victim_data["timestamp"] = datetime.now().isoformat()
            
            resp = await client.post(
                f"{target_url}/api/log-victim",
                json=victim_data,
                headers={"Content-Type": "application/json"}
            )
            if resp.status_code == 200:
                result = resp.json()
                result["server_processed"] = True
                result["client_ip"] = client_ip
                result["location_source"] = victim_data.get("location", {}).get("source", "unknown")
                return result
            return {"status": "ok", "message": "Tracked by WAF", "server_processed": True}
    except Exception as e:
        logging.error(f"Failed to log victim: {e}")
        return {"status": "error", "message": "An internal server error occurred while processing your request."}


# ============= SPEED TEST API ENDPOINTS =============

def run_speed_test_thread():
    """Background thread to run speed test without blocking."""
    global SPEED_TEST_RESULT
    
    with SPEED_TEST_LOCK:
        SPEED_TEST_RESULT["status"] = "running"
        SPEED_TEST_RESULT["progress"] = 0
        SPEED_TEST_RESULT["message"] = "Initializing speed test..."
    
    try:
        # Try using speedtest-cli
        import shutil
        speedtest_path = shutil.which("speedtest-cli") or shutil.which("speedtest")
        
        if speedtest_path:
            # Use speedtest-cli if available
            with SPEED_TEST_LOCK:
                SPEED_TEST_RESULT["message"] = "Connecting to speed test server..."
                SPEED_TEST_RESULT["progress"] = 10
            
            result = subprocess.run(
                [speedtest_path, "--simple"],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.startswith("Ping:"):
                        SPEED_TEST_RESULT["ping"] = float(line.split()[1])
                    elif line.startswith("Download:"):
                        SPEED_TEST_RESULT["download"] = float(line.split()[1])
                    elif line.startswith("Upload:"):
                        SPEED_TEST_RESULT["upload"] = float(line.split()[1])
                
                with SPEED_TEST_LOCK:
                    SPEED_TEST_RESULT["status"] = "completed"
                    SPEED_TEST_RESULT["timestamp"] = datetime.now().isoformat()
                    SPEED_TEST_RESULT["progress"] = 100
                    SPEED_TEST_RESULT["message"] = "Speed test completed!"
                    SPEED_TEST_RESULT["server"] = "speedtest.net"
            else:
                raise Exception(f"Speed test failed: {result.stderr}")
        else:
            # Fallback: Use HTTP-based speed test
            with SPEED_TEST_LOCK:
                SPEED_TEST_RESULT["message"] = "Testing ping latency..."
                SPEED_TEST_RESULT["progress"] = 20
            
            # Ping test using HTTP request timing
            import urllib.request
            ping_times = []
            for _ in range(5):
                start = time.time()
                try:
                    urllib.request.urlopen("http://www.google.com", timeout=5)
                    ping_times.append((time.time() - start) * 1000)
                except:
                    ping_times.append(100)
            avg_ping = sum(ping_times) / len(ping_times)
            
            with SPEED_TEST_LOCK:
                SPEED_TEST_RESULT["ping"] = round(avg_ping, 2)
                SPEED_TEST_RESULT["message"] = "Testing download speed..."
                SPEED_TEST_RESULT["progress"] = 40
            
            # Download test (10MB file from fast CDN)
            download_urls = [
                "http://speed.cloudflare.com/__down?bytes=10000000",
                "http://ipv4.download.thinkbroadband.com/10MB.zip",
                "http://proof.ovh.net/files/10Mb.dat"
            ]
            
            download_speed = 0
            for url in download_urls:
                try:
                    start = time.time()
                    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                    response = urllib.request.urlopen(req, timeout=30)
                    data = response.read()
                    elapsed = time.time() - start
                    if elapsed > 0:
                        download_speed = (len(data) * 8) / elapsed / 1_000_000  # Mbps
                    break
                except Exception as e:
                    logging.warning(f"Download test failed for {url}: {e}")
                    continue
            
            with SPEED_TEST_LOCK:
                SPEED_TEST_RESULT["download"] = round(download_speed, 2)
                SPEED_TEST_RESULT["message"] = "Testing upload speed..."
                SPEED_TEST_RESULT["progress"] = 70
            
            # Upload test (simulate with POST to httpbin - limited but works)
            upload_speed = 0
            try:
                test_data = b'0' * 1_000_000  # 1MB of data
                start = time.time()
                req = urllib.request.Request(
                    "https://httpbin.org/post",
                    data=test_data,
                    headers={'Content-Type': 'application/octet-stream', 'User-Agent': 'Mozilla/5.0'},
                    method='POST'
                )
                urllib.request.urlopen(req, timeout=30)
                elapsed = time.time() - start
                if elapsed > 0:
                    upload_speed = (len(test_data) * 8) / elapsed / 1_000_000  # Mbps
            except Exception as e:
                logging.warning(f"Upload test failed: {e}")
                # Estimate upload as fraction of download if test fails
                upload_speed = download_speed * 0.3 if download_speed > 0 else 5.0
            
            with SPEED_TEST_LOCK:
                SPEED_TEST_RESULT["upload"] = round(upload_speed, 2)
                SPEED_TEST_RESULT["status"] = "completed"
                SPEED_TEST_RESULT["timestamp"] = datetime.now().isoformat()
                SPEED_TEST_RESULT["progress"] = 100
                SPEED_TEST_RESULT["message"] = "Speed test completed!"
                SPEED_TEST_RESULT["server"] = "HTTP-based test"
    
    except Exception as e:
        logging.error(f"Speed test error: {e}")
        with SPEED_TEST_LOCK:
            SPEED_TEST_RESULT["status"] = "error"
            SPEED_TEST_RESULT["message"] = "Speed test failed due to an internal server error."
            SPEED_TEST_RESULT["progress"] = 0


@router.post("/speed/test")
@limiter.limit(WRITE)
async def api_start_speed_test(request: Request):
    """Start a new internet speed test."""
    global SPEED_TEST_RESULT
    
    with SPEED_TEST_LOCK:
        if SPEED_TEST_RESULT["status"] == "running":
            return {
                "success": False,
                "message": "Speed test already in progress",
                "result": SPEED_TEST_RESULT
            }
    
    # Reset result
    with SPEED_TEST_LOCK:
        SPEED_TEST_RESULT = {
            "status": "running",
            "download": 0,
            "upload": 0,
            "ping": 0,
            "server": "",
            "timestamp": None,
            "progress": 0,
            "message": "Starting speed test..."
        }
    
    # Run in background thread
    thread = threading.Thread(target=run_speed_test_thread, daemon=True)
    thread.start()
    
    return {
        "success": True,
        "message": "Speed test started",
        "result": SPEED_TEST_RESULT
    }


@router.get("/speed/test")
@limiter.limit(RELAXED)
async def api_get_speed_test_result(request: Request):
    """Get the current speed test result/status."""
    return {
        "success": True,
        "result": SPEED_TEST_RESULT.copy()
    }


@router.get("/speed/realtime")
@limiter.limit(RELAXED)
async def api_get_realtime_speed(request: Request):
    """Get real-time network speed based on WAF traffic metrics."""
    global SPEED_TRACKER
    
    try:
        # Get current metrics
        from routes.api_metrics import REQUEST_LOG, STATS
        
        current_time = time.time()
        time_diff = current_time - SPEED_TRACKER["last_update"]
        
        if time_diff > 0:
            current_in = STATS.get("incoming_bytes", 0)
            current_out = STATS.get("outgoing_bytes", 0)
            
            bytes_in_diff = current_in - SPEED_TRACKER["last_in_bytes"]
            bytes_out_diff = current_out - SPEED_TRACKER["last_out_bytes"]
            
            # Calculate Mbps
            download_mbps = max(0, (bytes_in_diff * 8) / time_diff / 1_000_000)
            upload_mbps = max(0, (bytes_out_diff * 8) / time_diff / 1_000_000)
            
            SPEED_TRACKER["download_speed"] = round(download_mbps, 2)
            SPEED_TRACKER["upload_speed"] = round(upload_mbps, 2)
            SPEED_TRACKER["last_in_bytes"] = current_in
            SPEED_TRACKER["last_out_bytes"] = current_out
            SPEED_TRACKER["last_update"] = current_time
        
        return {
            "success": True,
            "download_speed": SPEED_TRACKER["download_speed"],
            "upload_speed": SPEED_TRACKER["upload_speed"],
            "total_in_bytes": SPEED_TRACKER["last_in_bytes"],
            "total_out_bytes": SPEED_TRACKER["last_out_bytes"],
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logging.error(f"Failed to get realtime speed: {e}")
        return {
            "success": False,
            "download_speed": 0,
            "upload_speed": 0,
            "error": "An internal server error occurred while processing your request."
        }


# ============= REAL NETWORK MONITORING ENDPOINTS =============

@router.get("/network/interfaces")
async def api_get_network_interfaces():
    """Get real network interface statistics using psutil."""
    if not PSUTIL_AVAILABLE:
        return {
            "success": False,
            "error": "psutil not installed",
            "interfaces": []
        }
    
    try:
        interfaces = []
        io_counters = psutil.net_io_counters(pernic=True)
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        
        for iface_name, io in io_counters.items():
            # Get interface addresses
            iface_addrs = addrs.get(iface_name, [])
            ipv4 = ""
            ipv6 = ""
            mac = ""
            
            for addr in iface_addrs:
                if addr.family == socket.AF_INET:
                    ipv4 = addr.address
                elif addr.family == socket.AF_INET6:
                    ipv6 = addr.address
                elif hasattr(socket, 'AF_LINK') and addr.family == socket.AF_LINK:
                    mac = addr.address
                elif addr.family == psutil.AF_LINK:
                    mac = addr.address
            
            # Get interface stats
            iface_stats = stats.get(iface_name)
            is_up = iface_stats.isup if iface_stats else False
            speed = iface_stats.speed if iface_stats else 0
            mtu = iface_stats.mtu if iface_stats else 0
            
            interfaces.append({
                "name": iface_name,
                "is_up": is_up,
                "speed_mbps": speed,
                "mtu": mtu,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "mac": mac,
                "bytes_sent": io.bytes_sent,
                "bytes_recv": io.bytes_recv,
                "packets_sent": io.packets_sent,
                "packets_recv": io.packets_recv,
                "errors_in": io.errin,
                "errors_out": io.errout,
                "drops_in": io.dropin,
                "drops_out": io.dropout
            })
        
        return {
            "success": True,
            "interfaces": interfaces,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logging.error(f"Failed to get network interfaces: {e}")
        return {
            "success": False,
            "error": "An internal server error occurred while processing your request.",
            "interfaces": []
        }


@router.get("/network/connections")
async def api_get_network_connections():
    """Get all active TCP/UDP connections with process info."""
    if not PSUTIL_AVAILABLE:
        return {
            "success": False,
            "error": "psutil not installed",
            "connections": []
        }
    
    try:
        connections = []
        for conn in psutil.net_connections(kind='all'):
            try:
                # Get process name if available
                process_name = ""
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        process_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_name = f"PID {conn.pid}"
                
                # Format addresses
                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                
                connections.append({
                    "type": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    "family": "IPv4" if conn.family == socket.AF_INET else "IPv6",
                    "local_address": local_addr,
                    "remote_address": remote_addr,
                    "status": conn.status if hasattr(conn, 'status') else "N/A",
                    "pid": conn.pid,
                    "process": process_name
                })
            except Exception:
                continue
        
        # Sort by status (ESTABLISHED first)
        connections.sort(key=lambda x: (0 if x['status'] == 'ESTABLISHED' else 1, x['type']))
        
        return {
            "success": True,
            "connections": connections[:200],  # Limit to 200 connections
            "total": len(connections),
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logging.error(f"Failed to get network connections: {e}")
        return {
            "success": False,
            "error": "An internal server error occurred while processing your request.",
            "connections": []
        }


@router.get("/network/ports")
async def api_get_listening_ports():
    """Get all listening ports with service information."""
    if not PSUTIL_AVAILABLE:
        return {
            "success": False,
            "error": "psutil not installed",
            "ports": []
        }
    
    try:
        ports = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN':
                try:
                    # Get process name
                    process_name = ""
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            process_name = proc.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            process_name = f"PID {conn.pid}"
                    
                    # Identify common services
                    port = conn.laddr.port
                    service = get_service_name(port)
                    
                    ports.append({
                        "port": port,
                        "address": conn.laddr.ip,
                        "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                        "family": "IPv4" if conn.family == socket.AF_INET else "IPv6",
                        "pid": conn.pid,
                        "process": process_name,
                        "service": service
                    })
                except Exception:
                    continue
        
        # Remove duplicates and sort by port
        seen = set()
        unique_ports = []
        for p in ports:
            key = (p['port'], p['address'], p['protocol'])
            if key not in seen:
                seen.add(key)
                unique_ports.append(p)
        
        unique_ports.sort(key=lambda x: x['port'])
        
        return {
            "success": True,
            "ports": unique_ports,
            "total": len(unique_ports),
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logging.error(f"Failed to get listening ports: {e}")
        return {
            "success": False,
            "error": "An internal server error occurred while processing your request.",
            "ports": []
        }


def get_service_name(port: int) -> str:
    """Get common service name for a port."""
    services = {
        20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
        119: "NNTP", 123: "NTP", 143: "IMAP", 161: "SNMP", 194: "IRC",
        443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        6379: "Redis", 8000: "HTTP Alt", 8080: "HTTP Proxy", 8443: "HTTPS Alt",
        9000: "PHP-FPM", 27017: "MongoDB"
    }
    return services.get(port, "Unknown")


@router.get("/network/summary")
async def api_get_network_summary():
    """Get a summary of network activity for the connection graph."""
    if not PSUTIL_AVAILABLE:
        return {"success": False, "error": "psutil not installed"}
    
    try:
        # Get overall IO counters
        io = psutil.net_io_counters()
        
        # Count connections by type
        connections = psutil.net_connections(kind='inet')
        conn_stats = {
            "total": len(connections),
            "established": 0,
            "listening": 0,
            "time_wait": 0,
            "close_wait": 0,
            "other": 0
        }
        
        remote_hosts = set()
        local_ports = set()
        
        for conn in connections:
            status = conn.status if hasattr(conn, 'status') else "NONE"
            if status == "ESTABLISHED":
                conn_stats["established"] += 1
                if conn.raddr:
                    remote_hosts.add(conn.raddr.ip)
            elif status == "LISTEN":
                conn_stats["listening"] += 1
                if conn.laddr:
                    local_ports.add(conn.laddr.port)
            elif status == "TIME_WAIT":
                conn_stats["time_wait"] += 1
            elif status == "CLOSE_WAIT":
                conn_stats["close_wait"] += 1
            else:
                conn_stats["other"] += 1
        
        return {
            "success": True,
            "io": {
                "bytes_sent": io.bytes_sent,
                "bytes_recv": io.bytes_recv,
                "packets_sent": io.packets_sent,
                "packets_recv": io.packets_recv,
                "errors": io.errin + io.errout,
                "drops": io.dropin + io.dropout
            },
            "connections": conn_stats,
            "unique_remote_hosts": len(remote_hosts),
            "open_ports": len(local_ports),
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logging.error(f"Failed to get network summary: {e}")
        return {"success": False, "error": "An internal server error occurred while processing your request."}


# ============= USER ACTIVITY TRACKING =============

@router.post("/activity/log")
async def api_log_user_activity(request: Request):
    """Log user activity from the vulnerable app for real-time monitoring."""
    global USER_ACTIVITY_LOG
    
    try:
        body = await request.json()
        
        # Use IP from request body if provided (comes from vulnerable app's tracking)
        # Otherwise fall back to header-based detection
        client_ip = body.get("ip")
        if not client_ip or client_ip == "unknown":
            client_ip = get_effective_client_ip(request, settings_obj=getattr(request.app.state, "settings", None))
        
        activity = {
            "id": len(USER_ACTIVITY_LOG) + 1,
            "timestamp": body.get("timestamp", datetime.now().isoformat()),
            "ip": client_ip,
            "action": body.get("action", "unknown"),
            "page": body.get("page", "/"),
            "details": body.get("details", {}),
            "user_agent": body.get("user_agent", request.headers.get("User-Agent", "Unknown")[:100]),
            "method": body.get("method", "GET"),
            "status": body.get("status", "success")
        }
        
        USER_ACTIVITY_LOG.append(activity)
        
        # Keep only last MAX_ACTIVITY_LOG entries
        if len(USER_ACTIVITY_LOG) > MAX_ACTIVITY_LOG:
            USER_ACTIVITY_LOG = USER_ACTIVITY_LOG[-MAX_ACTIVITY_LOG:]
        
        return {"success": True, "logged": True}
    
    except Exception as e:
        logging.error(f"Failed to log user activity: {e}")
        return {"success": False, "error": "An internal server error occurred while processing your request."}


@router.get("/activity/live")
async def api_get_live_activity():
    """Get live user activity feed from the vulnerable app."""
    try:
        # Also fetch from vulnerable app if available
        settings = get_settings()
        target_url = settings.vulnerable_app_url.rstrip('/') if settings.vulnerable_app_url else "http://localhost:8080"
        
        combined_activity = list(USER_ACTIVITY_LOG)
        
        # Try to fetch activities and victims from vulnerable app
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                # Fetch detailed user activities
                try:
                    resp = await client.get(f"{target_url}/api/user-activities")
                    if resp.status_code == 200:
                        data = resp.json()
                        for act in data.get("activities", []):
                            combined_activity.append({
                                "id": f"vuln_act_{act.get('timestamp', '')}",
                                "timestamp": act.get("timestamp", datetime.now().isoformat()),
                                "ip": act.get("ip", "unknown"),
                                "action": act.get("action", "page_visit"),
                                "page": act.get("page", "/"),
                                "details": act.get("details", {}),
                                "user_agent": act.get("user_agent", "Unknown")[:100],
                                "method": act.get("method", "GET"),
                                "status": "live"
                            })
                except Exception:
                    pass
                
                # Also fetch victims for location data
                resp = await client.get(f"{target_url}/api/victims")
                if resp.status_code == 200:
                    data = resp.json()
                    for victim in data.get("victims", []):
                        # Convert victim to activity format
                        combined_activity.append({
                            "id": f"victim_{victim.get('ip', 'unknown')}",
                            "timestamp": victim.get("timestamp", datetime.now().isoformat()),
                            "ip": victim.get("ip", "unknown"),
                            "action": "page_visit",
                            "page": victim.get("url", "/"),
                            "details": {"location": victim.get("location", {})},
                            "user_agent": victim.get("ua", "Unknown")[:100],
                            "method": "GET",
                            "status": "tracked"
                        })
        except Exception as e:
            logging.debug(f"Could not fetch from vulnerable app: {e}")
        
        # Deduplicate by timestamp and IP
        seen = set()
        unique_activities = []
        for act in combined_activity:
            key = (act.get("timestamp", ""), act.get("ip", ""), act.get("page", ""))
            if key not in seen:
                seen.add(key)
                unique_activities.append(act)
        
        # Sort by timestamp (newest first) and return last 50
        unique_activities.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        return {
            "success": True,
            "activities": unique_activities[:50],
            "total": len(unique_activities),
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logging.error(f"Failed to get live activity: {e}")
        return {"success": False, "activities": [], "error": "An internal server error occurred while processing your request."}


@router.get("/network/graph-data")
async def api_get_graph_data():
    """Get data formatted for connection visualization graph."""
    if not PSUTIL_AVAILABLE:
        return {"success": False, "error": "psutil not installed", "nodes": [], "links": []}
    
    try:
        nodes = []
        links = []
        node_ids = set()
        
        # Add server node
        server_id = "server"
        nodes.append({
            "id": server_id,
            "label": "VigilEdge Server",
            "type": "server",
            "group": 0
        })
        node_ids.add(server_id)
        
        # Get established connections
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                local_port = conn.laddr.port if conn.laddr else 0
                
                # Skip loopback
                if remote_ip.startswith('127.') or remote_ip == '::1':
                    continue
                
                # Add remote node
                node_id = f"remote_{remote_ip}"
                if node_id not in node_ids:
                    nodes.append({
                        "id": node_id,
                        "label": remote_ip,
                        "type": "remote",
                        "group": 1 if is_private_ip(remote_ip) else 2
                    })
                    node_ids.add(node_id)
                
                # Add link
                links.append({
                    "source": server_id,
                    "target": node_id,
                    "local_port": local_port,
                    "remote_port": remote_port,
                    "type": "established"
                })
        
        # Add listening ports as separate nodes
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN' and conn.laddr:
                port = conn.laddr.port
                service = get_service_name(port)
                
                port_id = f"port_{port}"
                if port_id not in node_ids:
                    nodes.append({
                        "id": port_id,
                        "label": f":{port} ({service})",
                        "type": "port",
                        "group": 3
                    })
                    node_ids.add(port_id)
                    
                    links.append({
                        "source": server_id,
                        "target": port_id,
                        "type": "listening"
                    })
        
        return {
            "success": True,
            "nodes": nodes[:50],  # Limit nodes
            "links": links[:100],  # Limit links
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logging.error(f"Failed to get graph data: {e}")
        return {"success": False, "nodes": [], "links": [], "error": "An internal server error occurred while processing your request."}
