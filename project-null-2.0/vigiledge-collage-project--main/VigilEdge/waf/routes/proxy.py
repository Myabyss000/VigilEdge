"""
Proxy Routes for VigilEdge WAF
Handles reverse proxy functionality for protecting backend applications.
"""

import re
import json
import logging
import asyncio
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse, Response
import httpx

from vigiledge.utils.upstream_config import (
    get_selected_upstream_url,
    get_upstream_proxy_path,
    should_proxy_root_request,
    upstream_subpath_enabled,
)
from vigiledge.utils.client_ip import get_effective_client_ip
from .auth import require_control_plane_access

router = APIRouter(tags=["Proxy"])

_upstream_client: httpx.AsyncClient | None = None


def get_upstream_http_client() -> httpx.AsyncClient:
    """Reuse a shared upstream client so protected requests benefit from connection pooling."""
    global _upstream_client
    if _upstream_client is None or _upstream_client.is_closed:
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)
        _upstream_client = httpx.AsyncClient(timeout=30.0, limits=limits)
    return _upstream_client


async def close_upstream_http_client():
    """Close the shared upstream client during application shutdown."""
    global _upstream_client
    if _upstream_client is not None and not _upstream_client.is_closed:
        await _upstream_client.aclose()
    _upstream_client = None


def get_waf_engine():
    """Get WAF engine from app state."""
    from app import waf_engine
    return waf_engine


def get_settings():
    """Get application settings."""
    from vigiledge.config import get_settings as _get_settings
    return _get_settings()


def get_ws_manager():
    """Get WebSocket manager."""
    from services.websocket_manager import manager
    return manager


@router.api_route("/proxy", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_request(request: Request):
    """Proxy endpoint to protect backend applications."""
    waf_engine = get_waf_engine()
    settings = get_settings()
    manager = get_ws_manager()
    
    try:
        target_url = request.query_params.get("target")
        if not target_url:
            raise HTTPException(status_code=400, detail="Target URL is required")
        
        client_ip = request.client.host if request.client else "unknown"
        method = request.method
        headers = dict(request.headers)
        body = await request.body()
        
        allowed, security_event = await waf_engine.process_request(
            method=method,
            url=target_url,
            headers=headers,
            body=body.decode() if body else None,
            client_ip=client_ip
        )
        
        if not allowed:
            await manager.broadcast(json.dumps({
                "type": "alert",
                "message": f"🚫 {security_event.threat_type.upper()} blocked from {client_ip}"
            }))
            
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Request blocked by WAF",
                    "reason": security_event.threat_type,
                    "event_id": security_event.id
                }
            )
        
        client = get_upstream_http_client()
        headers.pop("host", None)
        headers.pop("content-length", None)
        
        response = await client.request(
            method=method,
            url=target_url,
            headers=headers,
            content=body,
            timeout=settings.proxy_timeout
        )

        return JSONResponse(
            status_code=response.status_code,
            content=response.json() if response.headers.get("content-type", "").startswith("application/json") else {"data": response.text},
            headers=dict(response.headers)
        )
            
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail="Bad Gateway: Proxy connection failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


async def _track_visitor(client_ip: str, user_agent: str, url: str):
    """
    Track a visitor with server-side geolocation (runs in background).
    This is called for every request through /protected/ proxy.
    """
    try:
        from routes.api_network import get_ip_location, track_user_connection
        
        # Get location from server-side geolocation
        location = await get_ip_location(client_ip)
        
        # Track the user
        track_user_connection(
            ip=client_ip,
            user_agent=user_agent,
            url=url,
            location=location
        )
    except Exception as e:
        logging.debug(f"Visitor tracking failed for {client_ip}: {e}")


def _get_client_ip(request: Request) -> str:
    """Resolve the real client IP using trusted reverse-proxy rules."""
    return get_effective_client_ip(request, settings_obj=getattr(request.app.state, "settings", None))


def _wants_json_response(headers: dict) -> bool:
    content_type = headers.get('content-type', '').lower()
    accept_header = headers.get('accept', '').lower()
    return 'application/json' in content_type or 'application/json' in accept_header


def _build_target_url(settings, path: str = "") -> str:
    upstream_url = get_selected_upstream_url(settings)
    return f"{upstream_url}/{path}" if path else upstream_url


async def proxy_upstream_request(request: Request, path: str = "", public_base_path: str | None = None):
    """Proxy a request to the configured upstream website with WAF inspection."""
    waf_engine = get_waf_engine()
    settings = get_settings()
    manager = get_ws_manager()

    try:
        target_url = _build_target_url(settings, path)
        if request.url.query:
            target_url += f"?{request.url.query}"

        client_ip = _get_client_ip(request)
        method = request.method
        headers = dict(request.headers)
        body = await request.body()

        allowed, security_event = await waf_engine.process_request(
            method=method,
            url=target_url,
            headers=headers,
            body=body.decode() if body else None,
            client_ip=client_ip
        )

        effective_base_path = public_base_path if public_base_path is not None else get_upstream_proxy_path(settings)
        home_path = effective_base_path or "/"

        if not allowed:
            await manager.broadcast(json.dumps({
                "type": "alert",
                "message": f"🚫 {security_event.threat_type.upper()} blocked from {client_ip}"
            }))

            if _wants_json_response(headers):
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Request blocked by VigilEdge WAF",
                        "reason": security_event.threat_type,
                        "event_id": security_event.id,
                        "timestamp": security_event.timestamp.isoformat(),
                        "details": "Your request has been identified as potentially malicious"
                    },
                    headers={
                        "X-WAF-Status": "BLOCKED",
                        "X-WAF-Event-ID": security_event.id,
                        "X-WAF-Threat-Type": security_event.threat_type,
                    }
                )

            return HTMLResponse(
                content=_get_blocked_html(security_event, home_path),
                status_code=403
            )

        user_agent = headers.get('user-agent', 'Unknown')
        asyncio.create_task(_track_visitor(client_ip, user_agent, target_url))

        client = get_upstream_http_client()
        forward_headers = {
            k: v for k, v in headers.items()
            if k.lower() not in ['host', 'content-length', 'x-forwarded-for', 'x-real-ip']
        }

        forward_headers['X-Forwarded-For'] = client_ip
        forward_headers['X-Real-IP'] = client_ip
        forward_headers['X-Forwarded-Proto'] = 'https' if request.url.scheme == 'https' else 'http'
        forward_headers['X-Forwarded-Host'] = request.headers.get('host', 'localhost:5000')

        try:
            response = await client.request(
                method=method,
                url=target_url,
                headers=forward_headers,
                content=body if body else None,
                follow_redirects=False,
                timeout=settings.proxy_timeout,
            )

            content = response.content
            content_type = response.headers.get('content-type', '')

            if 'text/html' in content_type:
                try:
                    html_content = content.decode('utf-8')
                    html_content = _rewrite_html_links(html_content, effective_base_path)
                    content = html_content.encode('utf-8')
                except Exception:
                    pass

            response_headers = dict(response.headers)
            response_headers['content-length'] = str(len(content))
            response_headers.pop('transfer-encoding', None)

            return Response(
                content=content,
                status_code=response.status_code,
                headers=response_headers,
                media_type=response.headers.get('content-type', 'text/html')
            )

        except httpx.ConnectError:
            return HTMLResponse(
                content=_get_backend_unavailable_html(settings, home_path),
                status_code=503
            )

    except Exception as e:
        return HTMLResponse(
            content=_get_error_html("502 Bad Gateway: Upstream server is down"),
            status_code=500
        )


@router.api_route("/protected/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
@router.api_route("/protected", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"], include_in_schema=False)
async def protected_proxy(request: Request, path: str = ""):
    """
    Protected proxy endpoint - All requests go through WAF protection
    Access vulnerable app through this endpoint for full WAF protection
    Example: http://localhost:5000/protected/login
    """
    settings = get_settings()
    if not upstream_subpath_enabled(settings):
        return JSONResponse(
            status_code=404,
            content={"error": "Protected subpath mode is disabled for the upstream website."}
        )
    return await proxy_upstream_request(request, path=path, public_base_path=get_upstream_proxy_path(settings))


@router.get("/api/v1/test/{path:path}")
async def test_proxy_get(path: str, request: Request):
    """Proxy GET requests to the demo target for testing WAF protection."""
    try:
        settings = get_settings()
        demo_target_url = settings.upstream_demo_target_url.rstrip('/')
        target_url = f"{demo_target_url}/{path}"
        query_string = str(request.url.query)
        if query_string:
            target_url += f"?{query_string}"
        
        headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(target_url, headers=headers)
            
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get('content-type', 'text/html')
            )
    except httpx.RequestError as e:
        return JSONResponse(
            content={
                "error": "Demo website is not running",
                "message": f"Could not connect to {demo_target_url} (Connection Failed)",
                "instruction": "Start the demo website or switch the upstream target in settings."
            },
            status_code=503
        )
    except Exception as e:
        return JSONResponse(
            content={"error": "Proxy error", "message": "Upstream connection failed"},
            status_code=500
        )


@router.post("/api/v1/test/{path:path}")
async def test_proxy_post(path: str, request: Request):
    """Proxy POST requests to the demo target for testing WAF protection."""
    try:
        settings = get_settings()
        demo_target_url = settings.upstream_demo_target_url.rstrip('/')
        target_url = f"{demo_target_url}/{path}"
        body = await request.body()
        headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(target_url, content=body, headers=headers)
            
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get('content-type', 'text/html')
            )
    except httpx.RequestError as e:
        return JSONResponse(
            content={
                "error": "Demo website is not running",
                "message": f"Could not connect to {demo_target_url} (Connection Failed)",
                "instruction": "Start the demo website or switch the upstream target in settings."
            },
            status_code=503
        )
    except Exception as e:
        return JSONResponse(
            content={"error": "Proxy error", "message": "Upstream connection failed"},
            status_code=500
        )


@router.get("/test-target")
async def test_target_status(control_plane=Depends(require_control_plane_access)):
    """Check if the currently selected upstream target is running."""
    settings = get_settings()
    target_url = get_selected_upstream_url(settings)
    
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{target_url}/health")
            if response.status_code == 200:
                return JSONResponse({
                    "status": "online",
                    "message": "Selected upstream website is running",
                    "target_url": target_url,
                    "proxy_url": f"http://{settings.host}:{settings.port}{get_upstream_proxy_path(settings)}",
                    "dashboard": f"http://{settings.host}:{settings.port}/admin/dashboard",
                    "mode": settings.upstream_public_mode,
                    "using_demo_target": settings.upstream_use_demo_target,
                })
    except:
        pass
    
    return JSONResponse({
        "status": "offline",
        "message": "Selected upstream website is not running",
        "instruction": "Start the configured upstream website or switch to the demo target in settings.",
        "target_url": target_url,
        "mode": settings.upstream_public_mode,
        "using_demo_target": settings.upstream_use_demo_target,
    }, status_code=503)


# Helper functions for HTML generation

def _rewrite_html_links(html_content: str, public_base_path: str) -> str:
    """Rewrite HTML links to include the active public proxy prefix when needed."""
    normalized_base = (public_base_path or "").rstrip("/")
    if normalized_base in {"", "/"}:
        return html_content

    escaped_base_segment = re.escape(normalized_base.lstrip("/"))

    # Fix href attributes
    html_content = re.sub(
        rf'href=["\']/(?!{escaped_base_segment})([^"\']*)["\']',
        fr'href="{normalized_base}/\1"',
        html_content
    )
    
    # Fix action attributes
    html_content = re.sub(
        rf'action=["\']/(?!{escaped_base_segment})([^"\']*)["\']',
        fr'action="{normalized_base}/\1"',
        html_content
    )
    
    # Fix src attributes
    html_content = re.sub(
        rf'src=["\']/(?!{escaped_base_segment}|http)([^"\']*)["\']',
        fr'src="{normalized_base}/\1"',
        html_content
    )
    
    # Fix JavaScript fetch() calls with absolute paths (single and double quotes)
    # Pattern: fetch('/api/...' or fetch("/api/..."
    html_content = re.sub(
        rf"fetch\s*\(\s*['\"]\/(?!{escaped_base_segment})([^'\"]*)['\"]",
        fr"fetch('{normalized_base}/\1'",
        html_content
    )
    
    # Fix JavaScript API endpoints in template literals: fetch(`/api/...`)
    html_content = re.sub(
        rf"fetch\s*\(\s*`\/(?!{escaped_base_segment})([^`]*)`",
        fr"fetch(`{normalized_base}/\1`",
        html_content
    )
    
    # Fix XMLHttpRequest.open() calls
    html_content = re.sub(
        rf"\.open\s*\(\s*['\"][^'\"]*['\"]\s*,\s*['\"]\/(?!{escaped_base_segment})([^'\"]*)['\"]",
        fr".open('GET', '{normalized_base}/\1'",
        html_content
    )
    
    # Fix axios and other libraries: axios.get('/api/...')
    html_content = re.sub(
        rf"(axios\.\w+|jQuery\.\w+|\$\.\w+)\s*\(\s*['\"]\/(?!{escaped_base_segment})([^'\"]*)['\"]",
        fr"\1('{normalized_base}/\2'",
        html_content
    )
    
    # Add base tag
    if '<head>' in html_content:
        html_content = html_content.replace(
            '<head>',
            f'<head>\n    <base href="{normalized_base}/">'
        )
    
    return html_content


def _get_blocked_html(security_event, home_path: str) -> str:
    """Generate HTML for blocked request page."""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Request Blocked - VigilEdge WAF</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                color: #fff;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }}
            .container {{
                text-align: center;
                padding: 40px;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                border: 2px solid rgba(255, 107, 107, 0.5);
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            }}
            h1 {{ color: #ff6b6b; margin-bottom: 20px; }}
            .icon {{ font-size: 64px; margin-bottom: 20px; }}
            .details {{ 
                background: rgba(0, 0, 0, 0.3); 
                padding: 20px; 
                border-radius: 8px;
                margin-top: 20px;
                text-align: left;
            }}
            .back-btn {{
                display: inline-block;
                margin-top: 20px;
                padding: 12px 24px;
                background: #00d4ff;
                color: #000;
                text-decoration: none;
                border-radius: 6px;
                font-weight: bold;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="icon">🛡️</div>
            <h1>Request Blocked by VigilEdge WAF</h1>
            <p>Your request has been identified as potentially malicious and was blocked.</p>
            <div class="details">
                <p><strong>Event ID:</strong> {security_event.id}</p>
                <p><strong>Threat Type:</strong> {security_event.threat_type.upper()}</p>
                <p><strong>Threat Level:</strong> {security_event.threat_level.value.upper()}</p>
                <p><strong>Timestamp:</strong> {security_event.timestamp}</p>
            </div>
            <a href="{home_path}" class="back-btn">← Back to Home</a>
        </div>
    </body>
    </html>
    """


def _get_backend_unavailable_html(settings, home_path: str) -> str:
    """Generate HTML for backend unavailable page."""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Backend Unavailable - VigilEdge WAF</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                color: #fff;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }}
            .container {{
                text-align: center;
                padding: 40px;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                border: 2px solid rgba(255, 179, 71, 0.5);
            }}
            h1 {{ color: #ffb347; }}
            .icon {{ font-size: 64px; margin-bottom: 20px; }}
            .command {{
                background: rgba(0, 0, 0, 0.5);
                padding: 15px;
                border-radius: 6px;
                font-family: 'Courier New', monospace;
                color: #00ff87;
            }}
            .back-btn {{
                display: inline-block;
                margin-top: 20px;
                padding: 12px 24px;
                background: #00d4ff;
                color: #000;
                text-decoration: none;
                border-radius: 6px;
                font-weight: bold;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="icon">⚠️</div>
            <h1>Backend Application Not Available</h1>
            <p>The selected upstream website is not reachable at <strong>{settings.vulnerable_app_url}</strong></p>
            <p>Start your custom website or switch to the demo website target in the WAF settings.</p>
            <div class="command">Current mode: {settings.upstream_public_mode} | Demo target: {str(settings.upstream_use_demo_target).lower()}</div>
            <p><small>VigilEdge is ready and waiting to protect your website.</small></p>
            <a href="{home_path}" class="back-btn">← Retry Home</a>
        </div>
    </body>
    </html>
    """


def _get_error_html(error_message: str) -> str:
    """Generate HTML for generic error page."""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Error - VigilEdge WAF</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                color: #fff;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }}
            .container {{
                text-align: center;
                padding: 40px;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 12px;
            }}
            h1 {{ color: #ff6b6b; }}
            .error {{
                background: rgba(0, 0, 0, 0.3);
                padding: 15px;
                border-radius: 6px;
                margin-top: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔥 Proxy Error</h1>
            <p>An error occurred while processing your request.</p>
            <div class="error"><code>{error_message}</code></div>
        </div>
    </body>
    </html>
    """
