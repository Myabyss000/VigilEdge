"""
VigilEdge WAF - Application Factory
Creates and configures the FastAPI application with all middleware and routes.
"""

import os
import asyncio
import sqlite3
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import FileResponse, Response
import httpx

from vigiledge.config import get_settings, get_cors_origins
from vigiledge.core.waf_engine import WAFEngine
from vigiledge.api.routes import setup_routes
from vigiledge.middleware.security_middleware import SecurityMiddleware
from vigiledge.utils.logger import setup_logging
from vigiledge.utils.settings_loader import load_user_settings

from services.websocket_manager import manager
from services.background_tasks import animated_startup, monitoring_task, auto_backup_task
from vigiledge.utils.upstream_config import get_upstream_proxy_path, should_proxy_root_request
from routes.proxy import close_upstream_http_client


# Initialize settings and logging
settings = get_settings()

# Load user settings from waf_settings.json and apply overrides
try:
    user_settings_loader = load_user_settings()
    if user_settings_loader and user_settings_loader.user_settings:
        user_settings_loader.apply_to_app_settings(settings)
except Exception as e:
    logging.warning(f"Could not load user settings, using defaults: {e}")

setup_logging()

# Configure logging to suppress WebSocket connection errors
logging.getLogger("websockets.protocol").setLevel(logging.ERROR)
logging.getLogger("websockets.server").setLevel(logging.ERROR)
logging.getLogger("uvicorn.protocols.websockets").setLevel(logging.ERROR)
logging.getLogger("uvicorn.error").setLevel(logging.WARNING)

# Initialize WAF Engine as a global singleton
waf_engine = WAFEngine()
print(f"🌟 APP: WAF Engine created at module level! ID: {id(waf_engine)}")

# Path configuration
current_dir = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(current_dir, "static")
templates_dir = os.path.join(current_dir, "templates")

templates = Jinja2Templates(directory=templates_dir)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager with animated startup."""
    # Animated startup sequence
    animated_startup()
    
    # 🔄 Clear WAF in-memory state (fresh session)
    print(f"\n🔄 Resetting WAF Session State...")
    waf_engine.blocked_ips.clear()
    waf_engine.rate_limits.clear()
    waf_engine.metrics.reset()
    waf_engine.security_events.clear()
    waf_engine.connection_table.clear()
    waf_engine.request_patterns.clear()
    waf_engine.user_agent_cache.clear()
    print(f"   ✅ Blocked IPs cleared")
    print(f"   ✅ Rate limits reset")
    print(f"   ✅ Metrics reset to zero")
    print(f"   ✅ In-memory events cleared")
    print(f"   ✅ DDoS tracking data cleared")
    
    # 🗑️ Clear database (fresh start)
    print(f"\n🗑️  Clearing Database...")
    try:
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM security_events')
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        print(f"   ✅ Database cleared: {deleted_count} events deleted")
        print(f"   🆕 Fresh session - starting from zero")
    except Exception as e:
        print(f"   ⚠️  Database clear failed: {e}")
    
    # Show connection info
    display_host = "127.0.0.1" if settings.host == "0.0.0.0" else settings.host
    print(f"\n🌐 Server Information:")
    print(f"   📊 Dashboard: http://{display_host}:{settings.port}")
    print(f"   📖 API Docs: http://{display_host}:{settings.port}/docs")
    print(f"   🔧 Environment: {settings.environment}")
    print(f"   🛡️  Security Level: Maximum")
    
    # Check vulnerable application status
    if settings.vulnerable_app_enabled:
        print(f"\n🎯 Protected Website:")
        print(f"   🔗 Target: {settings.vulnerable_app_url}")
        print(f"   🛡️  Proxy Path: http://{display_host}:{settings.port}{get_upstream_proxy_path(settings)}")
        print(f"   🌍 Public Mode: {settings.upstream_public_mode}")
        
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{settings.vulnerable_app_url}/health")
                if response.status_code == 200:
                    print(f"   ✅ Status: ONLINE (Protected)")
                else:
                    print(f"   ⚠️  Status: REACHABLE but unhealthy")
        except:
            print(f"   ❌ Status: OFFLINE")
            print(f"   💡 Tip: Start with 'python vulnerable_app.py' in another terminal")
    
    print("\n" + "="*60)
    print("📡 REAL-TIME MONITORING ACTIVE")
    print("="*60)
    
    # Start background monitoring
    monitoring_task_handle = asyncio.create_task(monitoring_task(waf_engine, manager))
    
    # Start auto-backup scheduler if enabled
    backup_task_handle = None
    if user_settings_loader and user_settings_loader.user_settings:
        backup_settings = user_settings_loader.get_backup_settings()
        if backup_settings.get("auto_backup", False):
            backup_task_handle = asyncio.create_task(
                auto_backup_task(backup_settings.get("backup_frequency", "daily"))
            )
            print(f"💾 Auto-backup enabled: {backup_settings.get('backup_frequency', 'daily')}")
    
    yield
    
    # Shutdown sequence
    print("\n\n🛑 VigilEdge WAF Shutting down...")
    print("🔒 Closing security connections...")
    monitoring_task_handle.cancel()
    if backup_task_handle:
        backup_task_handle.cancel()
    try:
        await monitoring_task_handle
        if backup_task_handle:
            await backup_task_handle
    except asyncio.CancelledError:
        pass
    await close_upstream_http_client()
    print("✅ Shutdown complete. Stay secure! 🛡️")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="VigilEdge WAF",
        description="Advanced Web Application Firewall with Real-time Threat Detection",
        version="1.0.0",
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
        lifespan=lifespan
    )
    
    # Add CORS middleware - Allow all local origins for development
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_cors_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Add security middleware
    app.add_middleware(SecurityMiddleware, waf_engine=waf_engine)
    
    # Mount static files
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    
    # Store waf_engine and manager in app state for access from routes
    app.state.waf_engine = waf_engine
    app.state.manager = manager
    app.state.templates = templates
    app.state.settings = settings
    
    # Include all routers
    from routes import (
        dashboard_router,
        blocked_ips_router,
        events_router,
        metrics_router,
        settings_router,
        network_router,
        ai_router,
        chatbot_router,
        proxy_router,
        websocket_router,
        auth_router,
    )
    
    app.include_router(dashboard_router)
    app.include_router(blocked_ips_router)
    app.include_router(events_router)
    app.include_router(metrics_router)
    app.include_router(settings_router)
    app.include_router(network_router)
    app.include_router(ai_router)
    app.include_router(chatbot_router)
    app.include_router(websocket_router)
    app.include_router(auth_router)
    app.include_router(proxy_router)
    
    # Setup legacy routes (from vigiledge.api.routes)
    setup_routes(app, waf_engine, manager)

    # Favicon endpoint
    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        """Serve favicon to prevent 404 errors."""
        favicon_path = os.path.join(static_dir, "favicon.ico")
        if os.path.exists(favicon_path):
            return FileResponse(favicon_path)
        else:
            # Return a minimal 1x1 transparent ICO
            ico_data = bytes([
                0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00,
                0x18, 0x00, 0x30, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x28, 0x00,
                0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00,
                0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ])
            return Response(content=ico_data, media_type="image/x-icon")

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"], include_in_schema=False)
    async def root_upstream_proxy(request: Request, path: str = ""):
        """Proxy non-WAF root paths to the configured upstream website."""
        request_path = f"/{path}" if path else "/"
        if not should_proxy_root_request(request_path, request.app.state.settings):
            return Response(status_code=404)

        from routes.proxy import proxy_upstream_request

        return await proxy_upstream_request(request, path=path, public_base_path="")
    
    return app


# Create application instance for ASGI servers
app = create_app()
