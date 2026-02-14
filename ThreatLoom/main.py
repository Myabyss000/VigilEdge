"""
ThreatLoom - SOC Platform for Custom Firewall / WAF
Main application entry point.
"""
import asyncio
import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from threatloom.config import settings
from threatloom.database import engine, Base, async_session
from threatloom.api.v1.router import api_router
from threatloom.api.v1.dashboard import dashboard_router
from threatloom.websocket.manager import ws_router
from threatloom.auth.rbac import create_default_admin
from threatloom.detection.engine import DetectionEngine
from threatloom.storage.retention import RetentionManager

logger = logging.getLogger("threatloom")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown."""
    # --- Startup ---
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL),
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    )
    logger.info("ThreatLoom SOC Platform starting...")

    # Create database tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables initialized.")

    # Create default admin user
    async with async_session() as session:
        await create_default_admin(session)

    # ── Firewall connectivity check ─────────────────────────────────────
    if settings.FIREWALL_WEBHOOK_ENABLED and settings.FIREWALL_STARTUP_CHECK:
        firewall_connected = False
        health_url = settings.FIREWALL_HEALTH_URL.rstrip("/")
        logger.info(f"Checking firewall connectivity at {health_url}...")

        for attempt in range(1, settings.FIREWALL_STARTUP_RETRIES + 1):
            try:
                async with httpx.AsyncClient(timeout=5) as client:
                    resp = await client.get(health_url)
                    if resp.status_code < 500:
                        firewall_connected = True
                        logger.info(
                            f"Firewall connected (attempt {attempt}/{settings.FIREWALL_STARTUP_RETRIES}) "
                            f"— status {resp.status_code}"
                        )
                        break
            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                logger.warning(
                    f"Firewall not reachable (attempt {attempt}/{settings.FIREWALL_STARTUP_RETRIES}): {exc}"
                )
            except Exception as exc:
                logger.warning(f"Firewall check error: {exc}")

            if attempt < settings.FIREWALL_STARTUP_RETRIES:
                await asyncio.sleep(settings.FIREWALL_STARTUP_RETRY_DELAY)

        if firewall_connected:
            logger.info(
                f"Firewall webhook integration ACTIVE — commands will be sent to {settings.FIREWALL_WEBHOOK_URL}"
            )
        else:
            logger.error(
                f"Firewall at {health_url} is NOT reachable after {settings.FIREWALL_STARTUP_RETRIES} attempts. "
                f"Webhook actions will be recorded in-memory only. "
                f"Start your VigilEdge WAF and restart ThreatLoom, or set FIREWALL_STARTUP_CHECK=false."
            )
        app.state.firewall_connected = firewall_connected
    else:
        app.state.firewall_connected = False
        if not settings.FIREWALL_WEBHOOK_ENABLED:
            logger.warning(
                "Firewall webhook integration DISABLED. "
                "Set FIREWALL_WEBHOOK_ENABLED=true in .env to enable."
            )

    # Start detection engine background task
    detection_engine = DetectionEngine()
    detection_task = asyncio.create_task(detection_engine.run())
    app.state.detection_engine = detection_engine

    # Start retention manager
    retention = RetentionManager()
    retention_task = asyncio.create_task(retention.run_schedule())
    app.state.retention_manager = retention

    logger.info("ThreatLoom SOC Platform ready.")

    yield

    # --- Shutdown ---
    logger.info("ThreatLoom SOC Platform shutting down...")
    detection_task.cancel()
    retention_task.cancel()
    await engine.dispose()


app = FastAPI(
    title="ThreatLoom SOC Platform",
    description="Security Operations Center for Custom Firewall / WAF",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files & templates
app.mount("/static", StaticFiles(directory="dashboard/static"), name="static")

# API routes
app.include_router(api_router, prefix="/api/v1")

# Dashboard routes (server-rendered)
app.include_router(dashboard_router)

# WebSocket
app.include_router(ws_router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=settings.APP_DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
    )
