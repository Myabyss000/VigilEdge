"""
Dashboard routes - server-rendered HTML pages.
"""
import psutil
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func, desc, and_
from sqlalchemy.ext.asyncio import AsyncSession

from threatloom.database import get_db
from threatloom.models.logs import FirewallLog, AttackType, LogAction
from threatloom.models.alerts import Alert, AlertSeverity, AlertStatus
from threatloom.models.incidents import Incident, IncidentStatus
from threatloom.models.responses import AutomatedResponse, ResponseStatus

dashboard_router = APIRouter()
templates = Jinja2Templates(directory="dashboard/templates")


@dashboard_router.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request, db: AsyncSession = Depends(get_db)):
    """Main SOC dashboard."""
    now = datetime.utcnow()
    cutoff_24h = now - timedelta(hours=24)

    # Stats queries
    total_logs = await db.execute(
        select(func.count(FirewallLog.id)).where(FirewallLog.timestamp >= cutoff_24h)
    )
    total_blocked = await db.execute(
        select(func.count(FirewallLog.id)).where(
            and_(FirewallLog.timestamp >= cutoff_24h, FirewallLog.action == LogAction.BLOCKED)
        )
    )
    total_alerts = await db.execute(
        select(func.count(Alert.id)).where(Alert.created_at >= cutoff_24h)
    )
    active_alerts = await db.execute(
        select(func.count(Alert.id)).where(
            Alert.status.in_([AlertStatus.NEW, AlertStatus.ACKNOWLEDGED])
        )
    )
    open_incidents = await db.execute(
        select(func.count(Incident.id)).where(
            Incident.status.in_([IncidentStatus.NEW, IncidentStatus.INVESTIGATING])
        )
    )
    active_blocks = await db.execute(
        select(func.count(AutomatedResponse.id)).where(
            AutomatedResponse.status == ResponseStatus.ACTIVE
        )
    )

    # Recent alerts
    recent_alerts_result = await db.execute(
        select(Alert).order_by(desc(Alert.created_at)).limit(20)
    )
    recent_alerts = recent_alerts_result.scalars().all()

    # Top attackers
    top_attackers_result = await db.execute(
        select(FirewallLog.src_ip, FirewallLog.geo_country, func.count(FirewallLog.id).label("cnt"))
        .where(and_(FirewallLog.timestamp >= cutoff_24h, FirewallLog.attack_type != AttackType.NONE))
        .group_by(FirewallLog.src_ip, FirewallLog.geo_country)
        .order_by(desc("cnt")).limit(10)
    )
    top_attackers = [
        {"ip": r[0], "country": r[1] or "??", "count": r[2]}
        for r in top_attackers_result.all()
    ]

    # Attack distribution
    attack_dist_result = await db.execute(
        select(FirewallLog.attack_type, func.count(FirewallLog.id).label("cnt"))
        .where(and_(FirewallLog.timestamp >= cutoff_24h, FirewallLog.attack_type != AttackType.NONE))
        .group_by(FirewallLog.attack_type).order_by(desc("cnt"))
    )
    attack_dist = {
        str(r[0].value) if r[0] else "OTHER": r[1]
        for r in attack_dist_result.all()
    }

    # Severity distribution
    severity_dist_result = await db.execute(
        select(Alert.severity, func.count(Alert.id).label("cnt"))
        .where(Alert.created_at >= cutoff_24h)
        .group_by(Alert.severity)
    )
    severity_dist = {
        str(r[0].value): r[1] for r in severity_dist_result.all()
    }

    # Geo distribution
    geo_result = await db.execute(
        select(
            FirewallLog.geo_country,
            FirewallLog.geo_lat,
            FirewallLog.geo_lon,
            func.count(FirewallLog.id).label("cnt")
        )
        .where(and_(
            FirewallLog.timestamp >= cutoff_24h,
            FirewallLog.attack_type != AttackType.NONE,
            FirewallLog.geo_country != None,
        ))
        .group_by(FirewallLog.geo_country, FirewallLog.geo_lat, FirewallLog.geo_lon)
        .order_by(desc("cnt")).limit(20)
    )
    geo_data = [
        {"country": r[0], "lat": r[1], "lon": r[2], "count": r[3]}
        for r in geo_result.all()
    ]

    # System metrics
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory().percent

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "total_logs": total_logs.scalar() or 0,
        "total_blocked": total_blocked.scalar() or 0,
        "total_alerts": total_alerts.scalar() or 0,
        "active_alerts": active_alerts.scalar() or 0,
        "open_incidents": open_incidents.scalar() or 0,
        "active_blocks": active_blocks.scalar() or 0,
        "recent_alerts": recent_alerts,
        "top_attackers": top_attackers,
        "attack_dist": attack_dist,
        "severity_dist": severity_dist,
        "geo_data": geo_data,
        "cpu_percent": cpu,
        "memory_percent": mem,
    })


@dashboard_router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page."""
    return templates.TemplateResponse("login.html", {"request": request})


@dashboard_router.get("/alerts-view", response_class=HTMLResponse)
async def alerts_page(request: Request, db: AsyncSession = Depends(get_db)):
    """Alerts management page."""
    result = await db.execute(
        select(Alert).order_by(desc(Alert.created_at)).limit(100)
    )
    alerts = result.scalars().all()
    return templates.TemplateResponse("alerts.html", {
        "request": request,
        "alerts": alerts,
    })


@dashboard_router.get("/incidents-view", response_class=HTMLResponse)
async def incidents_page(request: Request, db: AsyncSession = Depends(get_db)):
    """Incidents management page."""
    result = await db.execute(
        select(Incident).order_by(desc(Incident.created_at)).limit(100)
    )
    incidents = result.scalars().all()
    return templates.TemplateResponse("incidents.html", {
        "request": request,
        "incidents": incidents,
    })


@dashboard_router.get("/logs-view", response_class=HTMLResponse)
async def logs_page(request: Request, db: AsyncSession = Depends(get_db)):
    """Log viewer page."""
    result = await db.execute(
        select(FirewallLog).order_by(desc(FirewallLog.timestamp)).limit(200)
    )
    logs = result.scalars().all()
    return templates.TemplateResponse("logs.html", {
        "request": request,
        "logs": logs,
    })
