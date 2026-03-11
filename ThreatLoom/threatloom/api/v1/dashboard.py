"""
Dashboard routes - server-rendered HTML pages.
"""
import json
import shlex

from typing import Optional
from urllib.parse import urlencode

import psutil
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func, desc, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from threatloom.database import get_db
from threatloom.models.logs import FirewallLog, AttackType, LogAction, LogProtocol, LogSeverity
from threatloom.models.alerts import Alert, AlertSeverity, AlertStatus
from threatloom.models.incidents import Incident, IncidentPriority, IncidentStatus
from threatloom.models.responses import AutomatedResponse, ResponseStatus
from threatloom.models.users import User, UserRole

dashboard_router = APIRouter()
templates = Jinja2Templates(directory="dashboard/templates")


def _parse_datetime_param(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None

    normalized = value.strip()
    if not normalized:
        return None

    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    if parsed.tzinfo is not None:
        parsed = parsed.astimezone().replace(tzinfo=None)

    return parsed


def _datetime_local_value(value: Optional[datetime]) -> str:
    if not value:
        return ""
    return value.strftime("%Y-%m-%dT%H:%M")


def _resolve_time_window(request: Request, default_hours: Optional[int] = None) -> tuple[Optional[datetime], Optional[datetime], str]:
    now = datetime.utcnow()
    start = _parse_datetime_param(request.query_params.get("start"))
    end = _parse_datetime_param(request.query_params.get("end"))

    if start and end and start > end:
        start, end = end, start

    if default_hours is not None and not start and not end:
        end = now
        start = now - timedelta(hours=default_hours)
        label = f"Last {default_hours} hours"
    elif start and end:
        label = f"{start.strftime('%Y-%m-%d %H:%M')} to {end.strftime('%Y-%m-%d %H:%M')}"
    elif start:
        label = f"From {start.strftime('%Y-%m-%d %H:%M')}"
    elif end:
        label = f"Until {end.strftime('%Y-%m-%d %H:%M')}"
    else:
        label = "All time"

    return start, end, label


def _apply_time_filter(statement, column, start: Optional[datetime], end: Optional[datetime]):
    if start:
        statement = statement.where(column >= start)
    if end:
        statement = statement.where(column <= end)
    return statement


def _build_query_string(params: dict[str, Optional[str]]) -> str:
    filtered = {
        key: value
        for key, value in params.items()
        if value not in (None, "")
    }
    return urlencode(filtered)


def _time_query_string(start: Optional[datetime], end: Optional[datetime]) -> str:
    return _build_query_string({
        "start": _datetime_local_value(start),
        "end": _datetime_local_value(end),
    })


def _normalize_query_value(value: Optional[str]) -> str:
    return value.strip() if value else ""


def _parse_enum(enum_cls, value: str):
    if not value:
        return None

    try:
        return enum_cls(value)
    except ValueError:
        return None


def _parse_json_list(value: Optional[str]) -> list[str]:
    if not value:
        return []

    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return [value] if value else []

    if isinstance(parsed, list):
        return [str(item) for item in parsed if item not in (None, "")]

    return [str(parsed)] if parsed not in (None, "") else []


def _parse_int(value: str) -> Optional[int]:
    if not value:
        return None

    try:
        return int(value)
    except ValueError:
        return None


def _parse_hunt_query(query: str) -> tuple[dict[str, str], list[str]]:
    if not query:
        return {}, []

    aliases = {
        "src": "src_ip",
        "source": "src_ip",
        "srcip": "src_ip",
        "dst": "dst_ip",
        "dest": "dst_ip",
        "destination": "dst_ip",
        "dstip": "dst_ip",
        "method": "http_method",
        "path": "http_path",
        "uri": "http_path",
        "country": "country",
        "status": "http_status",
        "code": "http_status",
        "response": "http_status",
        "attack": "attack_type",
        "severity": "severity",
        "action": "action",
        "ua": "user_agent",
        "agent": "user_agent",
        "useragent": "user_agent",
        "mitre": "mitre_technique",
        "protocol": "protocol",
        "proto": "protocol",
        "text": "search",
        "search": "search",
    }

    parsed_filters: dict[str, str] = {}
    free_terms: list[str] = []

    try:
        tokens = shlex.split(query)
    except ValueError:
        tokens = query.split()

    for token in tokens:
        if ":" not in token:
            free_terms.append(token)
            continue

        raw_key, raw_value = token.split(":", 1)
        key = aliases.get(raw_key.lower())
        value = raw_value.strip()
        if not key or not value:
            free_terms.append(token)
            continue

        if key == "search" and key in parsed_filters:
            parsed_filters[key] = f"{parsed_filters[key]} {value}".strip()
        else:
            parsed_filters[key] = value

    return parsed_filters, free_terms


def _severity_rank(severity: Optional[AlertSeverity]) -> int:
    if severity == AlertSeverity.CRITICAL:
        return 4
    if severity == AlertSeverity.HIGH:
        return 3
    if severity == AlertSeverity.MEDIUM:
        return 2
    if severity == AlertSeverity.LOW:
        return 1
    return 0


def _time_bucket(value: Optional[datetime], window_minutes: int) -> str:
    if not value:
        return "unknown"
    floored_minute = (value.minute // window_minutes) * window_minutes
    bucket = value.replace(minute=floored_minute, second=0, microsecond=0)
    return bucket.isoformat()


def _group_alert_rows(alerts: list[Alert], window_minutes: int) -> list[dict]:
    grouped: dict[tuple[str, str, str, str], dict] = {}

    for alert in alerts:
        src_ip = alert.src_ip or "unknown"
        attack_type = alert.attack_type or "OTHER"
        http_path = alert.http_path or "-"
        bucket = _time_bucket(alert.created_at or alert.first_seen, window_minutes)
        key = (src_ip, attack_type, http_path, bucket)

        group = grouped.get(key)
        if group is None:
            group = {
                "group_id": f"{src_ip}|{attack_type}|{http_path}|{bucket}",
                "src_ip": alert.src_ip,
                "attack_type": alert.attack_type,
                "http_path": alert.http_path,
                "group_window": bucket,
                "highest_severity": alert.severity,
                "primary_alert": alert,
                "members": [],
                "total_events": 0,
                "alert_count": 0,
                "first_seen": alert.first_seen or alert.created_at,
                "last_seen": alert.last_seen or alert.created_at,
                "detection_sources": set(),
                "mitre_techniques": set(),
            }
            grouped[key] = group

        group["members"].append(alert)
        group["alert_count"] += 1
        group["total_events"] += alert.event_count or 1
        group["detection_sources"].add(alert.detection_source)
        if alert.mitre_technique:
            group["mitre_techniques"].add(alert.mitre_technique)

        current_first = alert.first_seen or alert.created_at
        current_last = alert.last_seen or alert.created_at
        if current_first and (group["first_seen"] is None or current_first < group["first_seen"]):
            group["first_seen"] = current_first
        if current_last and (group["last_seen"] is None or current_last > group["last_seen"]):
            group["last_seen"] = current_last

        if _severity_rank(alert.severity) > _severity_rank(group["highest_severity"]):
            group["highest_severity"] = alert.severity
        if (alert.last_seen or alert.created_at) and (group["primary_alert"].last_seen or group["primary_alert"].created_at) and \
           (alert.last_seen or alert.created_at) > (group["primary_alert"].last_seen or group["primary_alert"].created_at):
            group["primary_alert"] = alert

    grouped_rows = list(grouped.values())
    for row in grouped_rows:
        row["detection_sources"] = sorted(row["detection_sources"])
        row["mitre_techniques"] = sorted(row["mitre_techniques"])
        row["members"].sort(key=lambda alert: alert.created_at or alert.last_seen, reverse=True)
    grouped_rows.sort(key=lambda row: row["last_seen"] or row["first_seen"], reverse=True)
    return grouped_rows


@dashboard_router.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request, db: AsyncSession = Depends(get_db)):
    """Main SOC dashboard."""
    start_time, end_time, time_window_label = _resolve_time_window(request, default_hours=24)

    # Stats queries
    total_logs = await db.execute(_apply_time_filter(
        select(func.count(FirewallLog.id)),
        FirewallLog.timestamp,
        start_time,
        end_time,
    ))
    total_blocked = await db.execute(_apply_time_filter(
        select(func.count(FirewallLog.id)).where(FirewallLog.action == LogAction.BLOCKED),
        FirewallLog.timestamp,
        start_time,
        end_time,
    ))
    total_alerts = await db.execute(_apply_time_filter(
        select(func.count(Alert.id)),
        Alert.created_at,
        start_time,
        end_time,
    ))
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
    recent_alerts_stmt = _apply_time_filter(
        select(Alert),
        Alert.created_at,
        start_time,
        end_time,
    ).order_by(desc(Alert.created_at)).limit(20)
    recent_alerts_result = await db.execute(recent_alerts_stmt)
    recent_alerts = recent_alerts_result.scalars().all()

    # Top attackers
    top_attackers_stmt = _apply_time_filter(
        select(FirewallLog.src_ip, FirewallLog.geo_country, func.count(FirewallLog.id).label("cnt"))
        .where(FirewallLog.attack_type != AttackType.NONE),
        FirewallLog.timestamp,
        start_time,
        end_time,
    ).group_by(FirewallLog.src_ip, FirewallLog.geo_country)
    top_attackers_result = await db.execute(
        top_attackers_stmt
        .order_by(desc("cnt")).limit(10)
    )
    top_attackers = [
        {"ip": r[0], "country": r[1] or "??", "count": r[2]}
        for r in top_attackers_result.all()
    ]

    # Attack distribution
    attack_dist_stmt = _apply_time_filter(
        select(FirewallLog.attack_type, func.count(FirewallLog.id).label("cnt"))
        .where(FirewallLog.attack_type != AttackType.NONE),
        FirewallLog.timestamp,
        start_time,
        end_time,
    )
    attack_dist_result = await db.execute(
        attack_dist_stmt.group_by(FirewallLog.attack_type).order_by(desc("cnt"))
    )
    attack_dist = {
        str(r[0].value) if r[0] else "OTHER": r[1]
        for r in attack_dist_result.all()
    }

    # Severity distribution
    severity_dist_stmt = _apply_time_filter(
        select(Alert.severity, func.count(Alert.id).label("cnt")),
        Alert.created_at,
        start_time,
        end_time,
    ).group_by(Alert.severity)
    severity_dist_result = await db.execute(severity_dist_stmt)
    severity_dist = {
        str(r[0].value): r[1] for r in severity_dist_result.all()
    }

    # Geo distribution
    geo_stmt = _apply_time_filter(
        select(
            FirewallLog.geo_country,
            FirewallLog.geo_lat,
            FirewallLog.geo_lon,
            func.count(FirewallLog.id).label("cnt")
        )
        .where(and_(
            FirewallLog.attack_type != AttackType.NONE,
            FirewallLog.geo_country != None,
        )),
        FirewallLog.timestamp,
        start_time,
        end_time,
    )
    geo_result = await db.execute(
        geo_stmt.group_by(FirewallLog.geo_country, FirewallLog.geo_lat, FirewallLog.geo_lon)
        .order_by(desc("cnt")).limit(20)
    )
    geo_data = [
        {"country": r[0], "lat": r[1], "lon": r[2], "count": r[3]}
        for r in geo_result.all()
    ]

    # System metrics
    cpu = psutil.cpu_percent(interval=None)
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
        "time_filter_start": _datetime_local_value(start_time),
        "time_filter_end": _datetime_local_value(end_time),
        "time_window_label": time_window_label,
        "time_filter_query": _time_query_string(start_time, end_time),
    })


@dashboard_router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, db: AsyncSession = Depends(get_db)):
    """Login page."""
    admin_exists = (await db.execute(select(User.id).where(User.role == UserRole.ADMIN).limit(1))).scalar_one_or_none() is not None
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "bootstrap_required": not admin_exists,
            "bootstrap_token_required": bool((request.app.state.settings.BOOTSTRAP_ADMIN_TOKEN or "").strip()),
        },
    )


@dashboard_router.get("/alerts-view", response_class=HTMLResponse)
async def alerts_page(request: Request, db: AsyncSession = Depends(get_db)):
    """Alerts management page."""
    start_time, end_time, time_window_label = _resolve_time_window(request)
    severity = _normalize_query_value(request.query_params.get("severity"))
    status = _normalize_query_value(request.query_params.get("status"))
    src_ip = _normalize_query_value(request.query_params.get("src_ip"))
    attack_type = _normalize_query_value(request.query_params.get("attack_type"))
    detection_source = _normalize_query_value(request.query_params.get("detection_source"))
    mitre_technique = _normalize_query_value(request.query_params.get("mitre_technique"))
    incident_id = _normalize_query_value(request.query_params.get("incident_id"))
    search = _normalize_query_value(request.query_params.get("search"))
    group_window = _parse_int(_normalize_query_value(request.query_params.get("group_window"))) or 15

    severity_filter = _parse_enum(AlertSeverity, severity)
    status_filter = _parse_enum(AlertStatus, status)

    alerts_stmt = _apply_time_filter(
        select(Alert),
        Alert.created_at,
        start_time,
        end_time,
    )

    if severity_filter:
        alerts_stmt = alerts_stmt.where(Alert.severity == severity_filter)
    if status_filter:
        alerts_stmt = alerts_stmt.where(Alert.status == status_filter)
    if src_ip:
        alerts_stmt = alerts_stmt.where(Alert.src_ip.contains(src_ip))
    if attack_type:
        alerts_stmt = alerts_stmt.where(Alert.attack_type == attack_type)
    if detection_source:
        alerts_stmt = alerts_stmt.where(Alert.detection_source.contains(detection_source))
    if mitre_technique:
        alerts_stmt = alerts_stmt.where(Alert.mitre_technique.contains(mitre_technique))
    if incident_id.isdigit():
        alerts_stmt = alerts_stmt.where(Alert.incident_id == int(incident_id))
    if search:
        alerts_stmt = alerts_stmt.where(or_(
            Alert.alert_uid.contains(search),
            Alert.title.contains(search),
            Alert.description.contains(search),
            Alert.http_path.contains(search),
            Alert.src_ip.contains(search),
            Alert.attack_type.contains(search),
            Alert.mitre_technique.contains(search),
        ))

    alerts_stmt = alerts_stmt.order_by(desc(Alert.created_at)).limit(100)
    result = await db.execute(alerts_stmt)
    alerts = result.scalars().all()
    grouped_alerts = _group_alert_rows(alerts, group_window)
    return templates.TemplateResponse("alerts.html", {
        "request": request,
        "alerts": alerts,
        "grouped_alerts": grouped_alerts,
        "result_count": len(grouped_alerts),
        "raw_alert_count": len(alerts),
        "time_filter_start": _datetime_local_value(start_time),
        "time_filter_end": _datetime_local_value(end_time),
        "time_window_label": time_window_label,
        "time_filter_query": _time_query_string(start_time, end_time),
        "filters": {
            "severity": severity,
            "status": status,
            "src_ip": src_ip,
            "attack_type": attack_type,
            "detection_source": detection_source,
            "mitre_technique": mitre_technique,
            "incident_id": incident_id,
            "group_window": str(group_window),
            "search": search,
        },
    })


@dashboard_router.get("/incidents-view", response_class=HTMLResponse)
async def incidents_page(request: Request, db: AsyncSession = Depends(get_db)):
    """Incidents management page."""
    start_time, end_time, time_window_label = _resolve_time_window(request)
    status = _normalize_query_value(request.query_params.get("status"))
    priority = _normalize_query_value(request.query_params.get("priority"))
    affected_ip = _normalize_query_value(request.query_params.get("affected_ip"))
    attack_type = _normalize_query_value(request.query_params.get("attack_type"))
    mitre_technique = _normalize_query_value(request.query_params.get("mitre_technique"))
    search = _normalize_query_value(request.query_params.get("search"))

    status_filter = _parse_enum(IncidentStatus, status)
    priority_filter = _parse_enum(IncidentPriority, priority)

    incidents_stmt = _apply_time_filter(
        select(Incident).options(selectinload(Incident.alerts), selectinload(Incident.notes)),
        Incident.created_at,
        start_time,
        end_time,
    )

    if status_filter:
        incidents_stmt = incidents_stmt.where(Incident.status == status_filter)
    if priority_filter:
        incidents_stmt = incidents_stmt.where(Incident.priority == priority_filter)
    if affected_ip:
        incidents_stmt = incidents_stmt.where(Incident.affected_ips.contains(affected_ip))
    if attack_type:
        incidents_stmt = incidents_stmt.where(Incident.attack_types.contains(attack_type))
    if mitre_technique:
        incidents_stmt = incidents_stmt.where(Incident.mitre_techniques.contains(mitre_technique))
    if search:
        incidents_stmt = incidents_stmt.where(or_(
            Incident.incident_uid.contains(search),
            Incident.title.contains(search),
            Incident.description.contains(search),
            Incident.response_summary.contains(search),
            Incident.affected_ips.contains(search),
            Incident.attack_types.contains(search),
            Incident.mitre_techniques.contains(search),
        ))

    incidents_stmt = incidents_stmt.order_by(desc(Incident.created_at)).limit(100)
    result = await db.execute(incidents_stmt)
    incidents = result.scalars().unique().all()
    incident_rows = [
        {
            "item": incident,
            "affected_ips": _parse_json_list(incident.affected_ips),
            "attack_types": _parse_json_list(incident.attack_types),
            "mitre_techniques": _parse_json_list(incident.mitre_techniques),
            "alert_count": len(incident.alerts),
            "note_count": len(incident.notes),
        }
        for incident in incidents
    ]
    return templates.TemplateResponse("incidents.html", {
        "request": request,
        "incidents": incident_rows,
        "result_count": len(incident_rows),
        "time_filter_start": _datetime_local_value(start_time),
        "time_filter_end": _datetime_local_value(end_time),
        "time_window_label": time_window_label,
        "time_filter_query": _time_query_string(start_time, end_time),
        "filters": {
            "status": status,
            "priority": priority,
            "affected_ip": affected_ip,
            "attack_type": attack_type,
            "mitre_technique": mitre_technique,
            "search": search,
        },
    })


@dashboard_router.get("/logs-view", response_class=HTMLResponse)
async def logs_page(request: Request, db: AsyncSession = Depends(get_db)):
    """Log viewer page."""
    start_time, end_time, time_window_label = _resolve_time_window(request)
    hunt_query = _normalize_query_value(request.query_params.get("q"))
    hunt_filters, hunt_terms = _parse_hunt_query(hunt_query)

    action = _normalize_query_value(request.query_params.get("action")) or hunt_filters.get("action", "")
    attack_type = _normalize_query_value(request.query_params.get("attack_type")) or hunt_filters.get("attack_type", "")
    severity = _normalize_query_value(request.query_params.get("severity")) or hunt_filters.get("severity", "")
    src_ip = _normalize_query_value(request.query_params.get("src_ip")) or hunt_filters.get("src_ip", "")
    dst_ip = _normalize_query_value(request.query_params.get("dst_ip")) or hunt_filters.get("dst_ip", "")
    http_method = _normalize_query_value(request.query_params.get("http_method")) or hunt_filters.get("http_method", "")
    http_path = _normalize_query_value(request.query_params.get("http_path")) or hunt_filters.get("http_path", "")
    country = _normalize_query_value(request.query_params.get("country")) or hunt_filters.get("country", "")
    mitre_technique = _normalize_query_value(request.query_params.get("mitre_technique")) or hunt_filters.get("mitre_technique", "")
    protocol = _normalize_query_value(request.query_params.get("protocol")) or hunt_filters.get("protocol", "")
    user_agent = _normalize_query_value(request.query_params.get("user_agent")) or hunt_filters.get("user_agent", "")
    http_status = _normalize_query_value(request.query_params.get("http_status")) or hunt_filters.get("http_status", "")
    search = _normalize_query_value(request.query_params.get("search")) or hunt_filters.get("search", "")
    if hunt_terms:
        search = f"{search} {' '.join(hunt_terms)}".strip()

    action_filter = _parse_enum(LogAction, action)
    attack_type_filter = _parse_enum(AttackType, attack_type)
    severity_filter = _parse_enum(LogSeverity, severity)
    protocol_filter = _parse_enum(LogProtocol, protocol.upper()) if protocol else None
    http_status_filter = _parse_int(http_status)

    logs_stmt = _apply_time_filter(
        select(FirewallLog),
        FirewallLog.timestamp,
        start_time,
        end_time,
    )

    if action_filter:
        logs_stmt = logs_stmt.where(FirewallLog.action == action_filter)
    if attack_type_filter:
        logs_stmt = logs_stmt.where(FirewallLog.attack_type == attack_type_filter)
    if severity_filter:
        logs_stmt = logs_stmt.where(FirewallLog.severity == severity_filter)
    if protocol_filter:
        logs_stmt = logs_stmt.where(FirewallLog.protocol == protocol_filter)
    if src_ip:
        logs_stmt = logs_stmt.where(FirewallLog.src_ip.contains(src_ip))
    if dst_ip:
        logs_stmt = logs_stmt.where(FirewallLog.dst_ip.contains(dst_ip))
    if http_method:
        logs_stmt = logs_stmt.where(FirewallLog.http_method == http_method.upper())
    if http_status_filter is not None:
        logs_stmt = logs_stmt.where(FirewallLog.http_status == http_status_filter)
    if http_path:
        logs_stmt = logs_stmt.where(FirewallLog.http_path.contains(http_path))
    if country:
        logs_stmt = logs_stmt.where(FirewallLog.geo_country == country.upper())
    if user_agent:
        logs_stmt = logs_stmt.where(FirewallLog.http_user_agent.contains(user_agent))
    if mitre_technique:
        logs_stmt = logs_stmt.where(FirewallLog.mitre_technique.contains(mitre_technique))
    if search:
        logs_stmt = logs_stmt.where(or_(
            FirewallLog.src_ip.contains(search),
            FirewallLog.dst_ip.contains(search),
            FirewallLog.http_path.contains(search),
            FirewallLog.http_user_agent.contains(search),
            FirewallLog.payload_snippet.contains(search),
            FirewallLog.matched_rule.contains(search),
            FirewallLog.mitre_technique.contains(search),
            FirewallLog.raw_log.contains(search),
        ))

    logs_stmt = logs_stmt.order_by(desc(FirewallLog.timestamp)).limit(200)
    result = await db.execute(logs_stmt)
    logs = result.scalars().all()
    return templates.TemplateResponse("logs.html", {
        "request": request,
        "logs": logs,
        "result_count": len(logs),
        "time_filter_start": _datetime_local_value(start_time),
        "time_filter_end": _datetime_local_value(end_time),
        "time_window_label": time_window_label,
        "time_filter_query": _time_query_string(start_time, end_time),
        "current_query_string": request.url.query,
        "filters": {
            "q": hunt_query,
            "action": action,
            "attack_type": attack_type,
            "severity": severity,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "http_method": http_method,
            "http_status": http_status,
            "http_path": http_path,
            "country": country,
            "protocol": protocol,
            "user_agent": user_agent,
            "mitre_technique": mitre_technique,
            "search": search,
        },
    })
