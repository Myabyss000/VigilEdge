"""
Log ingestion and query API endpoints.
"""
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from threatloom.database import get_db
from threatloom.models.logs import FirewallLog, AttackType, LogAction, LogSeverity
from threatloom.schemas.logs import (
    LogIngestJSON, LogIngestSyslog, LogIngestRaw, LogIngestBatch,
    LogResponse, SystemMetricsSnapshot,
)
from threatloom.ingestion.engine import IngestionEngine
from threatloom.auth.rbac import require_analyst, require_viewer, require_ingest_client
from threatloom.models.users import User
from threatloom.websocket.manager import manager

router = APIRouter()
ingestion = IngestionEngine()


@router.post("/ingest/json", response_model=dict)
async def ingest_json(
    payload: LogIngestJSON,
    db: AsyncSession = Depends(get_db),
    auth_context = Depends(require_ingest_client),
):
    """Ingest a single JSON-formatted firewall log."""
    log = await ingestion.ingest_json(payload.model_dump(), db)
    await db.commit()

    # Broadcast to WebSocket
    await manager.broadcast_log({
        "id": log.id,
        "src_ip": log.src_ip,
        "action": log.action.value if log.action else "ALLOWED",
        "attack_type": log.attack_type.value if log.attack_type else "NONE",
        "severity": log.severity.value if log.severity else "INFO",
        "http_path": log.http_path,
        "timestamp": log.timestamp.isoformat() if log.timestamp else None,
    })

    return {"status": "ingested", "log_id": log.id}


@router.post("/ingest/batch", response_model=dict)
async def ingest_batch(
    payload: LogIngestBatch,
    db: AsyncSession = Depends(get_db),
    auth_context = Depends(require_ingest_client),
):
    """Ingest a batch of JSON-formatted logs."""
    logs = await ingestion.ingest_json_batch(
        [l.model_dump() for l in payload.logs], db
    )
    await db.commit()
    return {"status": "ingested", "count": len(logs)}


@router.post("/ingest/syslog", response_model=dict)
async def ingest_syslog(
    payload: LogIngestSyslog,
    db: AsyncSession = Depends(get_db),
    auth_context = Depends(require_ingest_client),
):
    """Ingest a syslog-formatted log entry."""
    log = await ingestion.ingest_syslog(payload.raw, db)
    await db.commit()
    return {"status": "ingested", "log_id": log.id}


@router.post("/ingest/raw", response_model=dict)
async def ingest_raw(
    payload: LogIngestRaw,
    db: AsyncSession = Depends(get_db),
    auth_context = Depends(require_ingest_client),
):
    """Ingest a raw text log entry."""
    log = await ingestion.ingest_raw(payload.raw, db)
    await db.commit()
    return {"status": "ingested", "log_id": log.id}


@router.get("/", response_model=List[LogResponse])
async def list_logs(
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    action: Optional[str] = None,
    attack_type: Optional[str] = None,
    severity: Optional[str] = None,
    protocol: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    session_id: Optional[str] = None,
    http_path: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """Query firewall logs with filters."""
    query = select(FirewallLog)

    if src_ip:
        query = query.where(FirewallLog.src_ip == src_ip)
    if dst_ip:
        query = query.where(FirewallLog.dst_ip == dst_ip)
    if action:
        query = query.where(FirewallLog.action == LogAction(action))
    if attack_type:
        query = query.where(FirewallLog.attack_type == AttackType(attack_type))
    if severity:
        query = query.where(FirewallLog.severity == LogSeverity(severity))
    if start_time:
        query = query.where(FirewallLog.timestamp >= start_time)
    if end_time:
        query = query.where(FirewallLog.timestamp <= end_time)
    if session_id:
        query = query.where(FirewallLog.session_id == session_id)
    if http_path:
        query = query.where(FirewallLog.http_path.contains(http_path))

    query = query.order_by(desc(FirewallLog.timestamp)).offset(offset).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{log_id}", response_model=LogResponse)
async def get_log(
    log_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """Get a specific log entry by ID."""
    result = await db.execute(select(FirewallLog).where(FirewallLog.id == log_id))
    log = result.scalar_one_or_none()
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    return log


@router.get("/stats/summary", response_model=dict)
async def log_stats(
    hours: int = Query(default=24, le=720),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """Get log statistics for the last N hours."""
    cutoff = datetime.utcnow() - __import__("datetime").timedelta(hours=hours)

    total = await db.execute(
        select(func.count(FirewallLog.id)).where(FirewallLog.timestamp >= cutoff)
    )
    blocked = await db.execute(
        select(func.count(FirewallLog.id)).where(
            and_(FirewallLog.timestamp >= cutoff, FirewallLog.action == LogAction.BLOCKED)
        )
    )
    attacks = await db.execute(
        select(func.count(FirewallLog.id)).where(
            and_(FirewallLog.timestamp >= cutoff, FirewallLog.attack_type != AttackType.NONE)
        )
    )

    # Top attackers
    top_ips = await db.execute(
        select(FirewallLog.src_ip, func.count(FirewallLog.id).label("count"))
        .where(and_(FirewallLog.timestamp >= cutoff, FirewallLog.attack_type != AttackType.NONE))
        .group_by(FirewallLog.src_ip)
        .order_by(desc("count"))
        .limit(10)
    )

    # Attack type distribution
    attack_dist = await db.execute(
        select(FirewallLog.attack_type, func.count(FirewallLog.id).label("count"))
        .where(and_(FirewallLog.timestamp >= cutoff, FirewallLog.attack_type != AttackType.NONE))
        .group_by(FirewallLog.attack_type)
        .order_by(desc("count"))
    )

    return {
        "total_logs": total.scalar() or 0,
        "total_blocked": blocked.scalar() or 0,
        "total_attacks": attacks.scalar() or 0,
        "top_attackers": [
            {"ip": row[0], "count": row[1]} for row in top_ips.all()
        ],
        "attack_distribution": {
            str(row[0].value) if row[0] else "OTHER": row[1]
            for row in attack_dist.all()
        },
    }
