"""
Alert management API endpoints.
"""
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from threatloom.database import get_db
from threatloom.models.alerts import Alert, AlertSeverity, AlertStatus
from threatloom.schemas.alerts import (
    AlertCreate, AlertUpdate, AlertResponse, AlertStats,
)
from threatloom.auth.rbac import require_analyst, require_viewer
from threatloom.auth.audit import record_audit
from threatloom.models.users import User

router = APIRouter()


@router.get("/", response_model=List[AlertResponse])
async def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    src_ip: Optional[str] = None,
    attack_type: Optional[str] = None,
    detection_source: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    assigned_to: Optional[int] = None,
    limit: int = Query(default=50, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """Query alerts with filters."""
    query = select(Alert)

    if severity:
        query = query.where(Alert.severity == AlertSeverity(severity))
    if status:
        query = query.where(Alert.status == AlertStatus(status))
    if src_ip:
        query = query.where(Alert.src_ip == src_ip)
    if attack_type:
        query = query.where(Alert.attack_type == attack_type)
    if detection_source:
        query = query.where(Alert.detection_source.contains(detection_source))
    if start_time:
        query = query.where(Alert.created_at >= start_time)
    if end_time:
        query = query.where(Alert.created_at <= end_time)
    if assigned_to:
        query = query.where(Alert.assigned_to == assigned_to)

    query = query.order_by(desc(Alert.created_at)).offset(offset).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/stats", response_model=AlertStats)
async def alert_stats(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """Get alert statistics."""
    total = await db.execute(select(func.count(Alert.id)))

    by_severity = await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .group_by(Alert.severity)
    )
    by_status = await db.execute(
        select(Alert.status, func.count(Alert.id))
        .group_by(Alert.status)
    )
    by_attack = await db.execute(
        select(Alert.attack_type, func.count(Alert.id))
        .where(Alert.attack_type != None)
        .group_by(Alert.attack_type)
    )

    recent = await db.execute(
        select(Alert)
        .where(Alert.severity == AlertSeverity.CRITICAL)
        .order_by(desc(Alert.created_at))
        .limit(5)
    )

    return AlertStats(
        total=total.scalar() or 0,
        by_severity={str(r[0].value): r[1] for r in by_severity.all()},
        by_status={str(r[0].value): r[1] for r in by_status.all()},
        by_attack_type={str(r[0]): r[1] for r in by_attack.all() if r[0]},
        recent_critical=recent.scalars().all(),
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """Get a specific alert."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: int,
    update: AlertUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Update alert status, assignment, or link to incident."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    changes = {}
    if update.status:
        alert.status = AlertStatus(update.status)
        changes["status"] = update.status
        if update.status in ("RESOLVED", "FALSE_POSITIVE"):
            alert.resolved_at = datetime.utcnow()
    if update.assigned_to is not None:
        alert.assigned_to = update.assigned_to
        changes["assigned_to"] = update.assigned_to
    if update.incident_id is not None:
        alert.incident_id = update.incident_id
        changes["incident_id"] = update.incident_id

    alert.updated_at = datetime.utcnow()

    await record_audit(
        db, action="alert.update", user_id=user.id, username=user.username,
        resource_type="alert", resource_id=alert_id, detail=changes,
    )

    await db.commit()
    return alert


@router.post("/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Quick acknowledge an alert."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = AlertStatus.ACKNOWLEDGED
    alert.assigned_to = user.id
    alert.updated_at = datetime.utcnow()

    await record_audit(
        db, action="alert.acknowledge", user_id=user.id, username=user.username,
        resource_type="alert", resource_id=alert_id,
    )

    await db.commit()
    return alert
