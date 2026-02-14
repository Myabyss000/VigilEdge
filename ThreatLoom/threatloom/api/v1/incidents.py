"""
Incident management API endpoints.
"""
import json
import uuid
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from threatloom.database import get_db
from threatloom.models.incidents import Incident, IncidentNote, IncidentStatus, IncidentPriority
from threatloom.models.alerts import Alert, AlertStatus
from threatloom.schemas.incidents import (
    IncidentCreate, IncidentUpdate, IncidentNoteCreate,
    IncidentResponse, IncidentNoteResponse, IncidentTimeline,
)
from threatloom.auth.rbac import require_analyst, require_viewer
from threatloom.auth.audit import record_audit
from threatloom.models.users import User

router = APIRouter()


@router.get("/", response_model=List[IncidentResponse])
async def list_incidents(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assigned_to: Optional[int] = None,
    limit: int = Query(default=50, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """List incidents with filters."""
    query = select(Incident).options(selectinload(Incident.notes))

    if status:
        query = query.where(Incident.status == IncidentStatus(status))
    if priority:
        query = query.where(Incident.priority == IncidentPriority(priority))
    if assigned_to:
        query = query.where(Incident.assigned_to == assigned_to)

    query = query.order_by(desc(Incident.created_at)).offset(offset).limit(limit)
    result = await db.execute(query)
    return result.scalars().unique().all()


@router.post("/", response_model=IncidentResponse)
async def create_incident(
    payload: IncidentCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Create a new incident, optionally linking alerts."""
    incident = Incident(
        incident_uid=f"INC-{uuid.uuid4().hex[:12].upper()}",
        title=payload.title,
        description=payload.description,
        priority=IncidentPriority(payload.priority),
        affected_ips=payload.affected_ips,
        attack_types=payload.attack_types,
        created_by=user.id,
        assigned_to=user.id,
        playbook_id=payload.playbook_id,
    )
    db.add(incident)
    await db.flush()

    # Link alerts
    if payload.alert_ids:
        for aid in payload.alert_ids:
            result = await db.execute(select(Alert).where(Alert.id == aid))
            alert = result.scalar_one_or_none()
            if alert:
                alert.incident_id = incident.id
                alert.status = AlertStatus.IN_PROGRESS

    await record_audit(
        db, action="incident.create", user_id=user.id, username=user.username,
        resource_type="incident", resource_id=incident.id,
        detail={"title": payload.title},
    )

    await db.commit()

    # Re-fetch with notes
    result = await db.execute(
        select(Incident).options(selectinload(Incident.notes))
        .where(Incident.id == incident.id)
    )
    return result.scalar_one()


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """Get a specific incident with notes."""
    result = await db.execute(
        select(Incident).options(selectinload(Incident.notes))
        .where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: int,
    update: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Update incident status, priority, or assignment."""
    result = await db.execute(
        select(Incident).options(selectinload(Incident.notes))
        .where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    changes = {}
    if update.status:
        incident.status = IncidentStatus(update.status)
        changes["status"] = update.status
        if update.status == "MITIGATED":
            incident.resolved_at = datetime.utcnow()
        if update.status == "CLOSED":
            incident.closed_at = datetime.utcnow()
    if update.priority:
        incident.priority = IncidentPriority(update.priority)
        changes["priority"] = update.priority
    if update.assigned_to is not None:
        incident.assigned_to = update.assigned_to
        changes["assigned_to"] = update.assigned_to
    if update.response_summary:
        incident.response_summary = update.response_summary
        changes["response_summary"] = update.response_summary
    if update.description:
        incident.description = update.description

    incident.updated_at = datetime.utcnow()

    await record_audit(
        db, action="incident.update", user_id=user.id, username=user.username,
        resource_type="incident", resource_id=incident_id, detail=changes,
    )

    await db.commit()
    return incident


@router.post("/{incident_id}/notes", response_model=IncidentNoteResponse)
async def add_note(
    incident_id: int,
    payload: IncidentNoteCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Add a note to an incident."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Incident not found")

    note = IncidentNote(
        incident_id=incident_id,
        author_id=user.id,
        content=payload.content,
        note_type=payload.note_type,
    )
    db.add(note)

    await record_audit(
        db, action="incident.note_added", user_id=user.id, username=user.username,
        resource_type="incident", resource_id=incident_id,
    )

    await db.commit()
    return note


@router.get("/{incident_id}/timeline", response_model=List[IncidentTimeline])
async def get_timeline(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """Get the timeline of events for an incident."""
    # Get incident
    result = await db.execute(
        select(Incident).options(selectinload(Incident.notes), selectinload(Incident.alerts))
        .where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    timeline = []

    # Incident creation
    timeline.append(IncidentTimeline(
        timestamp=incident.created_at,
        event_type="incident_created",
        summary=f"Incident created: {incident.title}",
    ))

    # Linked alerts
    for alert in incident.alerts:
        timeline.append(IncidentTimeline(
            timestamp=alert.created_at,
            event_type="alert",
            summary=f"Alert: {alert.title}",
            detail=f"Severity: {alert.severity.value}, Source: {alert.detection_source}",
        ))

    # Notes
    for note in incident.notes:
        timeline.append(IncidentTimeline(
            timestamp=note.created_at,
            event_type=note.note_type,
            summary=note.content[:128],
            detail=note.content,
        ))

    # Sort by timestamp
    timeline.sort(key=lambda t: t.timestamp)
    return timeline
