"""
Pydantic schemas for incidents.
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    priority: str = "MEDIUM"
    alert_ids: Optional[List[int]] = None
    affected_ips: Optional[str] = None
    attack_types: Optional[str] = None
    playbook_id: Optional[int] = None


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[int] = None
    response_summary: Optional[str] = None
    description: Optional[str] = None


class IncidentNoteCreate(BaseModel):
    content: str
    note_type: str = "note"    # note, evidence, action, escalation


class IncidentNoteResponse(BaseModel):
    id: int
    incident_id: int
    author_id: int
    content: str
    note_type: str
    attachment_path: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class IncidentResponse(BaseModel):
    id: int
    incident_uid: str
    title: str
    description: Optional[str] = None
    status: str
    priority: str
    affected_ips: Optional[str] = None
    attack_types: Optional[str] = None
    mitre_tactics: Optional[str] = None
    mitre_techniques: Optional[str] = None
    assigned_to: Optional[int] = None
    created_by: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    response_summary: Optional[str] = None
    notes: Optional[List[IncidentNoteResponse]] = None

    model_config = {"from_attributes": True}


class IncidentQueryParams(BaseModel):
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[int] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = Field(default=50, le=500)
    offset: int = 0


class IncidentTimeline(BaseModel):
    """Incident timeline entry for visualization."""
    timestamp: datetime
    event_type: str        # alert, note, status_change, response
    summary: str
    detail: Optional[str] = None
    actor: Optional[str] = None
