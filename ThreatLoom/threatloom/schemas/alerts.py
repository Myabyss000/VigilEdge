"""
Pydantic schemas for alerts.
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class AlertCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "MEDIUM"
    detection_source: str = "manual"
    rule_id: Optional[str] = None
    attack_type: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    http_path: Optional[str] = None
    session_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    correlated_log_ids: Optional[str] = None
    event_count: int = 1


class AlertUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[int] = None
    incident_id: Optional[int] = None


class AlertResponse(BaseModel):
    id: int
    alert_uid: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    confidence: Optional[float] = None
    detection_source: str
    rule_id: Optional[str] = None
    attack_type: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    http_path: Optional[str] = None
    geo_country: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    event_count: int
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    auto_response_taken: bool
    response_action: Optional[str] = None
    assigned_to: Optional[int] = None
    incident_id: Optional[int] = None

    model_config = {"from_attributes": True}


class AlertQueryParams(BaseModel):
    severity: Optional[str] = None
    status: Optional[str] = None
    src_ip: Optional[str] = None
    attack_type: Optional[str] = None
    detection_source: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    assigned_to: Optional[int] = None
    limit: int = Field(default=50, le=500)
    offset: int = 0


class AlertStats(BaseModel):
    total: int
    by_severity: dict
    by_status: dict
    by_attack_type: dict
    recent_critical: List[AlertResponse]
