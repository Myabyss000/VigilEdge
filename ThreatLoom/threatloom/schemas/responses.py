"""
Pydantic schemas for automated responses and playbooks.
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel


class ResponseCreate(BaseModel):
    action: str           # IP_BLOCK, RATE_LIMIT, TEMP_BAN, etc.
    target_ip: Optional[str] = None
    target_cidr: Optional[str] = None
    target_country: Optional[str] = None
    target_path: Optional[str] = None
    reason: Optional[str] = None
    duration_seconds: Optional[int] = None
    rate_limit_rps: Optional[int] = None
    alert_id: Optional[int] = None


class ResponseRevoke(BaseModel):
    reason: Optional[str] = None


class ResponseResponse(BaseModel):
    id: int
    action: str
    status: str
    target_ip: Optional[str] = None
    target_cidr: Optional[str] = None
    target_country: Optional[str] = None
    reason: Optional[str] = None
    duration_seconds: Optional[int] = None
    rate_limit_rps: Optional[int] = None
    triggered_by: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    trigger_conditions: str     # JSON
    actions: str                # JSON
    cooldown_seconds: int = 300
    max_auto_executions: int = 10


class PlaybookResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    status: str
    trigger_conditions: str
    actions: str
    cooldown_seconds: int
    max_auto_executions: int
    created_at: datetime

    model_config = {"from_attributes": True}


class DashboardStats(BaseModel):
    """Aggregated dashboard statistics."""
    total_logs_24h: int
    total_blocked_24h: int
    total_alerts_24h: int
    active_alerts: int
    open_incidents: int
    active_blocks: int
    top_attackers: List[dict]
    attack_type_distribution: dict
    severity_distribution: dict
    geo_distribution: List[dict]
    alerts_timeline: List[dict]
    system_health: dict
