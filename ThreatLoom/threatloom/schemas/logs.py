"""
Pydantic schemas for log ingestion and retrieval.
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


# ---------- Ingestion (inbound) ----------

class LogIngestJSON(BaseModel):
    """Schema for JSON-formatted log ingestion."""
    timestamp: Optional[datetime] = None
    src_ip: str
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: str = "HTTP"
    action: str = "ALLOWED"

    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_status: Optional[int] = None
    http_user_agent: Optional[str] = None
    http_host: Optional[str] = None
    http_referer: Optional[str] = None

    attack_type: Optional[str] = "NONE"
    attack_signature: Optional[str] = None
    severity: Optional[str] = "INFO"
    confidence: Optional[float] = None
    matched_rule: Optional[str] = None
    payload_snippet: Optional[str] = None

    session_id: Optional[str] = None

    dns_query: Optional[str] = None
    dns_response: Optional[str] = None

    sys_cpu: Optional[float] = None
    sys_memory: Optional[float] = None
    sys_latency_ms: Optional[float] = None

    raw_log: Optional[str] = None


class LogIngestSyslog(BaseModel):
    """Schema for syslog-formatted log ingestion."""
    raw: str
    source: Optional[str] = None


class LogIngestRaw(BaseModel):
    """Schema for raw text log ingestion."""
    raw: str
    source: Optional[str] = None


class LogIngestBatch(BaseModel):
    """Batch ingestion of multiple logs."""
    logs: List[LogIngestJSON]
    source: Optional[str] = None


# ---------- Query / Response ----------

class LogResponse(BaseModel):
    id: int
    timestamp: datetime
    src_ip: str
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: str
    action: str
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_status: Optional[int] = None
    http_user_agent: Optional[str] = None
    attack_type: str
    severity: str
    confidence: Optional[float] = None
    matched_rule: Optional[str] = None
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    geo_lat: Optional[float] = None
    geo_lon: Optional[float] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    session_id: Optional[str] = None

    model_config = {"from_attributes": True}


class LogQueryParams(BaseModel):
    """Query parameters for log search."""
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    action: Optional[str] = None
    attack_type: Optional[str] = None
    severity: Optional[str] = None
    protocol: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    session_id: Optional[str] = None
    http_path: Optional[str] = None
    limit: int = Field(default=100, le=1000)
    offset: int = 0


class SystemMetricsSnapshot(BaseModel):
    """System health metrics."""
    cpu_percent: float
    memory_percent: float
    active_connections: int
    requests_per_second: float
    blocked_per_second: float
    avg_latency_ms: float
    dropped_packets: int
    uptime_seconds: float
