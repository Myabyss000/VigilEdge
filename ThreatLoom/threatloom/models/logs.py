"""
Firewall log model - canonical representation of all ingested logs.
"""
import enum
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, DateTime, Text, Enum, Float, Boolean, Index,
)
from threatloom.database import Base


class LogProtocol(str, enum.Enum):
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    TCP = "TCP"
    UDP = "UDP"
    DNS = "DNS"
    ICMP = "ICMP"
    OTHER = "OTHER"


class LogAction(str, enum.Enum):
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    RATE_LIMITED = "RATE_LIMITED"
    DROPPED = "DROPPED"
    FLAGGED = "FLAGGED"


class LogSeverity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackType(str, enum.Enum):
    NONE = "NONE"
    SQLI = "SQLI"
    XSS = "XSS"
    RCE = "RCE"
    LFI = "LFI"
    RFI = "RFI"
    BRUTE_FORCE = "BRUTE_FORCE"
    PORT_SCAN = "PORT_SCAN"
    DDOS = "DDOS"
    DIRECTORY_TRAVERSAL = "DIRECTORY_TRAVERSAL"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    SSRF = "SSRF"
    XXE = "XXE"
    CSRF = "CSRF"
    BOT = "BOT"
    OTHER = "OTHER"


class FirewallLog(Base):
    """Canonical firewall log entry."""
    __tablename__ = "firewall_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Timestamps
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    received_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Source & Destination
    src_ip = Column(String(45), nullable=False, index=True)       # IPv4 or IPv6
    src_port = Column(Integer, nullable=True)
    dst_ip = Column(String(45), nullable=True)
    dst_port = Column(Integer, nullable=True)

    # Protocol & Action
    protocol = Column(Enum(LogProtocol), nullable=False, default=LogProtocol.HTTP)
    action = Column(Enum(LogAction), nullable=False, default=LogAction.ALLOWED, index=True)

    # HTTP metadata
    http_method = Column(String(10), nullable=True)
    http_path = Column(Text, nullable=True)
    http_status = Column(Integer, nullable=True)
    http_user_agent = Column(Text, nullable=True)
    http_host = Column(String(255), nullable=True)
    http_referer = Column(Text, nullable=True)

    # Attack classification
    attack_type = Column(Enum(AttackType), nullable=False, default=AttackType.NONE, index=True)
    attack_signature = Column(String(255), nullable=True)
    severity = Column(Enum(LogSeverity), nullable=False, default=LogSeverity.INFO, index=True)
    confidence = Column(Float, nullable=True)        # 0.0 - 1.0

    # Payload / Rule match
    matched_rule = Column(String(255), nullable=True)
    payload_snippet = Column(Text, nullable=True)    # Truncated for storage

    # GeoIP
    geo_country = Column(String(2), nullable=True)
    geo_city = Column(String(128), nullable=True)
    geo_lat = Column(Float, nullable=True)
    geo_lon = Column(Float, nullable=True)
    geo_asn = Column(String(128), nullable=True)

    # Session
    session_id = Column(String(64), nullable=True, index=True)

    # MITRE ATT&CK
    mitre_tactic = Column(String(64), nullable=True)
    mitre_technique = Column(String(64), nullable=True)

    # Metadata
    raw_log = Column(Text, nullable=True)
    source_format = Column(String(16), nullable=True)   # json, syslog, raw
    ingestion_pipeline = Column(String(64), nullable=True)

    # Retention tier
    tier = Column(String(8), default="hot")   # hot, warm, cold

    # DNS-specific
    dns_query = Column(String(255), nullable=True)
    dns_response = Column(String(255), nullable=True)

    # System metrics snapshot (optional, for correlated entries)
    sys_cpu = Column(Float, nullable=True)
    sys_memory = Column(Float, nullable=True)
    sys_latency_ms = Column(Float, nullable=True)

    __table_args__ = (
        Index("ix_logs_src_ip_timestamp", "src_ip", "timestamp"),
        Index("ix_logs_attack_timestamp", "attack_type", "timestamp"),
        Index("ix_logs_severity_timestamp", "severity", "timestamp"),
    )

    def __repr__(self):
        return (
            f"<FirewallLog id={self.id} src={self.src_ip} "
            f"action={self.action} attack={self.attack_type}>"
        )
