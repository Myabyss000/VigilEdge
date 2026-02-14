"""
Automated response records - IP blocks, rate limits, bans.
"""
import enum
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, DateTime, Text, Enum, Boolean, ForeignKey,
)
from threatloom.database import Base


class ResponseAction(str, enum.Enum):
    IP_BLOCK = "IP_BLOCK"
    RATE_LIMIT = "RATE_LIMIT"
    TEMP_BAN = "TEMP_BAN"
    CAPTCHA = "CAPTCHA"
    GEO_BLOCK = "GEO_BLOCK"
    CUSTOM = "CUSTOM"


class ResponseStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class AutomatedResponse(Base):
    """Records of automated defensive actions taken."""
    __tablename__ = "automated_responses"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # What action
    action = Column(Enum(ResponseAction), nullable=False)
    status = Column(Enum(ResponseStatus), default=ResponseStatus.ACTIVE)

    # Target
    target_ip = Column(String(45), nullable=True, index=True)
    target_cidr = Column(String(50), nullable=True)
    target_country = Column(String(2), nullable=True)
    target_path = Column(String(512), nullable=True)

    # Source trigger
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id"), nullable=True)

    # Config
    reason = Column(Text, nullable=True)
    duration_seconds = Column(Integer, nullable=True)   # null = permanent
    rate_limit_rps = Column(Integer, nullable=True)     # requests per second (for rate limits)

    # Who
    triggered_by = Column(String(32), default="auto")   # auto, manual
    revoked_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    expires_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<AutomatedResponse id={self.id} action={self.action} target={self.target_ip}>"
