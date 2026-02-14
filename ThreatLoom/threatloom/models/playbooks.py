"""
SOAR Playbook models.
"""
import enum
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, DateTime, Text, Enum, Boolean, ForeignKey,
)
from threatloom.database import Base


class PlaybookStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    DRAFT = "DRAFT"


class Playbook(Base):
    """Automated response playbook definition."""
    __tablename__ = "playbooks"

    id = Column(Integer, primary_key=True, autoincrement=True)

    name = Column(String(128), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(Enum(PlaybookStatus), default=PlaybookStatus.ACTIVE)

    # Trigger conditions (JSON)
    trigger_conditions = Column(Text, nullable=False)   # JSON: severity, attack_type, threshold, etc.

    # Actions (JSON array of action steps)
    actions = Column(Text, nullable=False)              # JSON array

    # Metadata
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    cooldown_seconds = Column(Integer, default=300)     # Prevent re-trigger within window
    max_auto_executions = Column(Integer, default=10)   # Safety cap

    def __repr__(self):
        return f"<Playbook id={self.id} name={self.name}>"


class PlaybookExecution(Base):
    """Record of a playbook execution."""
    __tablename__ = "playbook_executions"

    id = Column(Integer, primary_key=True, autoincrement=True)

    playbook_id = Column(Integer, ForeignKey("playbooks.id"), nullable=False)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)

    triggered_by = Column(String(32), default="auto")    # auto or manual
    status = Column(String(32), default="running")       # running, completed, failed
    result_detail = Column(Text, nullable=True)          # JSON

    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<PlaybookExecution id={self.id} playbook={self.playbook_id} status={self.status}>"
