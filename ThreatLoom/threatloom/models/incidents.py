"""
Incident model - created from escalated alerts for investigation tracking.
"""
import enum
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, DateTime, Text, Enum, ForeignKey, Index,
)
from sqlalchemy.orm import relationship
from threatloom.database import Base


class IncidentStatus(str, enum.Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    MITIGATED = "MITIGATED"
    CLOSED = "CLOSED"
    REOPENED = "REOPENED"


class IncidentPriority(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Incident(Base):
    """Security incident composed of one or more alerts."""
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Identification
    incident_uid = Column(String(64), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Classification
    status = Column(Enum(IncidentStatus), nullable=False, default=IncidentStatus.NEW, index=True)
    priority = Column(Enum(IncidentPriority), nullable=False, default=IncidentPriority.MEDIUM)

    # Affected entities
    affected_ips = Column(Text, nullable=True)       # JSON array
    affected_paths = Column(Text, nullable=True)     # JSON array
    attack_types = Column(Text, nullable=True)       # JSON array

    # MITRE ATT&CK
    mitre_tactics = Column(Text, nullable=True)      # JSON array
    mitre_techniques = Column(Text, nullable=True)   # JSON array

    # Assignment
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)

    # Response
    response_summary = Column(Text, nullable=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id"), nullable=True)

    # Relations
    alerts = relationship("Alert", back_populates="incident")
    notes = relationship("IncidentNote", back_populates="incident", order_by="IncidentNote.created_at")

    __table_args__ = (
        Index("ix_incidents_status_priority", "status", "priority"),
    )

    def __repr__(self):
        return f"<Incident id={self.id} title={self.title} status={self.status}>"


class IncidentNote(Base):
    """Analyst notes and evidence attached to an incident."""
    __tablename__ = "incident_notes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    content = Column(Text, nullable=False)
    note_type = Column(String(32), default="note")    # note, evidence, action, escalation
    attachment_path = Column(String(512), nullable=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Relations
    incident = relationship("Incident", back_populates="notes")

    def __repr__(self):
        return f"<IncidentNote id={self.id} incident={self.incident_id}>"
