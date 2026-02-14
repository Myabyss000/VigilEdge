"""
Audit log model - tracks all SOC analyst and admin actions.
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from threatloom.database import Base


class AuditLog(Base):
    """Immutable audit trail for SOC actions."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    username = Column(String(64), nullable=True)
    action = Column(String(128), nullable=False)           # e.g., "alert.acknowledge", "incident.create"
    resource_type = Column(String(64), nullable=True)      # alert, incident, user, response
    resource_id = Column(String(64), nullable=True)
    detail = Column(Text, nullable=True)                    # JSON payload of what changed
    ip_address = Column(String(45), nullable=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f"<AuditLog id={self.id} action={self.action} user={self.username}>"
