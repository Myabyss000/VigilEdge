"""
Audit logging - records all SOC analyst and admin actions.
"""
import json
import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from threatloom.models.audit import AuditLog

logger = logging.getLogger("threatloom.audit")


async def record_audit(
    db: AsyncSession,
    action: str,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    detail: Optional[dict] = None,
    ip_address: Optional[str] = None,
):
    """Write an audit log entry."""
    entry = AuditLog(
        user_id=user_id,
        username=username or "system",
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        detail=json.dumps(detail) if detail else None,
        ip_address=ip_address,
    )
    db.add(entry)
    await db.flush()
    logger.info(f"AUDIT | {username or 'system'} | {action} | {resource_type}:{resource_id}")
