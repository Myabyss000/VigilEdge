"""
API dependencies - DB session, auth, audit helpers.
"""
from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from threatloom.database import get_db
from threatloom.models.users import User
from threatloom.auth.rbac import get_current_user
from threatloom.auth.audit import record_audit


async def get_client_ip(request: Request) -> str:
    """Extract client IP from request."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def audit_action(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Helper to record audit actions."""
    ip = await get_client_ip(request)

    async def record(action: str, resource_type: str = None, resource_id=None, detail: dict = None):
        await record_audit(
            db=db,
            action=action,
            user_id=user.id,
            username=user.username,
            resource_type=resource_type,
            resource_id=resource_id,
            detail=detail,
            ip_address=ip,
        )
    return record
