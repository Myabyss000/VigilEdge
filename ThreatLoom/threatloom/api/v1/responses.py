"""
Automated response management API endpoints.
"""
from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from threatloom.database import get_db
from threatloom.models.responses import AutomatedResponse, ResponseStatus
from threatloom.schemas.responses import ResponseCreate, ResponseRevoke, ResponseResponse
from threatloom.response.engine import ResponseEngine
from threatloom.auth.rbac import require_analyst, require_admin
from threatloom.auth.audit import record_audit
from threatloom.models.users import User

router = APIRouter()
response_engine = ResponseEngine()


@router.get("/", response_model=List[ResponseResponse])
async def list_responses(
    status: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = Query(default=50, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """List automated responses."""
    query = select(AutomatedResponse)
    if status:
        query = query.where(AutomatedResponse.status == ResponseStatus(status))
    if action:
        query = query.where(AutomatedResponse.action == action)

    query = query.order_by(desc(AutomatedResponse.created_at)).offset(offset).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.post("/", response_model=ResponseResponse)
async def create_response(
    payload: ResponseCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Manually create a defensive response (IP block, rate limit, etc.)."""
    resp = await response_engine.execute_response(
        db=db,
        action=payload.action,
        target_ip=payload.target_ip,
        target_cidr=payload.target_cidr,
        target_country=payload.target_country,
        target_path=payload.target_path,
        reason=payload.reason,
        duration_seconds=payload.duration_seconds,
        rate_limit_rps=payload.rate_limit_rps,
        alert_id=payload.alert_id,
        triggered_by="manual",
    )

    await record_audit(
        db, action="response.create", user_id=user.id, username=user.username,
        resource_type="response", resource_id=resp.id,
        detail={"action": payload.action, "target_ip": payload.target_ip},
    )

    await db.commit()
    return resp


@router.post("/{response_id}/revoke", response_model=ResponseResponse)
async def revoke_response(
    response_id: int,
    payload: ResponseRevoke,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Revoke an active response (analyst override)."""
    resp = await response_engine.revoke_response(db, response_id, user.id)
    if not resp:
        raise HTTPException(status_code=404, detail="Response not found")

    await record_audit(
        db, action="response.revoke", user_id=user.id, username=user.username,
        resource_type="response", resource_id=response_id,
        detail={"reason": payload.reason},
    )

    await db.commit()
    return resp


@router.get("/active", response_model=List[ResponseResponse])
async def active_responses(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Get all currently active defensive responses."""
    result = await db.execute(
        select(AutomatedResponse)
        .where(AutomatedResponse.status == ResponseStatus.ACTIVE)
        .order_by(desc(AutomatedResponse.created_at))
    )
    return result.scalars().all()
