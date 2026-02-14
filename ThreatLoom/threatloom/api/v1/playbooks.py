"""
Playbook management API endpoints.
"""
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from threatloom.database import get_db
from threatloom.models.playbooks import Playbook, PlaybookStatus, PlaybookExecution
from threatloom.schemas.responses import PlaybookCreate, PlaybookResponse
from threatloom.response.playbook_runner import PlaybookRunner
from threatloom.auth.rbac import require_analyst, require_admin
from threatloom.auth.audit import record_audit
from threatloom.models.users import User

router = APIRouter()
runner = PlaybookRunner()


@router.get("/", response_model=List[PlaybookResponse])
async def list_playbooks(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """List all playbooks."""
    result = await db.execute(select(Playbook).order_by(Playbook.name))
    return result.scalars().all()


@router.post("/", response_model=PlaybookResponse)
async def create_playbook(
    payload: PlaybookCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
):
    """Create a new playbook (admin only)."""
    playbook = Playbook(
        name=payload.name,
        description=payload.description,
        trigger_conditions=payload.trigger_conditions,
        actions=payload.actions,
        cooldown_seconds=payload.cooldown_seconds,
        max_auto_executions=payload.max_auto_executions,
        created_by=user.id,
    )
    db.add(playbook)

    await record_audit(
        db, action="playbook.create", user_id=user.id, username=user.username,
        resource_type="playbook", resource_id=payload.name,
    )

    await db.commit()
    return playbook


@router.post("/{playbook_id}/run")
async def run_playbook(
    playbook_id: int,
    alert_id: int = None,
    incident_id: int = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Manually trigger a playbook."""
    execution = await runner.run_manual(
        db, playbook_id, alert_id=alert_id, incident_id=incident_id
    )
    if not execution:
        raise HTTPException(status_code=404, detail="Playbook not found")

    await record_audit(
        db, action="playbook.manual_run", user_id=user.id, username=user.username,
        resource_type="playbook", resource_id=playbook_id,
    )

    await db.commit()
    return {"status": execution.status, "result": execution.result_detail}


@router.patch("/{playbook_id}/toggle")
async def toggle_playbook(
    playbook_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
):
    """Enable/disable a playbook."""
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    if playbook.status == PlaybookStatus.ACTIVE:
        playbook.status = PlaybookStatus.DISABLED
    else:
        playbook.status = PlaybookStatus.ACTIVE

    await db.commit()
    return {"status": playbook.status.value}
