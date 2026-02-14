"""
Response engine - orchestrates automated defensive actions.
"""
import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from threatloom.models.responses import AutomatedResponse, ResponseAction, ResponseStatus
from threatloom.models.alerts import Alert
from threatloom.response.actions import ActionExecutor

logger = logging.getLogger("threatloom.response")


class ResponseEngine:
    """
    Executes automated defensive responses:
      - IP blocking
      - Rate limiting
      - Temporary bans
      - Geo-based blocks
    """

    def __init__(self):
        self.executor = ActionExecutor()

    async def execute_response(
        self,
        db: AsyncSession,
        action: str,
        target_ip: Optional[str] = None,
        target_cidr: Optional[str] = None,
        target_country: Optional[str] = None,
        target_path: Optional[str] = None,
        reason: Optional[str] = None,
        duration_seconds: Optional[int] = None,
        rate_limit_rps: Optional[int] = None,
        alert_id: Optional[int] = None,
        playbook_id: Optional[int] = None,
        triggered_by: str = "auto",
    ) -> AutomatedResponse:
        """Execute a defensive action and record it."""

        # Check if an active response already exists for this target
        existing = await self._find_active_response(db, action, target_ip)
        if existing:
            logger.info(f"Active response already exists for {action} on {target_ip}")
            return existing

        # Calculate expiry
        expires_at = None
        if duration_seconds:
            expires_at = datetime.utcnow() + timedelta(seconds=duration_seconds)

        # Execute the actual action
        action_enum = ResponseAction(action)
        success = await self.executor.execute(
            action=action_enum,
            target_ip=target_ip,
            target_cidr=target_cidr,
            target_country=target_country,
            target_path=target_path,
            rate_limit_rps=rate_limit_rps,
        )

        if not success:
            logger.error(f"Failed to execute {action} on {target_ip}")

        # Record in database
        response = AutomatedResponse(
            action=action_enum,
            target_ip=target_ip,
            target_cidr=target_cidr,
            target_country=target_country,
            target_path=target_path,
            alert_id=alert_id,
            playbook_id=playbook_id,
            reason=reason,
            duration_seconds=duration_seconds,
            rate_limit_rps=rate_limit_rps,
            triggered_by=triggered_by,
            expires_at=expires_at,
        )
        db.add(response)
        await db.flush()

        # Update alert if linked
        if alert_id:
            result = await db.execute(select(Alert).where(Alert.id == alert_id))
            alert = result.scalar_one_or_none()
            if alert:
                alert.auto_response_taken = True
                alert.response_action = action

        logger.info(
            f"Response executed: {action} target={target_ip or target_cidr or target_country} "
            f"duration={duration_seconds}s triggered_by={triggered_by}"
        )
        return response

    async def revoke_response(
        self, db: AsyncSession, response_id: int, user_id: int
    ) -> Optional[AutomatedResponse]:
        """Revoke an active response (analyst manual override)."""
        result = await db.execute(
            select(AutomatedResponse).where(AutomatedResponse.id == response_id)
        )
        response = result.scalar_one_or_none()
        if not response:
            return None

        # Undo the action
        await self.executor.revoke(
            action=response.action,
            target_ip=response.target_ip,
            target_cidr=response.target_cidr,
            target_country=response.target_country,
        )

        response.status = ResponseStatus.REVOKED
        response.revoked_by = user_id
        response.revoked_at = datetime.utcnow()

        logger.info(f"Response {response_id} revoked by user {user_id}")
        return response

    async def expire_responses(self, db: AsyncSession):
        """Expire responses past their duration."""
        now = datetime.utcnow()
        result = await db.execute(
            select(AutomatedResponse).where(
                and_(
                    AutomatedResponse.status == ResponseStatus.ACTIVE,
                    AutomatedResponse.expires_at != None,
                    AutomatedResponse.expires_at <= now,
                )
            )
        )
        expired = result.scalars().all()
        for resp in expired:
            await self.executor.revoke(
                action=resp.action,
                target_ip=resp.target_ip,
                target_cidr=resp.target_cidr,
                target_country=resp.target_country,
            )
            resp.status = ResponseStatus.EXPIRED
            logger.info(f"Response {resp.id} expired: {resp.action} on {resp.target_ip}")

        if expired:
            await db.commit()

    async def _find_active_response(
        self, db: AsyncSession, action: str, target_ip: Optional[str]
    ) -> Optional[AutomatedResponse]:
        conditions = [AutomatedResponse.status == ResponseStatus.ACTIVE]
        try:
            conditions.append(AutomatedResponse.action == ResponseAction(action))
        except ValueError:
            return None
        if target_ip:
            conditions.append(AutomatedResponse.target_ip == target_ip)
        result = await db.execute(
            select(AutomatedResponse).where(and_(*conditions)).limit(1)
        )
        return result.scalar_one_or_none()

    async def get_active_blocks(self, db: AsyncSession) -> list:
        """Get all active IP blocks."""
        result = await db.execute(
            select(AutomatedResponse).where(
                AutomatedResponse.status == ResponseStatus.ACTIVE
            ).order_by(AutomatedResponse.created_at.desc())
        )
        return result.scalars().all()
