"""
SOAR Playbook runner - executes automated response playbooks.
"""
import json
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from threatloom.models.playbooks import Playbook, PlaybookExecution, PlaybookStatus
from threatloom.models.alerts import Alert, AlertSeverity
from threatloom.response.engine import ResponseEngine

logger = logging.getLogger("threatloom.response.playbook")


class PlaybookRunner:
    """
    Evaluates and executes SOAR-style playbooks.

    Playbook trigger_conditions (JSON):
    {
        "severity": ["HIGH", "CRITICAL"],
        "attack_type": ["SQLI", "RCE"],
        "event_count_gte": 5
    }

    Playbook actions (JSON array):
    [
        {"action": "IP_BLOCK", "duration_seconds": 3600},
        {"action": "RATE_LIMIT", "rate_limit_rps": 5, "duration_seconds": 1800},
        {"action": "notify", "channel": "soc"}
    ]
    """

    def __init__(self):
        self.response_engine = ResponseEngine()

    async def evaluate_alert(self, db: AsyncSession, alert: Alert):
        """
        Check if any playbook should trigger for this alert.
        Executes matching playbooks automatically.
        """
        result = await db.execute(
            select(Playbook).where(Playbook.status == PlaybookStatus.ACTIVE)
        )
        playbooks = result.scalars().all()

        for playbook in playbooks:
            if self._matches_trigger(alert, playbook):
                await self._execute_playbook(db, playbook, alert=alert)

    def _matches_trigger(self, alert: Alert, playbook: Playbook) -> bool:
        """Check if an alert matches a playbook's trigger conditions."""
        try:
            conditions = json.loads(playbook.trigger_conditions)
        except (json.JSONDecodeError, TypeError):
            return False

        # Severity match
        if "severity" in conditions:
            if alert.severity.value not in conditions["severity"]:
                return False

        # Attack type match
        if "attack_type" in conditions:
            if alert.attack_type not in conditions["attack_type"]:
                return False

        # Event count threshold
        if "event_count_gte" in conditions:
            if alert.event_count < conditions["event_count_gte"]:
                return False

        # Detection source match
        if "detection_source" in conditions:
            sources = conditions["detection_source"]
            if isinstance(sources, list):
                if not any(s in alert.detection_source for s in sources):
                    return False
            elif sources not in alert.detection_source:
                return False

        return True

    async def _execute_playbook(
        self,
        db: AsyncSession,
        playbook: Playbook,
        alert: Optional[Alert] = None,
        incident_id: Optional[int] = None,
        triggered_by: str = "auto",
    ):
        """Execute a playbook's actions."""
        # Create execution record
        execution = PlaybookExecution(
            playbook_id=playbook.id,
            alert_id=alert.id if alert else None,
            incident_id=incident_id,
            triggered_by=triggered_by,
            status="running",
        )
        db.add(execution)
        await db.flush()

        try:
            actions = json.loads(playbook.actions)
        except (json.JSONDecodeError, TypeError):
            execution.status = "failed"
            execution.result_detail = json.dumps({"error": "Invalid actions JSON"})
            execution.completed_at = datetime.utcnow()
            return

        results = []
        for action_def in actions:
            action_type = action_def.get("action")
            if not action_type:
                continue

            try:
                if action_type in ("IP_BLOCK", "RATE_LIMIT", "TEMP_BAN", "GEO_BLOCK"):
                    resp = await self.response_engine.execute_response(
                        db=db,
                        action=action_type,
                        target_ip=alert.src_ip if alert else None,
                        reason=f"Playbook: {playbook.name}",
                        duration_seconds=action_def.get("duration_seconds"),
                        rate_limit_rps=action_def.get("rate_limit_rps"),
                        alert_id=alert.id if alert else None,
                        playbook_id=playbook.id,
                        triggered_by=triggered_by,
                    )
                    results.append({
                        "action": action_type,
                        "status": "executed",
                        "response_id": resp.id,
                    })

                elif action_type == "notify":
                    # Notification stub - integrate with email/Slack/webhook
                    channel = action_def.get("channel", "soc")
                    logger.info(
                        f"PLAYBOOK NOTIFY [{channel}]: {playbook.name} "
                        f"triggered for alert {alert.id if alert else 'N/A'}"
                    )
                    results.append({"action": "notify", "channel": channel, "status": "sent"})

                elif action_type == "escalate":
                    # Escalate alert
                    if alert:
                        alert.status = "ESCALATED"
                    results.append({"action": "escalate", "status": "done"})

                else:
                    results.append({"action": action_type, "status": "unknown_action"})

            except Exception as e:
                logger.error(f"Playbook action failed: {action_type}: {e}")
                results.append({"action": action_type, "status": "failed", "error": str(e)})

        execution.status = "completed"
        execution.result_detail = json.dumps(results)
        execution.completed_at = datetime.utcnow()

        logger.info(
            f"Playbook '{playbook.name}' executed: {len(results)} actions, "
            f"alert={alert.id if alert else 'N/A'}"
        )

    async def run_manual(
        self, db: AsyncSession, playbook_id: int,
        alert_id: Optional[int] = None, incident_id: Optional[int] = None,
    ) -> Optional[PlaybookExecution]:
        """Manually trigger a playbook."""
        result = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
        playbook = result.scalar_one_or_none()
        if not playbook:
            return None

        alert = None
        if alert_id:
            r = await db.execute(select(Alert).where(Alert.id == alert_id))
            alert = r.scalar_one_or_none()

        await self._execute_playbook(
            db, playbook, alert=alert, incident_id=incident_id, triggered_by="manual"
        )

        # Return the latest execution
        r = await db.execute(
            select(PlaybookExecution)
            .where(PlaybookExecution.playbook_id == playbook_id)
            .order_by(PlaybookExecution.started_at.desc())
            .limit(1)
        )
        return r.scalar_one_or_none()
