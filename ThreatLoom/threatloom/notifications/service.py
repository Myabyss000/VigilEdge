"""
Notification delivery service for alerting external systems and browser clients.
"""
import logging
from typing import Optional

import httpx

from threatloom.config import settings
from threatloom.websocket.manager import manager

logger = logging.getLogger("threatloom.notifications")


class NotificationService:
    _SEVERITY_RANK = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    def _should_send(self, severity: Optional[str]) -> bool:
        if not settings.NOTIFICATIONS_ENABLED:
            return False

        current = self._SEVERITY_RANK.get((severity or "").upper(), 0)
        threshold = self._SEVERITY_RANK.get(settings.NOTIFICATION_MIN_SEVERITY.upper(), 3)
        return current >= threshold

    def _build_alert_notification(self, payload: dict) -> dict:
        severity = (payload.get("severity") or "INFO").upper()
        attack_type = (payload.get("attack_type") or "activity").replace("_", " ").upper()
        src_ip = payload.get("src_ip") or "unknown"
        http_path = payload.get("http_path") or "/"
        geo_country = payload.get("geo_country")

        title = f"{severity}: {attack_type}"
        message = f"{http_path} • {src_ip}"
        if geo_country:
            message = f"{message} • {geo_country}"

        return {
            **payload,
            "notification_title": title,
            "message": message,
        }

    def _build_playbook_notification(self, payload: dict) -> dict:
        channel = payload.get("channel") or "soc"
        playbook = payload.get("playbook") or "Playbook"
        message = payload.get("message") or "Automated response triggered."
        return {
            **payload,
            "notification_title": f"{channel.upper()} notification: {playbook}",
            "message": message,
        }

    async def notify_alert(self, payload: dict):
        severity = payload.get("severity")
        if not self._should_send(severity):
            return

        notification_payload = self._build_alert_notification(payload)

        await manager.broadcast_notification({
            "kind": "alert",
            **notification_payload,
        })

        if not settings.NOTIFICATION_WEBHOOK_URL:
            return

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    settings.NOTIFICATION_WEBHOOK_URL,
                    json={
                        "type": "alert_notification",
                        "payload": notification_payload,
                    },
                    headers={
                        "Content-Type": "application/json",
                        "X-ThreatLoom-Notification-Secret": settings.NOTIFICATION_WEBHOOK_SECRET,
                    },
                )
                if response.status_code < 300:
                    logger.info("Notification webhook OK: %s", response.status_code)
                else:
                    logger.warning("Notification webhook returned %s: %s", response.status_code, response.text)
        except Exception as exc:
            logger.error("Notification webhook failed: %s", exc)

    async def notify_playbook(self, payload: dict):
        notification_payload = self._build_playbook_notification(payload)
        await manager.broadcast_notification({
            "kind": "playbook",
            **notification_payload,
        })

        if not settings.NOTIFICATION_WEBHOOK_URL:
            return

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    settings.NOTIFICATION_WEBHOOK_URL,
                    json={
                        "type": "playbook_notification",
                        "payload": notification_payload,
                    },
                    headers={
                        "Content-Type": "application/json",
                        "X-ThreatLoom-Notification-Secret": settings.NOTIFICATION_WEBHOOK_SECRET,
                    },
                )
                if response.status_code >= 300:
                    logger.warning("Playbook notification webhook returned %s: %s", response.status_code, response.text)
        except Exception as exc:
            logger.error("Playbook notification webhook failed: %s", exc)