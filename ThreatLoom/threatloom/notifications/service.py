"""
Notification delivery service for alerting external systems and browser clients.
"""
import asyncio
import logging
import smtplib
from email.message import EmailMessage
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

    def _email_is_configured(self) -> bool:
        return bool(
            settings.NOTIFICATION_EMAIL_ENABLED
            and settings.NOTIFICATION_EMAIL_TO
            and settings.SMTP_HOST
            and settings.SMTP_FROM_EMAIL
        )

    def _send_email_sync(self, subject: str, body: str):
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = settings.SMTP_FROM_EMAIL
        message["To"] = settings.NOTIFICATION_EMAIL_TO
        message.set_content(body)

        if settings.SMTP_USE_TLS:
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as smtp:
                smtp.starttls()
                if settings.SMTP_USERNAME:
                    smtp.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as smtp:
                if settings.SMTP_USERNAME:
                    smtp.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                smtp.send_message(message)

    async def _send_email_notification(self, notification_payload: dict):
        if not self._email_is_configured():
            return

        subject = notification_payload.get("notification_title") or "ThreatLoom alert"
        message = notification_payload.get("message") or "Attack detected"
        attack_type = notification_payload.get("attack_type") or "activity"
        src_ip = notification_payload.get("src_ip") or "unknown"
        http_path = notification_payload.get("http_path") or "/"
        geo_country = notification_payload.get("geo_country") or "unknown"
        severity = notification_payload.get("severity") or "INFO"

        body = (
            f"{message}\n\n"
            f"Attack: {attack_type}\n"
            f"Severity: {severity}\n"
            f"IP: {src_ip}\n"
            f"Path: {http_path}\n"
            f"Country: {geo_country}\n"
        )

        try:
            await asyncio.to_thread(self._send_email_sync, subject, body)
            logger.info("Notification email sent to %s", settings.NOTIFICATION_EMAIL_TO)
        except Exception as exc:
            logger.error("Notification email failed: %s", exc)

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

        await self._send_email_notification(notification_payload)

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

        await self._send_email_notification(notification_payload)

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