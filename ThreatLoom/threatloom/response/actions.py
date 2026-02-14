"""
Action executor — applies defensive actions via the firewall webhook.

When FIREWALL_WEBHOOK_ENABLED=true, every block/unblock/rate-limit action
is POSTed to your firewall's webhook endpoint. Otherwise, actions are
tracked in-memory (useful for development & testing).
"""
import logging
from typing import Optional, Set

import httpx

from threatloom.config import settings
from threatloom.models.responses import ResponseAction

logger = logging.getLogger("threatloom.response.actions")


class ActionExecutor:
    """
    Executes defensive actions.

    If FIREWALL_WEBHOOK_ENABLED is true, actions are pushed to your
    firewall via HTTP POST. Otherwise they are kept in-memory.
    """

    def __init__(self):
        self._blocked_ips: Set[str] = set()
        self._rate_limited_ips: dict = {}       # ip -> rps limit
        self._banned_ips: Set[str] = set()
        self._geo_blocked: Set[str] = set()

    # ── Webhook helper ──────────────────────────────────────────────────

    async def _call_firewall(self, payload: dict) -> bool:
        """
        POST an action to the firewall's webhook endpoint.
        Returns True on success, False on failure (with log).
        """
        if not settings.FIREWALL_WEBHOOK_ENABLED:
            logger.warning(
                "Firewall webhook DISABLED — action '%s' recorded in-memory only. "
                "Set FIREWALL_WEBHOOK_ENABLED=true in .env to push to firewall.",
                payload.get("action"),
            )
            return True  # webhook disabled, actions stay in-memory only

        if not settings.FIREWALL_WEBHOOK_URL:
            logger.error(
                "FIREWALL_WEBHOOK_URL is empty — cannot send action '%s'. "
                "Set FIREWALL_WEBHOOK_URL in .env (e.g. http://localhost:5000/soc-webhook).",
                payload.get("action"),
            )
            return False

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    settings.FIREWALL_WEBHOOK_URL,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-ThreatLoom-Secret": settings.FIREWALL_WEBHOOK_SECRET,
                    },
                )
                if resp.status_code < 300:
                    logger.info(f"Firewall webhook OK: {payload.get('action')} -> {resp.status_code}")
                    return True
                else:
                    logger.warning(f"Firewall webhook returned {resp.status_code}: {resp.text}")
                    return False
        except Exception as e:
            logger.error(f"Firewall webhook call failed: {e}")
            return False

    # ── Execute ─────────────────────────────────────────────────────────

    async def execute(
        self,
        action: ResponseAction,
        target_ip: Optional[str] = None,
        target_cidr: Optional[str] = None,
        target_country: Optional[str] = None,
        target_path: Optional[str] = None,
        rate_limit_rps: Optional[int] = None,
        duration_minutes: Optional[int] = None,
        reason: Optional[str] = None,
    ) -> bool:
        """Execute a defensive action. Returns True if successful."""
        try:
            if action == ResponseAction.IP_BLOCK:
                target = target_ip or target_cidr
                self._blocked_ips.add(target)
                logger.info(f"BLOCKED IP: {target}")
                return await self._call_firewall({
                    "action": "BLOCK_IP",
                    "target_ip": target,
                    "duration_minutes": duration_minutes or 60,
                    "reason": reason or "SOC automated block",
                })

            elif action == ResponseAction.RATE_LIMIT:
                rps = rate_limit_rps or 10
                self._rate_limited_ips[target_ip] = rps
                logger.info(f"RATE LIMITED IP: {target_ip} -> {rps} rps")
                return await self._call_firewall({
                    "action": "RATE_LIMIT",
                    "target_ip": target_ip,
                    "rate_limit_rps": rps,
                    "duration_minutes": duration_minutes or 60,
                    "reason": reason or "SOC rate limit",
                })

            elif action == ResponseAction.TEMP_BAN:
                self._banned_ips.add(target_ip)
                self._blocked_ips.add(target_ip)
                logger.info(f"TEMP BANNED IP: {target_ip}")
                return await self._call_firewall({
                    "action": "TEMP_BAN",
                    "target_ip": target_ip,
                    "duration_minutes": duration_minutes or 120,
                    "reason": reason or "SOC temporary ban",
                })

            elif action == ResponseAction.GEO_BLOCK:
                self._geo_blocked.add(target_country)
                logger.info(f"GEO BLOCKED: {target_country}")
                return await self._call_firewall({
                    "action": "GEO_BLOCK",
                    "target_country": target_country,
                    "reason": reason or "SOC geo block",
                })

            elif action == ResponseAction.CAPTCHA:
                logger.info(f"CAPTCHA challenge enabled for {target_ip}")
                return await self._call_firewall({
                    "action": "CAPTCHA",
                    "target_ip": target_ip,
                    "reason": reason or "SOC captcha challenge",
                })

            elif action == ResponseAction.CUSTOM:
                logger.info(f"Custom action for {target_ip or target_path}")
                return await self._call_firewall({
                    "action": "CUSTOM",
                    "target_ip": target_ip,
                    "target_path": target_path,
                    "reason": reason or "SOC custom action",
                })

            else:
                logger.warning(f"Unknown action: {action}")
                return False

        except Exception as e:
            logger.error(f"Action execution failed: {e}")
            return False

    # ── Revoke ──────────────────────────────────────────────────────────

    async def revoke(
        self,
        action: ResponseAction,
        target_ip: Optional[str] = None,
        target_cidr: Optional[str] = None,
        target_country: Optional[str] = None,
    ) -> bool:
        """Revoke a previously applied action."""
        try:
            if action == ResponseAction.IP_BLOCK:
                target = target_ip or target_cidr
                self._blocked_ips.discard(target)
                logger.info(f"UNBLOCKED IP: {target}")
                return await self._call_firewall({
                    "action": "UNBLOCK_IP",
                    "target_ip": target,
                })

            elif action == ResponseAction.RATE_LIMIT:
                self._rate_limited_ips.pop(target_ip, None)
                logger.info(f"Rate limit removed for {target_ip}")
                return await self._call_firewall({
                    "action": "REMOVE_RATE_LIMIT",
                    "target_ip": target_ip,
                })

            elif action == ResponseAction.TEMP_BAN:
                self._banned_ips.discard(target_ip)
                self._blocked_ips.discard(target_ip)
                logger.info(f"Ban lifted for {target_ip}")
                return await self._call_firewall({
                    "action": "UNBAN_IP",
                    "target_ip": target_ip,
                })

            elif action == ResponseAction.GEO_BLOCK:
                self._geo_blocked.discard(target_country)
                logger.info(f"Geo block removed for {target_country}")
                return await self._call_firewall({
                    "action": "REMOVE_GEO_BLOCK",
                    "target_country": target_country,
                })

            return True

        except Exception as e:
            logger.error(f"Action revocation failed: {e}")
            return False

    # ── Status queries ──────────────────────────────────────────────────

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked_ips or ip in self._banned_ips

    def get_rate_limit(self, ip: str) -> Optional[int]:
        return self._rate_limited_ips.get(ip)

    def get_blocked_ips(self) -> Set[str]:
        return self._blocked_ips.copy()

    def get_banned_ips(self) -> Set[str]:
        return self._banned_ips.copy()
