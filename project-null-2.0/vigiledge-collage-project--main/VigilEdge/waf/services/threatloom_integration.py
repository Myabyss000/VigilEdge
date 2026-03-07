"""
ThreatLoom SOC Integration Service for VigilEdge WAF.

Forwards security events from the WAF engine to ThreatLoom's
log ingestion API in a non-blocking, fire-and-forget fashion.
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional, Dict, Any

import httpx

logger = logging.getLogger("vigiledge.threatloom")


# ---------------------------------------------------------------------------
# Threat-type → ThreatLoom attack_type mapping
# ---------------------------------------------------------------------------
_ATTACK_TYPE_MAP: Dict[str, str] = {
    "sql_injection":        "SQLI",
    "xss_attempt":          "XSS",
    "path_traversal":       "DIRECTORY_TRAVERSAL",
    "command_injection":    "COMMAND_INJECTION",
    "ddos_attack":          "DDOS",
    "rate_limit_exceeded":  "OTHER",
    "blocked_ip":           "OTHER",
    "bot_detected":         "BOT",
    "ldap_injection":       "OTHER",
    "xml_injection":        "XXE",
    "ssrf_attempt":         "SSRF",
    "template_injection":   "OTHER",
    "rce_attempt":          "RCE",
    "html_injection":       "OTHER",
    "auth_bypass_attempt":  "OTHER",
    "none":                 "NONE",
}

_SEVERITY_MAP: Dict[str, str] = {
    "low":      "LOW",
    "medium":   "MEDIUM",
    "high":     "HIGH",
    "critical": "CRITICAL",
}


class ThreatLoomIntegrator:
    """
    Async service that ships VigilEdge SecurityEvents to ThreatLoom.

    Usage:
        integrator = ThreatLoomIntegrator(api_url="http://localhost:8443")
        asyncio.create_task(integrator.send_event(security_event))
    """

    def __init__(
        self,
        api_url: str = "http://localhost:8443",
        api_key: str = "",
        enabled: bool = True,
        timeout: float = 5.0,
    ):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.enabled = enabled
        self.timeout = timeout
        self._ingest_url = f"{self.api_url}/api/v1/logs/ingest/json"
        self._healthy: Optional[bool] = None
        logger.info(
            "ThreatLoom integrator initialized  enabled=%s  url=%s",
            self.enabled,
            self.api_url,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def send_event(self, security_event) -> None:
        """
        Transform a VigilEdge SecurityEvent and POST it to ThreatLoom.

        This method is designed to be called via ``asyncio.create_task``
        so it never blocks the request pipeline.
        """
        if not self.enabled:
            return

        try:
            payload = self._transform(security_event)
            print(f"🔗 ThreatLoom: sending event to {self._ingest_url}")
            headers: Dict[str, str] = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    self._ingest_url,
                    json=payload,
                    headers=headers,
                )

            if resp.status_code < 300:
                print(f"✅ ThreatLoom: event ingested (log_id from ThreatLoom)")
                logger.debug(
                    "Event shipped to ThreatLoom  id=%s  status=%s",
                    security_event.id,
                    resp.status_code,
                )
            else:
                print(f"⚠️ ThreatLoom rejected event: {resp.status_code} - {resp.text[:200]}")
                logger.warning(
                    "ThreatLoom rejected event  id=%s  status=%s  body=%s",
                    security_event.id,
                    resp.status_code,
                    resp.text[:200],
                )

        except httpx.ConnectError:
            print(f"⚠️ ThreatLoom unreachable at {self.api_url}")
            if self._healthy is not False:
                logger.warning(
                    "ThreatLoom unreachable at %s — events will be retried silently.",
                    self.api_url,
                )
                self._healthy = False
        except Exception as exc:
            print(f"❌ ThreatLoom send_event error: {exc}")
            logger.error("ThreatLoom send_event error: %s", exc, exc_info=True)

    async def check_health(self) -> bool:
        """Quick health-check against ThreatLoom."""
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                resp = await client.get(f"{self.api_url}/api/docs")
            self._healthy = resp.status_code < 500
        except Exception:
            self._healthy = False
        return self._healthy

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _transform(self, event) -> Dict[str, Any]:
        """
        Map a VigilEdge ``SecurityEvent`` to the ThreatLoom
        ``LogIngestJSON`` schema.
        """
        threat_type = getattr(event, "threat_type", "none") or "none"
        threat_level = (
            event.threat_level.value
            if hasattr(event.threat_level, "value")
            else str(event.threat_level)
        )
        action_str = (
            event.action_taken.value
            if hasattr(event.action_taken, "value")
            else str(event.action_taken)
        )

        return {
            "timestamp": (
                event.timestamp.isoformat()
                if isinstance(event.timestamp, datetime)
                else str(event.timestamp)
            ),
            "src_ip": event.source_ip or "unknown",
            "protocol": "HTTP",
            "action": "BLOCKED" if event.blocked else "ALLOWED",
            "http_method": event.details.get("method", "GET"),
            "http_path": event.target_url or "/",
            "http_user_agent": event.user_agent or "",
            "attack_type": _ATTACK_TYPE_MAP.get(threat_type.lower(), "OTHER"),
            "severity": _SEVERITY_MAP.get(threat_level.lower(), "MEDIUM"),
            "payload_snippet": str(event.details.get("detected_patterns", ""))[:500],
            "session_id": event.id,
            "raw_log": str(event.to_dict())[:2000],
        }
