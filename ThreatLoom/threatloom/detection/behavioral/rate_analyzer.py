"""
Rate anomaly analyzer - detects unusually high request rates from IPs.
"""
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from threatloom.models.logs import FirewallLog

logger = logging.getLogger("threatloom.detection.rate")


class RateAnalyzer:
    """
    Detects rate anomalies:
      - High request rate from single IP
      - Sudden spike in blocked requests
      - Burst patterns (many requests in short window)
    """

    # Thresholds (configurable)
    REQUESTS_PER_MINUTE_THRESHOLD = 120
    BLOCKED_PER_MINUTE_THRESHOLD = 20
    BURST_WINDOW_SECONDS = 10
    BURST_THRESHOLD = 30

    def __init__(self):
        # Rolling baselines per IP
        self._baselines: Dict[str, float] = defaultdict(lambda: 10.0)

    async def analyze(self, logs: List[FirewallLog], db: AsyncSession) -> List[dict]:
        """Analyze logs for rate anomalies."""
        alerts = []

        # Group logs by src_ip
        by_ip = defaultdict(list)
        for log in logs:
            by_ip[log.src_ip].append(log)

        for ip, ip_logs in by_ip.items():
            count = len(ip_logs)

            # High request rate
            if count >= self.REQUESTS_PER_MINUTE_THRESHOLD:
                alerts.append({
                    "title": f"High request rate from {ip}",
                    "description": (
                        f"{count} requests detected in scan window. "
                        f"Threshold: {self.REQUESTS_PER_MINUTE_THRESHOLD}/min."
                    ),
                    "severity": "HIGH" if count > self.REQUESTS_PER_MINUTE_THRESHOLD * 2 else "MEDIUM",
                    "src_ip": ip,
                    "attack_type": "DDOS",
                    "event_count": count,
                    "log_ids": [l.id for l in ip_logs[:50]],
                    "confidence": min(0.95, 0.5 + (count / self.REQUESTS_PER_MINUTE_THRESHOLD) * 0.3),
                    "mitre_tactic": "Impact",
                    "mitre_technique": "T1498",
                })

            # High blocked rate
            blocked = [l for l in ip_logs if l.action and l.action.value == "BLOCKED"]
            if len(blocked) >= self.BLOCKED_PER_MINUTE_THRESHOLD:
                alerts.append({
                    "title": f"High block rate for {ip}",
                    "description": f"{len(blocked)} blocked requests from {ip}.",
                    "severity": "HIGH",
                    "src_ip": ip,
                    "attack_type": "BRUTE_FORCE",
                    "event_count": len(blocked),
                    "log_ids": [l.id for l in blocked[:50]],
                    "confidence": 0.8,
                    "mitre_tactic": "Credential Access",
                    "mitre_technique": "T1110",
                })

            # Burst detection (many requests in very short window)
            if count >= self.BURST_THRESHOLD:
                sorted_logs = sorted(ip_logs, key=lambda l: l.timestamp)
                for i in range(len(sorted_logs) - self.BURST_THRESHOLD):
                    window = sorted_logs[i:i + self.BURST_THRESHOLD]
                    delta = (window[-1].timestamp - window[0].timestamp).total_seconds()
                    if delta <= self.BURST_WINDOW_SECONDS:
                        alerts.append({
                            "title": f"Burst traffic from {ip}",
                            "description": (
                                f"{self.BURST_THRESHOLD} requests in {delta:.1f}s."
                            ),
                            "severity": "HIGH",
                            "src_ip": ip,
                            "attack_type": "DDOS",
                            "event_count": self.BURST_THRESHOLD,
                            "log_ids": [l.id for l in window],
                            "confidence": 0.9,
                        })
                        break   # One burst alert per IP per cycle

            # Update baseline
            self._baselines[ip] = (self._baselines[ip] * 0.9) + (count * 0.1)

        return alerts
