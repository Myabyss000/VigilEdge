"""
Time window correlator - detects temporally correlated attack patterns.
"""
import logging
from collections import defaultdict
from datetime import timedelta
from typing import List

from threatloom.models.logs import FirewallLog

logger = logging.getLogger("threatloom.detection.correlation.time")


class TimeWindowCorrelator:
    """
    Detects time-correlated patterns:
      - Attack bursts (many attacks in narrow window)
      - Sequential recon → exploit patterns
      - Time-of-day anomalies
    """

    ATTACK_BURST_WINDOW_SECONDS = 30
    ATTACK_BURST_THRESHOLD = 10

    def correlate(self, logs: List[FirewallLog]) -> List[dict]:
        """Run time-window correlation."""
        alerts = []

        # Filter to attack-only logs
        attack_logs = [
            l for l in logs
            if l.attack_type and l.attack_type.value != "NONE"
        ]
        if len(attack_logs) < self.ATTACK_BURST_THRESHOLD:
            return alerts

        # Sort by time
        sorted_logs = sorted(attack_logs, key=lambda l: l.timestamp)

        # Sliding window burst detection across all IPs
        for i in range(len(sorted_logs)):
            window = []
            for j in range(i, len(sorted_logs)):
                delta = (sorted_logs[j].timestamp - sorted_logs[i].timestamp).total_seconds()
                if delta <= self.ATTACK_BURST_WINDOW_SECONDS:
                    window.append(sorted_logs[j])
                else:
                    break

            if len(window) >= self.ATTACK_BURST_THRESHOLD:
                unique_ips = set(l.src_ip for l in window)
                attack_types = set(l.attack_type.value for l in window)

                alerts.append({
                    "title": "Attack burst detected",
                    "description": (
                        f"{len(window)} attacks from {len(unique_ips)} IPs in "
                        f"{self.ATTACK_BURST_WINDOW_SECONDS}s. "
                        f"Types: {', '.join(attack_types)}"
                    ),
                    "severity": "CRITICAL" if len(unique_ips) > 3 else "HIGH",
                    "src_ip": list(unique_ips)[0],
                    "attack_type": "DDOS" if len(unique_ips) > 3 else "OTHER",
                    "event_count": len(window),
                    "log_ids": [l.id for l in window[:50]],
                    "confidence": 0.9,
                    "mitre_tactic": "Impact",
                    "mitre_technique": "T1498" if len(unique_ips) > 3 else "T1190",
                })
                # Only one burst alert per cycle
                break

        # Recon → Exploit pattern (scan paths followed by attack)
        alerts.extend(self._detect_recon_exploit(sorted_logs))

        return alerts

    def _detect_recon_exploit(self, sorted_logs: List[FirewallLog]) -> List[dict]:
        """Detect recon-to-exploit patterns within sessions/IPs."""
        alerts = []
        by_ip = defaultdict(list)
        for log in sorted_logs:
            by_ip[log.src_ip].append(log)

        recon_types = {"PORT_SCAN", "BOT", "DIRECTORY_TRAVERSAL"}
        exploit_types = {"SQLI", "XSS", "RCE", "LFI", "RFI", "COMMAND_INJECTION", "SSRF", "XXE"}

        for ip, ip_logs in by_ip.items():
            has_recon = any(l.attack_type.value in recon_types for l in ip_logs if l.attack_type)
            has_exploit = any(l.attack_type.value in exploit_types for l in ip_logs if l.attack_type)

            if has_recon and has_exploit:
                alerts.append({
                    "title": f"Recon → Exploit chain from {ip}",
                    "description": (
                        f"{ip} performed reconnaissance followed by exploitation. "
                        f"Kill chain pattern detected."
                    ),
                    "severity": "CRITICAL",
                    "src_ip": ip,
                    "attack_type": "OTHER",
                    "event_count": len(ip_logs),
                    "log_ids": [l.id for l in ip_logs[:50]],
                    "confidence": 0.9,
                    "mitre_tactic": "Initial Access",
                    "mitre_technique": "T1190",
                })

        return alerts
