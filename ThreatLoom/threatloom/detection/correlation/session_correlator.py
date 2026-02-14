"""
Session correlator - tracks suspicious behavior within a single session.
"""
import logging
from collections import defaultdict
from typing import List

from threatloom.models.logs import FirewallLog

logger = logging.getLogger("threatloom.detection.correlation.session")


class SessionCorrelator:
    """
    Correlates events within sessions:
      - Privilege escalation patterns (normal → attack within same session)
      - Session with increasing severity
      - Session spanning multiple attack types
    """

    ATTACK_DIVERSITY_THRESHOLD = 2   # Different attack types in one session
    SEVERITY_ESCALATION_MAP = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    def correlate(self, logs: List[FirewallLog]) -> List[dict]:
        """Run session correlation on a batch of logs."""
        alerts = []

        by_session = defaultdict(list)
        for log in logs:
            if log.session_id:
                by_session[log.session_id].append(log)

        for session_id, session_logs in by_session.items():
            if len(session_logs) < 2:
                continue

            # Multiple attack types in session
            attack_types = set(
                l.attack_type.value for l in session_logs
                if l.attack_type and l.attack_type.value != "NONE"
            )
            if len(attack_types) >= self.ATTACK_DIVERSITY_THRESHOLD:
                alerts.append({
                    "title": f"Session multi-attack: {session_id[:16]}...",
                    "description": (
                        f"Session exhibits {len(attack_types)} attack types: "
                        f"{', '.join(sorted(attack_types))}"
                    ),
                    "severity": "HIGH",
                    "src_ip": session_logs[0].src_ip,
                    "session_id": session_id,
                    "attack_type": "OTHER",
                    "event_count": len(session_logs),
                    "log_ids": [l.id for l in session_logs[:30]],
                    "confidence": 0.8,
                    "mitre_tactic": "Lateral Movement",
                    "mitre_technique": "T1078",
                })

            # Severity escalation within session
            sorted_logs = sorted(session_logs, key=lambda l: l.timestamp)
            severities = [
                self.SEVERITY_ESCALATION_MAP.get(
                    l.severity.value if l.severity else "INFO", 0
                )
                for l in sorted_logs
            ]
            if len(severities) >= 3:
                # Check for monotonically increasing severity
                increasing = all(
                    severities[i] <= severities[i + 1]
                    for i in range(len(severities) - 1)
                )
                if increasing and severities[-1] >= 3:
                    alerts.append({
                        "title": f"Escalating severity in session",
                        "description": (
                            f"Session {session_id[:16]}... shows escalating "
                            f"severity pattern from {sorted_logs[0].src_ip}"
                        ),
                        "severity": "HIGH",
                        "src_ip": session_logs[0].src_ip,
                        "session_id": session_id,
                        "event_count": len(session_logs),
                        "log_ids": [l.id for l in sorted_logs],
                        "confidence": 0.75,
                        "mitre_tactic": "Privilege Escalation",
                        "mitre_technique": "T1068",
                    })

        return alerts
