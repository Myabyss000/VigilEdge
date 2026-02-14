"""
IP correlator - correlates events across source IPs to detect coordinated attacks.
"""
import logging
from collections import defaultdict
from typing import List

from threatloom.models.logs import FirewallLog

logger = logging.getLogger("threatloom.detection.correlation.ip")


class IPCorrelator:
    """
    Correlates events by IP:
      - Single IP with multiple attack types → sophisticated attacker
      - Multiple IPs hitting same target path → coordinated attack
    """

    MULTI_ATTACK_THRESHOLD = 3    # Different attack types from 1 IP
    COORDINATED_IP_THRESHOLD = 5  # Different IPs hitting same path with attacks

    def correlate(self, logs: List[FirewallLog]) -> List[dict]:
        """Run IP correlation on a batch of logs."""
        alerts = []

        # --- Single IP, multiple attack types ---
        ip_attacks = defaultdict(set)
        ip_logs = defaultdict(list)
        for log in logs:
            if log.attack_type and log.attack_type.value != "NONE":
                ip_attacks[log.src_ip].add(log.attack_type.value)
                ip_logs[log.src_ip].append(log)

        for ip, attacks in ip_attacks.items():
            if len(attacks) >= self.MULTI_ATTACK_THRESHOLD:
                alerts.append({
                    "title": f"Multi-vector attack from {ip}",
                    "description": (
                        f"{ip} used {len(attacks)} different attack types: "
                        f"{', '.join(sorted(attacks))}"
                    ),
                    "severity": "CRITICAL",
                    "src_ip": ip,
                    "attack_type": "OTHER",
                    "event_count": len(ip_logs[ip]),
                    "log_ids": [l.id for l in ip_logs[ip][:50]],
                    "confidence": 0.9,
                    "mitre_tactic": "Initial Access",
                    "mitre_technique": "T1190",
                })

        # --- Multiple IPs, same target path (coordinated) ---
        path_ips = defaultdict(set)
        path_logs = defaultdict(list)
        for log in logs:
            if (log.http_path and log.attack_type
                    and log.attack_type.value != "NONE"):
                path_ips[log.http_path].add(log.src_ip)
                path_logs[log.http_path].append(log)

        for path, ips in path_ips.items():
            if len(ips) >= self.COORDINATED_IP_THRESHOLD:
                alerts.append({
                    "title": f"Coordinated attack on {path[:64]}",
                    "description": (
                        f"{len(ips)} unique IPs attacking {path} "
                        f"({len(path_logs[path])} total events)"
                    ),
                    "severity": "CRITICAL",
                    "src_ip": list(ips)[0],
                    "attack_type": "OTHER",
                    "event_count": len(path_logs[path]),
                    "log_ids": [l.id for l in path_logs[path][:50]],
                    "confidence": 0.85,
                    "mitre_tactic": "Initial Access",
                    "mitre_technique": "T1190",
                })

        return alerts
