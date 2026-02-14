"""
Request pattern analyzer - detects suspicious request patterns.
"""
import logging
import re
from collections import defaultdict, Counter
from typing import List

from threatloom.models.logs import FirewallLog

logger = logging.getLogger("threatloom.detection.pattern")


class PatternAnalyzer:
    """
    Detects suspicious request patterns:
      - Directory enumeration / scanning
      - Repeated suspicious paths
      - User-agent anomalies
      - Method abuse
    """

    # Suspicious paths indicating scanning / enumeration
    SCAN_PATHS = [
        r"/\.env", r"/\.git", r"/wp-admin", r"/wp-login", r"/admin",
        r"/phpmyadmin", r"/\.htaccess", r"/\.htpasswd", r"/config\.",
        r"/backup", r"/\.svn", r"/\.DS_Store", r"/server-status",
        r"/actuator", r"/api/swagger", r"/debug", r"/console",
        r"/shell", r"/cmd", r"/exec", r"/eval",
    ]
    SCAN_RE = re.compile("|".join(SCAN_PATHS), re.I)

    # Suspicious user agents
    SUSPICIOUS_UA = [
        r"sqlmap", r"nikto", r"nmap", r"masscan", r"dirbuster",
        r"gobuster", r"wfuzz", r"hydra", r"burp", r"zap",
        r"nessus", r"openvas", r".*scanner.*", r"python-requests",
    ]
    SUSPICIOUS_UA_RE = re.compile("|".join(SUSPICIOUS_UA), re.I)

    SCAN_PATH_THRESHOLD = 5      # How many scan paths before alerting
    UNIQUE_PATH_THRESHOLD = 50   # Too many unique paths from one IP

    def analyze(self, logs: List[FirewallLog]) -> List[dict]:
        """Analyze logs for suspicious request patterns."""
        alerts = []

        by_ip = defaultdict(list)
        for log in logs:
            by_ip[log.src_ip].append(log)

        for ip, ip_logs in by_ip.items():
            # Directory scanning detection
            scan_hits = [
                l for l in ip_logs
                if l.http_path and self.SCAN_RE.search(l.http_path)
            ]
            if len(scan_hits) >= self.SCAN_PATH_THRESHOLD:
                paths = list(set(l.http_path for l in scan_hits if l.http_path))[:10]
                alerts.append({
                    "title": f"Directory enumeration from {ip}",
                    "description": (
                        f"{len(scan_hits)} requests to known scan paths: "
                        f"{', '.join(paths[:5])}"
                    ),
                    "severity": "HIGH",
                    "src_ip": ip,
                    "attack_type": "PORT_SCAN",
                    "event_count": len(scan_hits),
                    "log_ids": [l.id for l in scan_hits[:30]],
                    "confidence": 0.85,
                    "mitre_tactic": "Discovery",
                    "mitre_technique": "T1083",
                })

            # High path diversity (fuzzing / scanning)
            unique_paths = set(l.http_path for l in ip_logs if l.http_path)
            if len(unique_paths) >= self.UNIQUE_PATH_THRESHOLD:
                alerts.append({
                    "title": f"High path diversity from {ip}",
                    "description": f"{len(unique_paths)} unique paths requested by {ip}.",
                    "severity": "MEDIUM",
                    "src_ip": ip,
                    "attack_type": "PORT_SCAN",
                    "event_count": len(unique_paths),
                    "log_ids": [l.id for l in ip_logs[:30]],
                    "confidence": 0.7,
                    "mitre_tactic": "Reconnaissance",
                    "mitre_technique": "T1595",
                })

            # Suspicious user agent
            for log in ip_logs:
                if log.http_user_agent and self.SUSPICIOUS_UA_RE.search(log.http_user_agent):
                    alerts.append({
                        "title": f"Suspicious tool detected: {ip}",
                        "description": f"User-Agent: {log.http_user_agent[:128]}",
                        "severity": "HIGH",
                        "src_ip": ip,
                        "attack_type": "BOT",
                        "event_count": 1,
                        "log_ids": [log.id],
                        "confidence": 0.9,
                        "mitre_tactic": "Reconnaissance",
                        "mitre_technique": "T1595",
                    })
                    break  # One alert per IP per cycle

        return alerts
