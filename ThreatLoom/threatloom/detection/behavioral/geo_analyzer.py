"""
Geo anomaly analyzer - detects suspicious geographic patterns.
"""
import logging
from collections import defaultdict, Counter
from typing import List

from threatloom.models.logs import FirewallLog

logger = logging.getLogger("threatloom.detection.geo")

# High-risk countries (ISO 3166-1 alpha-2) - configurable
HIGH_RISK_COUNTRIES = {"KP", "IR", "SY", "CU", "VE"}
# Countries on watch list
WATCH_COUNTRIES = {"RU", "CN", "BY", "UA"}


class GeoAnalyzer:
    """
    Detects geo-based anomalies:
      - Attacks from high-risk countries
      - Geographic diversity anomaly (same session, multiple countries)
      - Sudden new country appearing in traffic
    """

    MULTI_COUNTRY_THRESHOLD = 3   # IPs from > N countries in one session = suspicious

    def __init__(self):
        self._known_countries: set = set()

    def analyze(self, logs: List[FirewallLog]) -> List[dict]:
        """Analyze logs for geographic anomalies."""
        alerts = []

        # Group by session
        by_session = defaultdict(list)
        country_counts = Counter()

        for log in logs:
            if log.geo_country:
                country_counts[log.geo_country] += 1
            if log.session_id and log.geo_country:
                by_session[log.session_id].append(log)

        # High-risk country attacks
        for log in logs:
            if (log.geo_country in HIGH_RISK_COUNTRIES
                    and log.attack_type and log.attack_type.value != "NONE"):
                alerts.append({
                    "title": f"Attack from high-risk country ({log.geo_country})",
                    "description": (
                        f"Attack type {log.attack_type.value} from {log.src_ip} "
                        f"(country: {log.geo_country})"
                    ),
                    "severity": "HIGH",
                    "src_ip": log.src_ip,
                    "geo_country": log.geo_country,
                    "attack_type": log.attack_type.value,
                    "event_count": 1,
                    "log_ids": [log.id],
                    "confidence": 0.75,
                    "mitre_tactic": "Initial Access",
                    "mitre_technique": "T1190",
                })

        # Multi-country session anomaly
        for session_id, session_logs in by_session.items():
            countries = set(l.geo_country for l in session_logs if l.geo_country)
            if len(countries) >= self.MULTI_COUNTRY_THRESHOLD:
                alerts.append({
                    "title": f"Multi-country session anomaly",
                    "description": (
                        f"Session {session_id[:16]}... observed from {len(countries)} "
                        f"countries: {', '.join(countries)}"
                    ),
                    "severity": "HIGH",
                    "src_ip": session_logs[0].src_ip,
                    "session_id": session_id,
                    "event_count": len(session_logs),
                    "log_ids": [l.id for l in session_logs[:20]],
                    "confidence": 0.85,
                    "mitre_tactic": "Defense Evasion",
                    "mitre_technique": "T1090",
                })

        # New country detection
        current_countries = set(country_counts.keys())
        new_countries = current_countries - self._known_countries
        for nc in new_countries:
            if nc in WATCH_COUNTRIES:
                alerts.append({
                    "title": f"New traffic from watch-list country: {nc}",
                    "description": f"First-time traffic observed from {nc} ({country_counts[nc]} events).",
                    "severity": "LOW",
                    "geo_country": nc,
                    "event_count": country_counts[nc],
                    "log_ids": [],
                    "confidence": 0.5,
                })
        self._known_countries.update(current_countries)

        return alerts
