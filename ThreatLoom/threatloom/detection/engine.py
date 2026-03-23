"""
Main detection engine - orchestrates rule-based, behavioral, and correlation analysis.
Runs as a background async loop that processes new logs and generates alerts.
"""
import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from threatloom.database import async_session
from threatloom.models.logs import FirewallLog, AttackType, LogSeverity
from threatloom.models.alerts import Alert, AlertSeverity, AlertStatus
from threatloom.models.incidents import Incident, IncidentStatus, IncidentPriority
from threatloom.detection.rules.rule_engine import RuleEngine
from threatloom.detection.behavioral.rate_analyzer import RateAnalyzer
from threatloom.detection.behavioral.geo_analyzer import GeoAnalyzer
from threatloom.detection.behavioral.pattern_analyzer import PatternAnalyzer
from threatloom.detection.correlation.ip_correlator import IPCorrelator
from threatloom.detection.correlation.session_correlator import SessionCorrelator
from threatloom.detection.correlation.time_window import TimeWindowCorrelator
from threatloom.config import settings
from threatloom.notifications.service import NotificationService
from threatloom.websocket.manager import manager

logger = logging.getLogger("threatloom.detection")


class DetectionEngine:
    """
    Background detection engine.

    Periodically scans recent logs, runs detection modules, and creates alerts.
    """

    ALERT_GROUP_WINDOW_MINUTES = 15

    def __init__(self):
        self.rule_engine = RuleEngine()
        self.rate_analyzer = RateAnalyzer()
        self.geo_analyzer = GeoAnalyzer()
        self.pattern_analyzer = PatternAnalyzer()
        self.ip_correlator = IPCorrelator()
        self.session_correlator = SessionCorrelator()
        self.time_window = TimeWindowCorrelator()
        self.notification_service = NotificationService()
        self.scan_interval_seconds = max(1, int(settings.DETECTION_SCAN_INTERVAL_SECONDS))
        self.lookback_seconds = max(self.scan_interval_seconds, int(settings.DETECTION_LOOKBACK_SECONDS))
        self._last_scan = datetime.utcnow()

    async def run(self):
        """Main detection loop."""
        logger.info("Detection engine started.")
        while True:
            try:
                await self._scan_cycle()
            except asyncio.CancelledError:
                logger.info("Detection engine stopped.")
                return
            except Exception as e:
                logger.error(f"Detection cycle error: {e}", exc_info=True)
            await asyncio.sleep(self.scan_interval_seconds)

    async def _scan_cycle(self):
        """Single scan cycle: fetch recent logs, run detectors, create alerts."""
        cutoff = datetime.utcnow() - timedelta(seconds=self.lookback_seconds)
        scan_from = max(cutoff, self._last_scan)

        async with async_session() as db:
            # Fetch recent logs
            result = await db.execute(
                select(FirewallLog)
                .where(FirewallLog.received_at >= scan_from)
                .order_by(FirewallLog.received_at)
            )
            logs = result.scalars().all()

            if not logs:
                self._last_scan = datetime.utcnow()
                return

            logger.debug(f"Detection scan: {len(logs)} logs since {scan_from}")

            # --- Rule-based detection ---
            for log in logs:
                rule_hits = self.rule_engine.evaluate(log)
                for hit in rule_hits:
                    await self._create_alert(db, log, hit, source="rule")

            # --- Threshold detection ---
            thr_hits = self.rule_engine.threshold_detector.evaluate_batch(logs)
            for th in thr_hits:
                await self._create_alert_from_behavioral(db, th, source="threshold")

            # --- Behavioral analysis (profile-gated) ---
            if settings.DETECTION_BEHAVIORAL_ENABLED:
                rate_alerts = await self.rate_analyzer.analyze(logs, db)
                for ra in rate_alerts:
                    await self._create_alert_from_behavioral(db, ra, source="behavioral.rate")

                geo_alerts = self.geo_analyzer.analyze(logs)
                for ga in geo_alerts:
                    await self._create_alert_from_behavioral(db, ga, source="behavioral.geo")

                pattern_alerts = self.pattern_analyzer.analyze(logs)
                for pa in pattern_alerts:
                    await self._create_alert_from_behavioral(db, pa, source="behavioral.pattern")

            # --- Correlation (profile-gated) ---
            if settings.DETECTION_CORRELATION_ENABLED:
                ip_corr = self.ip_correlator.correlate(logs)
                for ic in ip_corr:
                    await self._create_alert_from_correlation(db, ic, source="correlation.ip")

                session_corr = self.session_correlator.correlate(logs)
                for sc in session_corr:
                    await self._create_alert_from_correlation(db, sc, source="correlation.session")

                time_corr = self.time_window.correlate(logs)
                for tc in time_corr:
                    await self._create_alert_from_correlation(db, tc, source="correlation.time")

            await db.commit()
            self._last_scan = datetime.utcnow()

    async def _create_alert(
        self, db: AsyncSession, log: FirewallLog, hit: dict, source: str
    ):
        """Create an alert from a rule hit."""
        # Check for duplicate/similar recent alert
        existing = await self._find_similar_alert(
            db,
            src_ip=log.src_ip,
            rule_id=hit.get("rule_id"),
            attack_type=str(log.attack_type.value) if log.attack_type else None,
            http_path=log.http_path,
            detection_source=source,
            minutes=self.ALERT_GROUP_WINDOW_MINUTES,
        )
        if existing:
            self._merge_into_existing_alert(
                existing,
                event_increment=1,
                log_ids=[log.id],
                last_seen=datetime.utcnow(),
                confidence=hit.get("confidence", 0.8),
                http_path=log.http_path,
            )
            return

        alert = Alert(
            alert_uid=str(uuid.uuid4()),
            title=hit.get("title", f"Rule match: {hit.get('rule_id', 'unknown')}"),
            description=hit.get("description"),
            severity=self._map_severity(hit.get("severity", "MEDIUM")),
            detection_source=source,
            rule_id=hit.get("rule_id"),
            attack_type=str(log.attack_type.value) if log.attack_type else None,
            src_ip=log.src_ip,
            dst_ip=log.dst_ip,
            http_path=log.http_path,
            session_id=log.session_id,
            geo_country=log.geo_country,
            mitre_tactic=log.mitre_tactic or hit.get("mitre_tactic"),
            mitre_technique=log.mitre_technique or hit.get("mitre_technique"),
            correlated_log_ids=json.dumps([log.id]),
            confidence=hit.get("confidence", 0.8),
        )
        db.add(alert)
        await db.flush()
        await self._emit_alert(alert)
        logger.info(f"Alert created: {alert.title} [{alert.severity}] src={log.src_ip}")

        # Auto-escalate HIGH/CRITICAL alerts to incidents
        if alert.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL):
            await self._auto_escalate(db, alert)

    async def _create_alert_from_behavioral(
        self, db: AsyncSession, data: dict, source: str
    ):
        """Create alert from behavioral analysis output."""
        existing = await self._find_similar_alert(
            db,
            src_ip=data.get("src_ip"),
            rule_id=source,
            attack_type=data.get("attack_type"),
            http_path=data.get("http_path"),
            detection_source=source,
            minutes=self.ALERT_GROUP_WINDOW_MINUTES,
        )
        if existing:
            self._merge_into_existing_alert(
                existing,
                event_increment=data.get("event_count", 1),
                log_ids=data.get("log_ids", []),
                last_seen=datetime.utcnow(),
                confidence=data.get("confidence", 0.7),
                http_path=data.get("http_path"),
            )
            return

        alert = Alert(
            alert_uid=str(uuid.uuid4()),
            title=data.get("title", f"Behavioral anomaly ({source})"),
            description=data.get("description"),
            severity=self._map_severity(data.get("severity", "MEDIUM")),
            detection_source=source,
            attack_type=data.get("attack_type"),
            src_ip=data.get("src_ip"),
            geo_country=data.get("geo_country"),
            mitre_tactic=data.get("mitre_tactic"),
            mitre_technique=data.get("mitre_technique"),
            correlated_log_ids=json.dumps(data.get("log_ids", [])),
            event_count=data.get("event_count", 1),
            confidence=data.get("confidence", 0.7),
        )
        db.add(alert)
        await db.flush()
        await self._emit_alert(alert)

    async def _create_alert_from_correlation(
        self, db: AsyncSession, data: dict, source: str
    ):
        """Create alert from correlation output."""
        existing = await self._find_similar_alert(
            db,
            src_ip=data.get("src_ip"),
            rule_id=source,
            attack_type=data.get("attack_type"),
            http_path=data.get("http_path"),
            detection_source=source,
            minutes=self.ALERT_GROUP_WINDOW_MINUTES,
        )
        if existing:
            self._merge_into_existing_alert(
                existing,
                event_increment=data.get("event_count", 1),
                log_ids=data.get("log_ids", []),
                last_seen=datetime.utcnow(),
                confidence=data.get("confidence", 0.85),
                http_path=data.get("http_path"),
            )
            return

        alert = Alert(
            alert_uid=str(uuid.uuid4()),
            title=data.get("title", f"Correlated event ({source})"),
            description=data.get("description"),
            severity=self._map_severity(data.get("severity", "HIGH")),
            detection_source=source,
            attack_type=data.get("attack_type"),
            src_ip=data.get("src_ip"),
            geo_country=data.get("geo_country"),
            mitre_tactic=data.get("mitre_tactic"),
            mitre_technique=data.get("mitre_technique"),
            correlated_log_ids=json.dumps(data.get("log_ids", [])),
            event_count=data.get("event_count", 1),
            confidence=data.get("confidence", 0.85),
        )
        db.add(alert)
        await db.flush()
        await self._emit_alert(alert)
        logger.info(f"Correlation alert: {alert.title}")

    async def _find_similar_alert(
        self,
        db: AsyncSession,
        src_ip: str = None,
        rule_id: str = None,
        attack_type: str = None,
        http_path: str = None,
        detection_source: str = None,
        minutes: int = 5,
    ) -> Optional[Alert]:
        """Find a similar unresolved alert to deduplicate."""
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        conditions = [
            Alert.created_at >= cutoff,
            Alert.status.in_([
                AlertStatus.NEW,
                AlertStatus.ACKNOWLEDGED,
                AlertStatus.IN_PROGRESS,
                AlertStatus.ESCALATED,
            ]),
        ]
        if src_ip:
            conditions.append(Alert.src_ip == src_ip)
        if rule_id:
            conditions.append(Alert.rule_id == rule_id)
        if detection_source:
            conditions.append(Alert.detection_source == detection_source)
        if attack_type:
            conditions.append(Alert.attack_type == attack_type)
        if http_path:
            conditions.append(Alert.http_path == http_path)
        else:
            conditions.append(Alert.http_path.is_(None))

        result = await db.execute(
            select(Alert).where(and_(*conditions)).order_by(Alert.created_at.desc()).limit(1)
        )
        return result.scalar_one_or_none()

    def _merge_into_existing_alert(
        self,
        alert: Alert,
        event_increment: int,
        log_ids: list[int],
        last_seen: datetime,
        confidence: float,
        http_path: Optional[str],
    ):
        alert.event_count += max(event_increment, 1)
        alert.last_seen = last_seen
        alert.updated_at = last_seen
        alert.confidence = max(alert.confidence or 0.0, confidence or 0.0)
        if not alert.http_path and http_path:
            alert.http_path = http_path

        existing_log_ids = []
        if alert.correlated_log_ids:
            try:
                existing_log_ids = json.loads(alert.correlated_log_ids)
            except (TypeError, ValueError, json.JSONDecodeError):
                existing_log_ids = []

        merged_log_ids = []
        seen = set()
        for log_id in [*existing_log_ids, *log_ids]:
            if log_id in (None, ""):
                continue
            if log_id in seen:
                continue
            seen.add(log_id)
            merged_log_ids.append(log_id)
        alert.correlated_log_ids = json.dumps(merged_log_ids)

    async def _auto_escalate(self, db: AsyncSession, alert: Alert):
        """Auto-create or attach to an incident for HIGH/CRITICAL alerts."""
        try:
            # Look for an open incident with the same src_ip
            cutoff = datetime.utcnow() - timedelta(hours=1)
            result = await db.execute(
                select(Incident)
                .where(
                    and_(
                        Incident.created_at >= cutoff,
                        Incident.status.in_([IncidentStatus.NEW, IncidentStatus.INVESTIGATING]),
                        Incident.affected_ips.contains(alert.src_ip or ""),
                    )
                )
                .limit(1)
            )
            existing = result.scalar_one_or_none()

            if existing:
                alert.incident_id = existing.id
                logger.info(f"Alert attached to existing incident #{existing.id}")
                return

            # Create a new incident
            priority = (
                IncidentPriority.CRITICAL
                if alert.severity == AlertSeverity.CRITICAL
                else IncidentPriority.HIGH
            )
            incident = Incident(
                incident_uid=str(uuid.uuid4()),
                title=f"Auto-escalated: {alert.title}",
                description=(
                    f"Automatically escalated from {alert.severity.value} alert. "
                    f"Source IP: {alert.src_ip or 'unknown'}. "
                    f"Attack type: {alert.attack_type or 'unknown'}."
                ),
                status=IncidentStatus.NEW,
                priority=priority,
                affected_ips=json.dumps([alert.src_ip] if alert.src_ip else []),
                affected_paths=json.dumps([alert.http_path] if alert.http_path else []),
                attack_types=json.dumps([alert.attack_type] if alert.attack_type else []),
                mitre_tactics=json.dumps([alert.mitre_tactic] if alert.mitre_tactic else []),
                mitre_techniques=json.dumps([alert.mitre_technique] if alert.mitre_technique else []),
            )
            db.add(incident)
            await db.flush()  # get incident.id
            alert.incident_id = incident.id
            logger.info(f"Incident #{incident.id} created from alert: {alert.title}")
        except Exception as e:
            logger.error(f"Auto-escalation failed: {e}", exc_info=True)

    async def _emit_alert(self, alert: Alert):
        payload = {
            "id": alert.id,
            "alert_uid": alert.alert_uid,
            "title": alert.title,
            "severity": alert.severity.value if alert.severity else "MEDIUM",
            "status": alert.status.value if alert.status else "NEW",
            "src_ip": alert.src_ip,
            "geo_country": alert.geo_country,
            "attack_type": alert.attack_type,
            "http_path": alert.http_path,
            "detection_source": alert.detection_source,
            "mitre_technique": alert.mitre_technique,
            "event_count": alert.event_count,
            "timestamp": (alert.created_at or datetime.utcnow()).isoformat(),
            "description": alert.description,
        }
        await manager.broadcast_alert(payload)
        await self.notification_service.notify_alert(payload)

    @staticmethod
    def _map_severity(sev: str) -> AlertSeverity:
        mapping = {
            "LOW": AlertSeverity.LOW,
            "MEDIUM": AlertSeverity.MEDIUM,
            "HIGH": AlertSeverity.HIGH,
            "CRITICAL": AlertSeverity.CRITICAL,
        }
        return mapping.get(sev.upper(), AlertSeverity.MEDIUM)
