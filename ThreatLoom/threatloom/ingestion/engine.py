"""
Main ingestion engine.
Receives raw log data, parses, normalizes, enriches (GeoIP), and stores.
"""
import logging
from datetime import datetime
from typing import Optional, List

from sqlalchemy.ext.asyncio import AsyncSession

from threatloom.models.logs import FirewallLog, LogProtocol, LogAction, LogSeverity, AttackType
from threatloom.ingestion.parsers.json_parser import JSONLogParser
from threatloom.ingestion.parsers.syslog_parser import SyslogParser
from threatloom.ingestion.parsers.raw_parser import RawLogParser
from threatloom.ingestion.normalizer import LogNormalizer
from threatloom.utils.geoip import GeoIPResolver
from threatloom.detection.mitre import MITREMapper

logger = logging.getLogger("threatloom.ingestion")


class IngestionEngine:
    """
    Central log ingestion pipeline.

    Flow:
      raw input -> parser -> normalizer -> GeoIP enrichment -> MITRE mapping -> DB store
    """

    def __init__(self):
        self.json_parser = JSONLogParser()
        self.syslog_parser = SyslogParser()
        self.raw_parser = RawLogParser()
        self.normalizer = LogNormalizer()
        self.geoip = GeoIPResolver()
        self.mitre = MITREMapper()

    async def ingest_json(self, data: dict, db: AsyncSession) -> FirewallLog:
        """Ingest a single JSON-formatted log."""
        parsed = self.json_parser.parse(data)
        return await self._process_and_store(parsed, "json", db)

    async def ingest_json_batch(self, logs: List[dict], db: AsyncSession) -> List[FirewallLog]:
        """Ingest a batch of JSON logs."""
        results = []
        for log_data in logs:
            try:
                log = await self.ingest_json(log_data, db)
                results.append(log)
            except Exception as e:
                logger.error(f"Failed to ingest log: {e}")
        return results

    async def ingest_syslog(self, raw: str, db: AsyncSession) -> FirewallLog:
        """Ingest a syslog-formatted entry."""
        parsed = self.syslog_parser.parse(raw)
        return await self._process_and_store(parsed, "syslog", db)

    async def ingest_raw(self, raw: str, db: AsyncSession) -> FirewallLog:
        """Ingest a raw text log entry."""
        parsed = self.raw_parser.parse(raw)
        return await self._process_and_store(parsed, "raw", db)

    async def _process_and_store(
        self, parsed: dict, source_format: str, db: AsyncSession
    ) -> FirewallLog:
        """Normalize, enrich, and store a parsed log."""
        # Normalize fields
        normalized = self.normalizer.normalize(parsed)

        # GeoIP enrichment
        src_ip = normalized.get("src_ip")
        if src_ip:
            geo = self.geoip.lookup(src_ip)
            normalized.update({
                "geo_country": geo.get("country"),
                "geo_city": geo.get("city"),
                "geo_lat": geo.get("latitude"),
                "geo_lon": geo.get("longitude"),
                "geo_asn": geo.get("asn"),
            })

        # MITRE ATT&CK mapping
        attack_type = normalized.get("attack_type", "NONE")
        if attack_type and attack_type != "NONE":
            mitre = self.mitre.map_attack(attack_type)
            normalized["mitre_tactic"] = mitre.get("tactic")
            normalized["mitre_technique"] = mitre.get("technique")

        # Set metadata
        normalized["source_format"] = source_format
        normalized["received_at"] = datetime.utcnow()
        normalized["tier"] = "hot"

        # Ensure enums are valid
        normalized["protocol"] = self._safe_enum(LogProtocol, normalized.get("protocol", "HTTP"), LogProtocol.OTHER)
        normalized["action"] = self._safe_enum(LogAction, normalized.get("action", "ALLOWED"), LogAction.ALLOWED)
        normalized["severity"] = self._safe_enum(LogSeverity, normalized.get("severity", "INFO"), LogSeverity.INFO)
        normalized["attack_type"] = self._safe_enum(AttackType, normalized.get("attack_type", "NONE"), AttackType.NONE)

        # Create DB record
        log_entry = FirewallLog(**{
            k: v for k, v in normalized.items()
            if hasattr(FirewallLog, k) and k != "id"
        })
        db.add(log_entry)
        await db.flush()

        logger.debug(f"Ingested log: src={log_entry.src_ip} action={log_entry.action} attack={log_entry.attack_type}")
        return log_entry

    @staticmethod
    def _safe_enum(enum_class, value, default):
        """Safely convert value to enum, falling back to default."""
        if isinstance(value, enum_class):
            return value
        try:
            return enum_class(value)
        except (ValueError, KeyError):
            return default
