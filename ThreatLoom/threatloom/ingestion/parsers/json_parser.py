"""
JSON log parser - handles structured JSON firewall logs.
"""
from datetime import datetime
from typing import Optional


class JSONLogParser:
    """Parse structured JSON log data into canonical dict."""

    # Common field aliases from various firewall/WAF log formats
    FIELD_MAP = {
        # Timestamp aliases
        "ts": "timestamp",
        "time": "timestamp",
        "@timestamp": "timestamp",
        "event_time": "timestamp",
        "log_time": "timestamp",
        # IP aliases
        "source_ip": "src_ip",
        "client_ip": "src_ip",
        "remote_addr": "src_ip",
        "attacker_ip": "src_ip",
        "source_port": "src_port",
        "client_port": "src_port",
        "destination_ip": "dst_ip",
        "server_ip": "dst_ip",
        "destination_port": "dst_port",
        "server_port": "dst_port",
        # HTTP aliases
        "method": "http_method",
        "request_method": "http_method",
        "uri": "http_path",
        "path": "http_path",
        "request_uri": "http_path",
        "url": "http_path",
        "status_code": "http_status",
        "response_code": "http_status",
        "status": "http_status",
        "user_agent": "http_user_agent",
        "ua": "http_user_agent",
        "host": "http_host",
        "referer": "http_referer",
        "referrer": "http_referer",
        # Action aliases
        "verdict": "action",
        "decision": "action",
        "rule_action": "action",
        # Attack aliases
        "threat_type": "attack_type",
        "category": "attack_type",
        "classification": "attack_type",
        "signature": "attack_signature",
        "rule_name": "matched_rule",
        "rule_matched": "matched_rule",
        "payload": "payload_snippet",
        # DNS
        "query": "dns_query",
        "response": "dns_response",
        "dns_name": "dns_query",
    }

    def parse(self, data: dict) -> dict:
        """Parse a JSON log payload into canonical fields."""
        result = {}

        for key, value in data.items():
            canonical = self.FIELD_MAP.get(key, key)
            result[canonical] = value

        # Parse timestamp
        if "timestamp" in result and isinstance(result["timestamp"], str):
            result["timestamp"] = self._parse_timestamp(result["timestamp"])
        elif "timestamp" not in result:
            result["timestamp"] = datetime.utcnow()

        # Normalize action to uppercase
        if "action" in result and isinstance(result["action"], str):
            result["action"] = result["action"].upper().replace(" ", "_")

        # Normalize attack_type
        if "attack_type" in result and isinstance(result["attack_type"], str):
            result["attack_type"] = result["attack_type"].upper().replace(" ", "_").replace("-", "_")

        # Normalize severity
        if "severity" in result and isinstance(result["severity"], str):
            result["severity"] = result["severity"].upper()

        # Normalize protocol
        if "protocol" in result and isinstance(result["protocol"], str):
            result["protocol"] = result["protocol"].upper()

        # Store original as raw
        if "raw_log" not in result:
            import json
            result["raw_log"] = json.dumps(data)

        return result

    @staticmethod
    def _parse_timestamp(ts_str: str) -> datetime:
        """Attempt multiple timestamp formats."""
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S %z",   # Apache/Nginx format
        ]
        for fmt in formats:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
        # Fallback: try dateutil
        try:
            from dateutil.parser import parse as dateutil_parse
            return dateutil_parse(ts_str)
        except Exception:
            return datetime.utcnow()
