"""
Syslog parser - handles RFC 3164 / RFC 5424 syslog messages.
"""
import re
from datetime import datetime


class SyslogParser:
    """Parse syslog-formatted log lines into canonical dict."""

    # RFC 3164: <PRI>TIMESTAMP HOSTNAME APP[PID]: MESSAGE
    RFC3164_RE = re.compile(
        r"<(\d+)>"
        r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(\S+)\s+"
        r"(\S+?)(?:\[(\d+)\])?:\s+"
        r"(.*)"
    )

    # RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP PROCID MSGID STRUCTURED-DATA MSG
    RFC5424_RE = re.compile(
        r"<(\d+)>"
        r"(\d+)\s+"
        r"(\S+)\s+"
        r"(\S+)\s+"
        r"(\S+)\s+"
        r"(\S+)\s+"
        r"(\S+)\s+"
        r"(?:\[.*?\]|-)\s*"
        r"(.*)"
    )

    # Common key=value or key="value" patterns in syslog messages
    KV_RE = re.compile(r'(\w+)="?([^"\s,]+)"?')

    def parse(self, raw: str) -> dict:
        """Parse a syslog line into canonical fields."""
        result = {"raw_log": raw, "timestamp": datetime.utcnow()}

        # Try RFC 5424
        m = self.RFC5424_RE.match(raw)
        if m:
            result["timestamp"] = self._parse_syslog_ts(m.group(3))
            result["ingestion_pipeline"] = "syslog_rfc5424"
            message = m.group(8)
        else:
            # Try RFC 3164
            m = self.RFC3164_RE.match(raw)
            if m:
                result["timestamp"] = self._parse_syslog_ts(m.group(2))
                result["ingestion_pipeline"] = "syslog_rfc3164"
                message = m.group(6)
            else:
                # Fallback: treat entire line as message
                message = raw
                result["ingestion_pipeline"] = "syslog_raw"

        # Extract key=value pairs from the message body
        kvs = dict(self.KV_RE.findall(message))
        result.update(self._map_kv_fields(kvs))

        # Extract IPs via regex if not found
        if "src_ip" not in result:
            ip_match = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', message)
            if ip_match:
                result["src_ip"] = ip_match[0]
                if len(ip_match) > 1:
                    result["dst_ip"] = ip_match[1]

        # Ensure src_ip exists
        if "src_ip" not in result:
            result["src_ip"] = "0.0.0.0"

        return result

    def _map_kv_fields(self, kvs: dict) -> dict:
        """Map extracted key-value pairs to canonical fields."""
        mapped = {}
        alias_map = {
            "src": "src_ip", "source": "src_ip", "srcip": "src_ip", "client": "src_ip",
            "dst": "dst_ip", "dest": "dst_ip", "dstip": "dst_ip", "server": "dst_ip",
            "srcport": "src_port", "sport": "src_port",
            "dstport": "dst_port", "dport": "dst_port",
            "proto": "protocol", "protocol": "protocol",
            "action": "action", "verdict": "action",
            "method": "http_method",
            "uri": "http_path", "path": "http_path", "url": "http_path",
            "status": "http_status",
            "ua": "http_user_agent", "agent": "http_user_agent",
            "attack": "attack_type", "threat": "attack_type", "category": "attack_type",
            "severity": "severity",
            "rule": "matched_rule",
        }
        for k, v in kvs.items():
            canonical = alias_map.get(k.lower(), k.lower())
            mapped[canonical] = v

        # Convert numeric fields
        for field in ["src_port", "dst_port", "http_status"]:
            if field in mapped:
                try:
                    mapped[field] = int(mapped[field])
                except (ValueError, TypeError):
                    del mapped[field]

        return mapped

    @staticmethod
    def _parse_syslog_ts(ts_str: str) -> datetime:
        """Parse common syslog timestamp formats."""
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%b %d %H:%M:%S",
            "%b  %d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str.strip(), fmt)
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.utcnow().year)
                return dt
            except ValueError:
                continue
        return datetime.utcnow()
