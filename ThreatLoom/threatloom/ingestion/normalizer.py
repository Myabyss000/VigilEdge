"""
Log normalizer - ensures all fields conform to canonical schema.
"""
from datetime import datetime
from typing import Optional


class LogNormalizer:
    """Normalize parsed log entries into canonical format."""

    def normalize(self, parsed: dict) -> dict:
        """Apply normalization rules to a parsed log dictionary."""
        result = dict(parsed)

        # Ensure timestamp
        if "timestamp" not in result or result["timestamp"] is None:
            result["timestamp"] = datetime.utcnow()

        # Ensure src_ip
        if not result.get("src_ip"):
            result["src_ip"] = "0.0.0.0"

        # Truncate payload snippet (prevent storage bloat)
        if result.get("payload_snippet"):
            result["payload_snippet"] = result["payload_snippet"][:2048]

        # Truncate user agent
        if result.get("http_user_agent"):
            result["http_user_agent"] = result["http_user_agent"][:1024]

        # Normalize HTTP method
        if result.get("http_method"):
            result["http_method"] = result["http_method"].upper()[:10]

        # Clamp confidence
        if result.get("confidence") is not None:
            result["confidence"] = max(0.0, min(1.0, float(result["confidence"])))

        # Clean IP format (strip whitespace)
        for ip_field in ("src_ip", "dst_ip"):
            if result.get(ip_field):
                result[ip_field] = result[ip_field].strip()

        # Numeric port clamping
        for port_field in ("src_port", "dst_port"):
            if result.get(port_field) is not None:
                try:
                    port = int(result[port_field])
                    result[port_field] = port if 0 <= port <= 65535 else None
                except (ValueError, TypeError):
                    result[port_field] = None

        return result
