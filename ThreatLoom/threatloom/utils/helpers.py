"""
Utility helpers.
"""
import uuid
import hashlib
from datetime import datetime


def generate_uid(prefix: str = "") -> str:
    """Generate a unique identifier with optional prefix."""
    uid = str(uuid.uuid4())
    return f"{prefix}{uid}" if prefix else uid


def generate_incident_uid() -> str:
    return generate_uid("INC-")


def generate_alert_uid() -> str:
    return generate_uid("ALT-")


def hash_value(value: str) -> str:
    """SHA-256 hash of a value."""
    return hashlib.sha256(value.encode()).hexdigest()


def truncate(text: str, max_length: int = 255) -> str:
    """Truncate text to max_length."""
    if not text:
        return text
    return text[:max_length] + "..." if len(text) > max_length else text


def format_timestamp(dt: datetime) -> str:
    """Format datetime for display."""
    if not dt:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def severity_color(severity: str) -> str:
    """Return CSS color class for severity level."""
    colors = {
        "INFO": "text-gray-400",
        "LOW": "text-blue-400",
        "MEDIUM": "text-yellow-400",
        "HIGH": "text-orange-400",
        "CRITICAL": "text-red-500",
    }
    return colors.get(severity.upper(), "text-gray-400")


def severity_badge_color(severity: str) -> str:
    """Return CSS background class for severity badge."""
    colors = {
        "INFO": "bg-gray-600",
        "LOW": "bg-blue-600",
        "MEDIUM": "bg-yellow-600",
        "HIGH": "bg-orange-600",
        "CRITICAL": "bg-red-600",
    }
    return colors.get(severity.upper(), "bg-gray-600")
