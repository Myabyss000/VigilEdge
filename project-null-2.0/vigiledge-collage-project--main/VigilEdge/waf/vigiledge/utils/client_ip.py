"""
Trusted client IP resolution helpers.
Only honor forwarding headers when the socket peer is a configured trusted proxy.
"""

import ipaddress
from typing import Optional

from fastapi import Request

from vigiledge.config import Settings, get_settings, get_trusted_reverse_proxies


def _normalize_ip(value: str | None) -> Optional[str]:
    if not value:
        return None

    candidate = value.strip()
    if not candidate or candidate.lower() == "unknown":
        return None

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def get_socket_peer_ip(request: Request) -> str:
    """Return the direct socket peer IP for the current request."""
    try:
        return request.client.host if request.client and request.client.host else "unknown"
    except AttributeError:
        return "unknown"


def is_trusted_proxy_ip(peer_ip: str, settings_obj: Optional[Settings] = None) -> bool:
    """Return whether the socket peer matches a configured trusted reverse proxy."""
    normalized_peer = _normalize_ip(peer_ip)
    if normalized_peer is None:
        return False

    peer_address = ipaddress.ip_address(normalized_peer)
    trusted_entries = get_trusted_reverse_proxies() if settings_obj is None else [
        entry.strip() for entry in (getattr(settings_obj, "trusted_reverse_proxies", "") or "").split(",") if entry.strip()
    ]

    for entry in trusted_entries:
        try:
            if peer_address in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def get_effective_client_ip(request: Request, settings_obj: Optional[Settings] = None) -> str:
    """Resolve the real client IP, trusting forwarding headers only from trusted proxies."""
    settings_obj = settings_obj or get_settings()
    peer_ip = get_socket_peer_ip(request)

    if not is_trusted_proxy_ip(peer_ip, settings_obj=settings_obj):
        return peer_ip

    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        for part in forwarded_for.split(","):
            normalized = _normalize_ip(part)
            if normalized is not None:
                return normalized

    real_ip = _normalize_ip(request.headers.get("x-real-ip", ""))
    if real_ip is not None:
        return real_ip

    return peer_ip
