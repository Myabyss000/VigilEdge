"""
Utilities for upstream website routing and productized WAF exposure modes.
"""

from __future__ import annotations

from typing import Any


RESERVED_EXACT_PATHS = {
    "/login",
    "/logout",
    "/dashboard",
    "/analytics",
    "/blocked-ips",
    "/event-logs",
    "/network-monitor",
    "/security-rules",
    "/settings",
    "/threat-detection",
    "/visualization-demo",
    "/ai-analysis",
    "/enhanced",
    "/classic",
    "/favicon.ico",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/ws",
    "/proxy",
    "/test-target",
}

RESERVED_PREFIXES = (
    "/api/",
    "/admin",
    "/auth/",
    "/static/",
    "/ws/",
)


def normalize_proxy_path(path: str | None) -> str:
    """Return a normalized public subpath such as /protected."""
    raw = (path or "/protected").strip()
    if not raw:
        return "/protected"
    if not raw.startswith("/"):
        raw = f"/{raw}"
    return raw.rstrip("/") or "/"


def get_upstream_public_mode(settings: Any) -> str:
    return getattr(settings, "upstream_public_mode", "protected")


def get_upstream_proxy_path(settings: Any) -> str:
    return normalize_proxy_path(getattr(settings, "vulnerable_app_proxy_path", "/protected"))


def upstream_root_enabled(settings: Any) -> bool:
    return get_upstream_public_mode(settings) in {"root", "both"}


def upstream_subpath_enabled(settings: Any) -> bool:
    return get_upstream_public_mode(settings) in {"protected", "both"}


def get_selected_upstream_url(settings: Any) -> str:
    return getattr(settings, "vulnerable_app_url", "http://localhost:8080").rstrip("/")


def is_demo_upstream_selected(settings: Any) -> bool:
    return bool(getattr(settings, "upstream_use_demo_target", False))


def is_reserved_waf_path(path: str, settings: Any | None = None) -> bool:
    if path in RESERVED_EXACT_PATHS:
        return True

    if settings is not None:
        proxy_path = get_upstream_proxy_path(settings)
        if proxy_path != "/" and (path == proxy_path or path.startswith(f"{proxy_path}/")):
            return True

    return any(path.startswith(prefix) for prefix in RESERVED_PREFIXES)


def should_proxy_root_request(path: str, settings: Any) -> bool:
    if not upstream_root_enabled(settings):
        return False
    return not is_reserved_waf_path(path, settings)