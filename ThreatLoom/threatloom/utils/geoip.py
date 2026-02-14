"""
GeoIP resolver - looks up geographic info for IP addresses.

Uses MaxMind GeoLite2 database if available, falls back to stub data.
Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
"""
import logging
import os
import random
from typing import Dict, Optional

from threatloom.config import settings

logger = logging.getLogger("threatloom.utils.geoip")

# Try to load geoip2 library
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    logger.warning("geoip2 not installed. GeoIP lookups will use stub data.")


# Stub data for development (when MaxMind DB not available)
STUB_GEO_DATA = [
    {"country": "US", "city": "New York", "latitude": 40.7128, "longitude": -74.0060, "asn": "AS15169"},
    {"country": "CN", "city": "Beijing", "latitude": 39.9042, "longitude": 116.4074, "asn": "AS4134"},
    {"country": "RU", "city": "Moscow", "latitude": 55.7558, "longitude": 37.6173, "asn": "AS12389"},
    {"country": "DE", "city": "Frankfurt", "latitude": 50.1109, "longitude": 8.6821, "asn": "AS3320"},
    {"country": "GB", "city": "London", "latitude": 51.5074, "longitude": -0.1278, "asn": "AS2856"},
    {"country": "BR", "city": "São Paulo", "latitude": -23.5505, "longitude": -46.6333, "asn": "AS28573"},
    {"country": "IN", "city": "Mumbai", "latitude": 19.0760, "longitude": 72.8777, "asn": "AS9829"},
    {"country": "JP", "city": "Tokyo", "latitude": 35.6762, "longitude": 139.6503, "asn": "AS2516"},
    {"country": "KR", "city": "Seoul", "latitude": 37.5665, "longitude": 126.9780, "asn": "AS4766"},
    {"country": "AU", "city": "Sydney", "latitude": -33.8688, "longitude": 151.2093, "asn": "AS1221"},
    {"country": "FR", "city": "Paris", "latitude": 48.8566, "longitude": 2.3522, "asn": "AS3215"},
    {"country": "NL", "city": "Amsterdam", "latitude": 52.3676, "longitude": 4.9041, "asn": "AS1136"},
]

# Private/internal IP ranges (no GeoIP)
PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.", "127.", "0.")


class GeoIPResolver:
    """Resolve IP addresses to geographic data."""

    def __init__(self):
        self._reader = None
        self._init_reader()
        self._cache: Dict[str, dict] = {}

    def _init_reader(self):
        """Initialize the MaxMind reader if available."""
        if GEOIP_AVAILABLE and os.path.exists(settings.GEOIP_DB_PATH):
            try:
                self._reader = geoip2.database.Reader(settings.GEOIP_DB_PATH)
                logger.info(f"GeoIP database loaded: {settings.GEOIP_DB_PATH}")
            except Exception as e:
                logger.warning(f"Failed to load GeoIP DB: {e}")

    def lookup(self, ip: str) -> dict:
        """
        Look up geographic info for an IP.

        Returns dict with: country, city, latitude, longitude, asn
        """
        if not ip or ip == "0.0.0.0":
            return {}

        # Check cache
        if ip in self._cache:
            return self._cache[ip]

        # Skip private IPs
        if any(ip.startswith(prefix) for prefix in PRIVATE_PREFIXES):
            return {"country": "PRIVATE", "city": "Internal", "latitude": 0, "longitude": 0}

        result = self._resolve(ip)
        self._cache[ip] = result

        # Limit cache size
        if len(self._cache) > 10000:
            # Evict oldest entries
            keys = list(self._cache.keys())
            for k in keys[:5000]:
                del self._cache[k]

        return result

    def _resolve(self, ip: str) -> dict:
        """Resolve IP via MaxMind or stub."""
        if self._reader:
            try:
                response = self._reader.city(ip)
                return {
                    "country": response.country.iso_code,
                    "city": response.city.name,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                    "asn": None,
                }
            except Exception:
                pass

        # Stub: deterministic based on IP hash
        idx = hash(ip) % len(STUB_GEO_DATA)
        return dict(STUB_GEO_DATA[idx])
