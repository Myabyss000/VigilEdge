"""
VigilEdge WAF - Web Application Firewall
Advanced security monitoring and threat detection system
"""

__version__ = "1.0.0"
__author__ = "VigilEdge Security Team"
__email__ = "security@vigiledge.com"

from .config import Settings, get_settings
from .core.waf_engine import WAFEngine
from .core.security_manager import SecurityManager

__all__ = [
    "Settings",
    "get_settings", 
    "WAFEngine",
    "SecurityManager",
]
