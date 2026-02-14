"""
VigilEdge WAF - Route modules
All API and page routes are organized into separate modules for maintainability.
"""

from .dashboard import router as dashboard_router
from .api_blocked_ips import router as blocked_ips_router
from .api_events import router as events_router
from .api_metrics import router as metrics_router
from .api_settings import router as settings_router
from .api_network import router as network_router
from .api_ai import router as ai_router
from .api_chatbot import router as chatbot_router
from .proxy import router as proxy_router
from .websocket import router as websocket_router
from .auth import router as auth_router

__all__ = [
    "dashboard_router",
    "blocked_ips_router",
    "events_router",
    "metrics_router",
    "settings_router",
    "network_router",
    "ai_router",
    "chatbot_router",
    "proxy_router",
    "websocket_router",
    "auth_router",
]
