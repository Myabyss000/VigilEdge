"""
WebSocket connection manager for real-time event feeds.
"""
import json
import logging
from typing import Dict, Optional, Set
from datetime import datetime

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from threatloom.database import async_session
from threatloom.auth.jwt import decode_access_token
from threatloom.models.users import User

logger = logging.getLogger("threatloom.websocket")

ws_router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""

    def __init__(self):
        # channel -> set of connections
        self.channels: Dict[str, Set[WebSocket]] = {
            "alerts": set(),
            "logs": set(),
            "incidents": set(),
            "metrics": set(),
            "notifications": set(),
        }

    async def connect(self, websocket: WebSocket, channel: str = "alerts"):
        await websocket.accept()
        if channel not in self.channels:
            self.channels[channel] = set()
        self.channels[channel].add(websocket)
        logger.info(f"WebSocket connected: channel={channel}")

    def disconnect(self, websocket: WebSocket, channel: str = "alerts"):
        if channel in self.channels:
            self.channels[channel].discard(websocket)
        logger.info(f"WebSocket disconnected: channel={channel}")

    async def broadcast(self, channel: str, data: dict):
        """Broadcast message to all connections on a channel."""
        if channel not in self.channels:
            return

        message = json.dumps(data, default=str)
        disconnected = set()

        for ws in self.channels[channel]:
            try:
                await ws.send_text(message)
            except Exception:
                disconnected.add(ws)

        # Clean up dead connections
        for ws in disconnected:
            self.channels[channel].discard(ws)

    async def broadcast_alert(self, alert_data: dict):
        """Broadcast a new alert to the alerts channel."""
        await self.broadcast("alerts", {
            "type": "new_alert",
            "timestamp": datetime.utcnow().isoformat(),
            "data": alert_data,
        })

    async def broadcast_log(self, log_data: dict):
        """Broadcast a new log entry to the logs channel."""
        await self.broadcast("logs", {
            "type": "new_log",
            "timestamp": datetime.utcnow().isoformat(),
            "data": log_data,
        })

    async def broadcast_metrics(self, metrics: dict):
        """Broadcast system metrics update."""
        await self.broadcast("metrics", {
            "type": "metrics_update",
            "timestamp": datetime.utcnow().isoformat(),
            "data": metrics,
        })

    async def broadcast_notification(self, notification_data: dict):
        """Broadcast a notification event."""
        await self.broadcast("notifications", {
            "type": "notification",
            "timestamp": datetime.utcnow().isoformat(),
            "data": notification_data,
        })



# Singleton manager
manager = ConnectionManager()


@ws_router.websocket("/ws/{channel}")
async def websocket_endpoint(
    websocket: WebSocket,
    channel: str,
    token: Optional[str] = Query(default=None),
):
    """WebSocket endpoint for real-time event streaming. Requires a valid JWT via ?token=."""
    # Accept first so that the close frame (with our custom code) is properly
    # transmitted to the browser.  Without accept(), the browser sees 1006
    # (abnormal closure) and cannot distinguish auth failures from network drops.
    await websocket.accept()

    # --- Auth check (uses its own short-lived session — never holds a DB
    #     connection open for the entire WS lifetime, which would conflict
    #     with SQLite's single-writer model) ---
    if not token:
        await websocket.close(code=4001, reason="Missing authentication token")
        return
    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        if not user_id:
            raise ValueError("Missing sub claim")
        async with async_session() as session:
            result = await session.execute(select(User).where(User.id == int(user_id)))
            user = result.scalar_one_or_none()
        if user is None or not user.is_active:
            raise ValueError("User invalid or inactive")
    except Exception:
        await websocket.close(code=4001, reason="Unauthorized")
        return

    if channel not in manager.channels:
        await websocket.close(code=4000, reason=f"Unknown channel: {channel}")
        return

    manager.channels[channel].add(websocket)
    logger.info(f"WebSocket connected: channel={channel}")
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket, channel)
    except Exception as exc:
        logger.warning(f"WebSocket error: channel={channel} {type(exc).__name__}: {exc}")
        manager.disconnect(websocket, channel)
