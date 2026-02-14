"""
WebSocket connection manager for real-time event feeds.
"""
import json
import logging
from typing import Dict, Set
from datetime import datetime

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

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


# Singleton manager
manager = ConnectionManager()


@ws_router.websocket("/ws/{channel}")
async def websocket_endpoint(websocket: WebSocket, channel: str):
    """WebSocket endpoint for real-time event streaming."""
    if channel not in manager.channels:
        await websocket.close(code=4000, reason=f"Unknown channel: {channel}")
        return

    await manager.connect(websocket, channel)
    try:
        while True:
            # Keep connection alive; handle incoming messages
            data = await websocket.receive_text()
            # Client can send ping/pong or subscribe commands
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket, channel)
