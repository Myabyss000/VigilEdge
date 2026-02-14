"""
WebSocket Connection Manager for VigilEdge WAF
Handles real-time WebSocket connections for live dashboard updates.
"""

from typing import List
from fastapi import WebSocket
from websockets.exceptions import ConnectionClosedError
from fastapi.websockets import WebSocketDisconnect


class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Accept and track a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection from tracking."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        """Send a message to a specific WebSocket connection."""
        try:
            await websocket.send_text(message)
        except (ConnectionClosedError, WebSocketDisconnect):
            # Client disconnected, remove from active connections silently
            self.disconnect(websocket)
        except Exception:
            # Handle any other WebSocket errors silently
            self.disconnect(websocket)

    async def broadcast(self, message: str):
        """Broadcast a message to all connected WebSocket clients."""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except (ConnectionClosedError, WebSocketDisconnect, Exception):
                # Mark for removal instead of immediate removal to avoid iteration issues
                disconnected.append(connection)
        
        # Remove disconnected connections
        for connection in disconnected:
            if connection in self.active_connections:
                self.active_connections.remove(connection)


# Global singleton instance
manager = ConnectionManager()
