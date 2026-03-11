"""
WebSocket Routes for VigilEdge WAF
Handles real-time WebSocket connections for live dashboard updates.
"""

import json
import asyncio
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from websockets.exceptions import ConnectionClosedError

from .auth import COOKIE_NAME, is_control_plane_token_valid, validate_admin_session_token

router = APIRouter(tags=["WebSocket"])


def _is_websocket_authorized(websocket: WebSocket) -> bool:
    """Authorize dashboard WebSocket clients via session cookie or bearer-style service token."""
    settings_obj = websocket.app.state.settings

    session_token = websocket.cookies.get(COOKIE_NAME)
    if session_token and validate_admin_session_token(session_token, settings_obj):
        return True

    auth_header = websocket.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        bearer_token = auth_header.split(" ", 1)[1].strip()
        if is_control_plane_token_valid(bearer_token, settings_obj):
            return True

    query_token = websocket.query_params.get("access_token")
    if query_token and is_control_plane_token_valid(query_token, settings_obj):
        return True

    return False


def get_waf_engine():
    """Get WAF engine from app state."""
    from app import waf_engine
    return waf_engine


def get_ws_manager():
    """Get WebSocket manager from app state."""
    from services.websocket_manager import manager
    return manager


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time dashboard updates."""
    if not _is_websocket_authorized(websocket):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    manager = get_ws_manager()
    waf_engine = get_waf_engine()
    
    await manager.connect(websocket)
    last_ping = asyncio.get_event_loop().time()
    ping_interval = 15  # Send ping every 15 seconds for mobile stability
    
    try:
        while True:
            current_time = asyncio.get_event_loop().time()
            
            # Send heartbeat ping to keep connection alive (especially for mobile)
            if current_time - last_ping >= ping_interval:
                try:
                    await websocket.send_json({"type": "ping"})
                    last_ping = current_time
                except:
                    break  # Connection lost, exit loop
            
            # Send periodic metrics updates
            try:
                metrics = await waf_engine.get_metrics()
                await manager.send_personal_message(
                    json.dumps({"type": "metrics", "data": metrics}),
                    websocket
                )
            except:
                break  # Connection lost, exit loop
            
            # Check for incoming messages (pong responses)
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=2.0)
            except asyncio.TimeoutError:
                # No message received, that's fine - continue
                pass
            except:
                break  # Connection error, exit loop
            
            await asyncio.sleep(3)  # Reduced from 5 to 3 seconds for faster updates
            
    except (WebSocketDisconnect, ConnectionClosedError):
        # Client disconnected normally - silent cleanup
        pass
    except Exception:
        # Any other error - silent cleanup
        pass
    finally:
        manager.disconnect(websocket)
