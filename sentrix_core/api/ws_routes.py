"""
sentrix_core/api/ws_routes.py

WebSocket Live Feed for Sentrix V10 Dashboard.

Provides a real-time push channel for the dashboard:
  WS /ws/live  — streams new events and alerts as they arrive

Protocol:
  Server pushes JSON messages every POLL_INTERVAL seconds (default 2s).
  Message format:
    {
      "type":       "update" | "heartbeat" | "error",
      "events":     [...],   — new raw events since last push
      "alerts":     [...],   — new alerts since last push
      "metrics":    {...},   — current KPI snapshot
      "timestamp":  "ISO8601"
    }

  Client may send:
    { "action": "ping" }  → server replies with heartbeat
"""
import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from sentrix_core.storage.event_store import get_event_store

logger = logging.getLogger("sentrix.ws")

router = APIRouter(tags=["WebSocket"])

# Push interval in seconds
POLL_INTERVAL = 2.0

# Active connection set for broadcasting
_active_connections: Set[WebSocket] = set()


class ConnectionManager:
    def __init__(self):
        self.active: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.add(ws)
        logger.info("[WS] Client connected. Active: %d", len(self.active))

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws)
        logger.info("[WS] Client disconnected. Active: %d", len(self.active))

    async def send(self, ws: WebSocket, message: dict):
        try:
            await ws.send_text(json.dumps(message, default=str))
        except Exception:
            self.disconnect(ws)


manager = ConnectionManager()


@router.websocket("/ws/live")
async def websocket_live_feed(websocket: WebSocket):
    """
    Live event feed WebSocket.
    Pushes new events, alerts, and metrics every POLL_INTERVAL seconds.
    """
    await manager.connect(websocket)

    try:
        store = get_event_store()
    except Exception as e:
        await websocket.send_text(json.dumps({
            "type": "error",
            "message": f"EventStore unavailable: {e}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))
        manager.disconnect(websocket)
        return

    # Track high-water mark to only push new records
    last_event_id = store.get_max_event_id()
    last_alert_id = store.get_max_alert_id()

    try:
        while True:
            # Check for incoming client message (non-blocking)
            try:
                client_msg = await asyncio.wait_for(websocket.receive_text(), timeout=0.05)
                try:
                    data = json.loads(client_msg)
                    if data.get("action") == "ping":
                        await manager.send(websocket, {
                            "type": "heartbeat",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        })
                except Exception:
                    pass
            except asyncio.TimeoutError:
                pass

            await asyncio.sleep(POLL_INTERVAL)

            # Fetch new events and alerts since last push
            try:
                new_events = store.get_events_since(last_event_id, limit=50)
                new_alerts = store.get_alerts_since(last_alert_id, limit=20)

                if new_events:
                    last_event_id = new_events[-1]["id"]
                if new_alerts:
                    last_alert_id = new_alerts[-1]["id"]

                # Always send, even if empty (includes metrics)
                metrics = store.get_metrics()

                message = {
                    "type":      "update",
                    "events":    new_events,
                    "alerts":    new_alerts,
                    "metrics":   {
                        "total_events":    metrics.get("total_events", 0),
                        "total_alerts":    metrics.get("total_alerts", 0),
                        "critical_alerts": metrics.get("critical_alerts", 0),
                        "high_alerts":     metrics.get("high_alerts", 0),
                        "unique_attackers":metrics.get("unique_attackers", 0),
                        "avg_risk_score":  metrics.get("avg_risk_score", 0),
                    },
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

                await manager.send(websocket, message)

            except Exception as e:
                logger.warning("[WS] Push error: %s", e)
                await manager.send(websocket, {
                    "type":      "heartbeat",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error("[WS] Unexpected error: %s", e)
        manager.disconnect(websocket)
