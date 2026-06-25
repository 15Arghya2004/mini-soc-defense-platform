from fastapi import APIRouter, Depends, Request, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
from sentrix_core.security.auth import require_soc_analyst
from sentrix_core.storage.event_store import get_event_store

router = APIRouter(tags=["Threat"])

class EventPayload(BaseModel):
    event: Dict[str, Any]

@router.post("/events/ingest")
async def ingest_event(request: Request, payload: EventPayload):
    threat_engine = getattr(request.app.state.engines, "threat", None)
    if not threat_engine:
        raise HTTPException(status_code=503, detail="Threat engine offline")

    raw_event = payload.event

    # ── Detect source type from raw event ──────────────────────────────────────
    if "rule" in raw_event and isinstance(raw_event.get("rule"), dict) and (
        "agent" in raw_event or "data" in raw_event or "decoder" in raw_event
    ):
        source_type = "wazuh"
    elif "event_type" in raw_event and "src_ip" in raw_event:
        source_type = "suricata"
    else:
        source_type = "generic"

    # ── Persist raw event immediately ─────────────────────────────────────────
    try:
        event_store = get_event_store()
        event_store.store_event(raw_event, source=source_type)
    except Exception as store_err:
        import logging
        logging.getLogger("sentrix.threat_routes").warning(
            "EventStore write error: %s", store_err
        )

    # ── Publish to Event Bus ──────────────────────────────────────────────────
    from sentrix_core.event_bus.bus import EventPublisher
    pub = EventPublisher()
    pub.publish("events.ingested", raw_event)

    return {"status": "queued", "message": "Event published to internal bus"}
@router.get("/status")
async def get_threat_status(request: Request):
    threat_engine = getattr(request.app.state.engines, "threat", None)
    if not threat_engine:
        raise HTTPException(status_code=503, detail="Threat engine offline")
    return threat_engine.get_status()

