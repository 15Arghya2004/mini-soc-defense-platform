from fastapi import APIRouter, Depends, Request, HTTPException
from sentrix_core.security.auth import require_soc_analyst

router = APIRouter(tags=["Investigation"])

@router.post("/generate/{source_ip}")
async def generate_investigation(request: Request, source_ip: str, severity: str = "high"):
    invest_engine = getattr(request.app.state.engines, "investigation", None)
    if not invest_engine:
        raise HTTPException(status_code=503, detail="Investigation engine offline")
    
    invest_engine.trigger_investigation(source_ip, incident_id=None, severity=severity)
    return {"status": "Investigation triggered", "source_ip": source_ip}

@router.get("/incidents")
async def get_incidents(request: Request):
    invest_engine = getattr(request.app.state.engines, "investigation", None)
    if not invest_engine:
        raise HTTPException(status_code=503, detail="Investigation engine offline")
    return invest_engine.list_incidents()
