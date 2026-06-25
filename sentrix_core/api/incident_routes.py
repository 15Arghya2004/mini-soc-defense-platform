from fastapi import APIRouter, Depends, Request, HTTPException
from sentrix_core.security.auth import require_soc_analyst
from fastapi.responses import FileResponse, PlainTextResponse
import os

router = APIRouter(tags=["Incident"])

@router.get("/{incident_id}")
async def get_incident(request: Request, incident_id: str):
    invest_engine = getattr(request.app.state.engines, "investigation", None)
    if not invest_engine:
        raise HTTPException(status_code=503, detail="Investigation engine offline")
    
    report = invest_engine.get_incident(incident_id)
    if not report:
        raise HTTPException(status_code=404, detail="Incident not found")
    return report

@router.get("/{incident_id}/export/json")
async def export_json(request: Request, incident_id: str):
    invest_engine = getattr(request.app.state.engines, "investigation", None)
    if not invest_engine:
        raise HTTPException(status_code=503, detail="Investigation engine offline")
        
    path = invest_engine.export_json(incident_id)
    if not path or not os.path.exists(path):
        raise HTTPException(status_code=404, detail="JSON export failed or not found")
    return FileResponse(path, media_type='application/json', filename=os.path.basename(path))

@router.get("/{incident_id}/export/pdf")
async def export_pdf(request: Request, incident_id: str):
    invest_engine = getattr(request.app.state.engines, "investigation", None)
    if not invest_engine:
        raise HTTPException(status_code=503, detail="Investigation engine offline")
        
    path = invest_engine.export_pdf(incident_id)
    if not path or not os.path.exists(path):
        raise HTTPException(status_code=404, detail="PDF export failed or not found")
    return FileResponse(path, media_type='application/pdf', filename=os.path.basename(path))

@router.post("/{incident_id}/assign")
async def assign_incident(request: Request, incident_id: str, assignee: str):
    invest_engine = getattr(request.app.state.engines, "investigation", None)
    if not invest_engine:
        raise HTTPException(status_code=503, detail="Investigation engine offline")
    
    invest_engine.case_store.assign_case(incident_id, assignee)
    return {"status": "success", "incident_id": incident_id, "assignee": assignee}

@router.post("/{incident_id}/close")
async def close_incident(request: Request, incident_id: str):
    invest_engine = getattr(request.app.state.engines, "investigation", None)
    if not invest_engine:
        raise HTTPException(status_code=503, detail="Investigation engine offline")
    
    invest_engine.case_store.update_case_status(incident_id, "CLOSED")
    return {"status": "success", "incident_id": incident_id, "case_status": "CLOSED"}

@router.post("/{incident_id}/reopen")
async def reopen_incident(request: Request, incident_id: str):
    invest_engine = getattr(request.app.state.engines, "investigation", None)
    if not invest_engine:
        raise HTTPException(status_code=503, detail="Investigation engine offline")
    
    invest_engine.case_store.update_case_status(incident_id, "OPEN")
    return {"status": "success", "incident_id": incident_id, "case_status": "OPEN"}
