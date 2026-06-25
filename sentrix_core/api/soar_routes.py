"""
sentrix_core/api/soar_routes.py
SOAR API endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException
from sentrix_core.response_engine.soar import SOAREngine

router = APIRouter(tags=["SOAR"])
soar_engine = SOAREngine()

@router.get("/audit", summary="Get SOAR Action Audit Log")
def get_audit_log(limit: int = 100):
    return {"audit_log": soar_engine.get_audit_log(limit)}

@router.post("/execute", summary="Manually trigger a SOAR action (Simulated)")
def trigger_action(action_type: str, target: str, incident_id: str = None):
    result = soar_engine.execute_action(action_type, target, incident_id)
    return result
