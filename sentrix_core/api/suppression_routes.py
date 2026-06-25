from fastapi import APIRouter, Depends, Request, HTTPException, status
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from sentrix_core.security.auth import require_admin, require_soc_analyst
from sentrix_core.suppression.suppression_engine import SuppressionEngine

router = APIRouter(tags=["Suppression"])

class SuppressionPayload(BaseModel):
    suppression_type: str
    value: str
    rule_id: Optional[str] = None
    reason: Optional[str] = ""
    expires_at: Optional[str] = None

class MaintenancePayload(BaseModel):
    name: str
    start_time: str
    end_time: str
    scope: Optional[str] = "global"
    scope_value: Optional[str] = None

def get_suppression_engine(request: Request) -> SuppressionEngine:
    engine = getattr(request.app.state.engines, "suppression", None)
    if not engine:
        # Fallback to local init if not in app state
        from sentrix_core.suppression.suppression_engine import SuppressionEngine
        engine = SuppressionEngine()
    return engine

@router.post("/", response_model=Dict[str, Any])
async def create_suppression(
    payload: SuppressionPayload,
    user: dict = Depends(require_admin),
    engine: SuppressionEngine = Depends(get_suppression_engine)
):
    try:
        return engine.add_suppression(
            suppression_type=payload.suppression_type,
            value=payload.value,
            rule_id=payload.rule_id,
            reason=payload.reason,
            created_by=user.get("sub", "system"),
            expires_at=payload.expires_at
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

@router.get("/", response_model=List[Dict[str, Any]])
async def list_suppressions(
    suppression_type: Optional[str] = None,
    active_only: bool = True,
    user: dict = Depends(require_soc_analyst),
    engine: SuppressionEngine = Depends(get_suppression_engine)
):
    return engine.list_suppressions(suppression_type=suppression_type, active_only=active_only)

@router.delete("/{suppression_id}", response_model=Dict[str, Any])
async def delete_suppression(
    suppression_id: str,
    user: dict = Depends(require_admin),
    engine: SuppressionEngine = Depends(get_suppression_engine)
):
    success = engine.remove_suppression(suppression_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Suppression entry not found or already inactive")
    return {"status": "success", "message": f"Suppression entry {suppression_id} deleted."}

@router.post("/maintenance", response_model=Dict[str, Any])
async def create_maintenance_window(
    payload: MaintenancePayload,
    user: dict = Depends(require_admin),
    engine: SuppressionEngine = Depends(get_suppression_engine)
):
    try:
        return engine.add_maintenance_window(
            name=payload.name,
            start_time=payload.start_time,
            end_time=payload.end_time,
            scope=payload.scope,
            scope_value=payload.scope_value,
            created_by=user.get("sub", "system")
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

@router.get("/maintenance", response_model=List[Dict[str, Any]])
async def list_maintenance_windows(
    active_only: bool = True,
    user: dict = Depends(require_soc_analyst),
    engine: SuppressionEngine = Depends(get_suppression_engine)
):
    return engine.list_maintenance_windows(active_only=active_only)
