from fastapi import APIRouter, Depends, Request, HTTPException
from sentrix_core.security.auth import require_admin, require_soc_analyst

router = APIRouter(tags=["Connectors"])

@router.get("/")
async def list_connectors(request: Request):
    registry = getattr(request.app.state.engines, "connector_registry", None)
    if not registry:
        raise HTTPException(staatus_code=503, detail="Connector Registry offline")
    return registry.get_all_connectors()

@router.post("/{connector_name}/enable")
async def enable_connector(request: Request, connector_name: str):
    registry = getattr(request.app.state.engines, "connector_registry", None)
    if not registry:
        raise HTTPException(status_code=503, detail="Connector Registry offline")
    
    registry.enable_connector(connector_name)
    return {"status": "success", "message": f"Connector {connector_name} enabled."}

@router.post("/{connector_name}/disable")
async def disable_connector(request: Request, connector_name: str):
    registry = getattr(request.app.state.engines, "connector_registry", None)
    if not registry:
        raise HTTPException(status_code=503, detail="Connector Registry offline")
    
    registry.disable_connector(connector_name)
    return {"status": "success", "message": f"Connector {connector_name} disabled."}

@router.post("/enrich/{ip}")
async def enrich_ip(request: Request, ip: str):
    registry = getattr(request.app.state.engines, "connector_registry", None)
    if not registry:
        raise HTTPException(status_code=503, detail="Connector Registry offline")
    
    return registry.enrich_ip(ip)
