from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sentrix_core.security.auth import require_admin
import time

router = APIRouter(tags=["Admin"])

class HealthResponse(BaseModel):
    status: str
    uptime_seconds: float
    threat_engine: dict
    prediction_engine: dict
    investigation_engine: dict

@router.get("/health")
async def get_health(request: Request):
    engines = getattr(request.app.state, "engines", None)
    start_time = getattr(request.app.state, "start_time", time.time())

    threat = getattr(engines, "threat", None) if engines else None
    pred = getattr(engines, "prediction", None) if engines else None
    invest = getattr(engines, "investigation", None) if engines else None

    return {
        "status": "healthy",
        "uptime_seconds": round(time.time() - start_time, 2),
        "threat_engine": threat.get_status() if threat else {"status": "offline"},
        "prediction_engine": pred.get_status() if pred else {"status": "offline"},
        "investigation_engine": invest.get_status() if invest else {"status": "offline"},
    }

@router.get("/ready")
async def get_ready():
    return {"status": "ready"}

@router.post("/auth/token")
async def issue_token(request: Request):
    """Issue a JWT token for admin API key holders."""
    from sentrix_core.security.auth import create_access_token, get_current_user
    from fastapi.security import APIKeyHeader
    from fastapi import Security
    settings = request.app.extra.get("settings") if hasattr(request.app, "extra") else None
    # Simple: if request carries a valid API key, return a JWT token
    from sentrix_core.config.settings import get_settings
    cfg = get_settings()
    api_key = request.headers.get("X-API-Key")
    if cfg.AUTH_ENABLED and (not api_key or api_key != cfg.SENTRIX_API_KEY):
        raise HTTPException(status_code=401, detail="Valid X-API-Key required to issue token")
    token = create_access_token({"sub": "admin_user", "role": "admin"})
    return {"access_token": token, "token_type": "bearer"}

