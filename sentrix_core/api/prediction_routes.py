from fastapi import APIRouter, Depends, Request, HTTPException
from sentrix_core.security.auth import require_soc_analyst

router = APIRouter(tags=["Prediction"])

@router.get("/forecast")
async def get_forecast(request: Request):
    pred_engine = getattr(request.app.state.engines, "prediction", None)
    if not pred_engine:
        raise HTTPException(status_code=503, detail="Prediction engine offline")
    return pred_engine.get_live_forecasts()

@router.get("/forecast/{source_ip}")
async def get_forecast_for_ip(request: Request, source_ip: str):
    pred_engine = getattr(request.app.state.engines, "prediction", None)
    if not pred_engine:
        raise HTTPException(status_code=503, detail="Prediction engine offline")
    
    forecast = pred_engine.get_forecast_for_ip(source_ip)
    if not forecast:
        raise HTTPException(status_code=404, detail="No forecast found for IP")
    return forecast

@router.get("/history")
async def get_history(request: Request, limit: int = 50):
    pred_engine = getattr(request.app.state.engines, "prediction", None)
    if not pred_engine:
        raise HTTPException(status_code=503, detail="Prediction engine offline")
    return pred_engine.get_history(limit)
