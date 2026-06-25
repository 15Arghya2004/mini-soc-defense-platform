"""
sentrix_core/api/dashboard_routes.py

Dashboard REST API for Sentrix V10.

Provides all endpoints consumed by the live dashboard.
All routes are read-only and pull from the persistent EventStore (SQLite).
No memory queries from engines anymore.

Endpoints:
    GET /api/v1/dashboard/events         
    GET /api/v1/dashboard/alerts         
    GET /api/v1/dashboard/incidents      
    GET /api/v1/dashboard/predictions    
    GET /api/v1/dashboard/investigations 
    GET /api/v1/dashboard/timeline       
    GET /api/v1/dashboard/metrics        
    GET /api/v1/dashboard/ioc            
    GET /api/v1/dashboard/mitre          
    GET /api/v1/dashboard/top-attackers  
    GET /api/v1/dashboard/top-targets    
    GET /api/v1/dashboard/search         
    GET /api/v1/dashboard/assets         
    GET /api/v1/dashboard/users          
"""
from fastapi import APIRouter, Request, HTTPException, Query
from typing import Optional
import logging

from sentrix_core.storage.event_store import get_event_store

logger = logging.getLogger("sentrix.dashboard_api")

router = APIRouter(tags=["Dashboard"])


def _event_store():
    try:
        return get_event_store()
    except Exception as e:
        logger.error("[DashboardAPI] EventStore unavailable: %s", e)
        raise HTTPException(status_code=503, detail="Event store not available")


@router.get("/events")
async def get_events(
    limit:      int           = Query(100, ge=1, le=1000),
    offset:     int           = Query(0,   ge=0),
    source:     Optional[str] = Query(None, description="suricata | wazuh"),
    event_type: Optional[str] = Query(None),
    src_ip:     Optional[str] = Query(None),
):
    store = _event_store()
    events = store.get_events(limit=limit, offset=offset, source=source, event_type=event_type, src_ip=src_ip)
    total = store.get_event_count(source=source)
    return {"total": total, "limit": limit, "offset": offset, "events": events}


@router.get("/alerts")
async def get_alerts(
    limit:       int           = Query(100, ge=1, le=1000),
    offset:      int           = Query(0,   ge=0),
    severity:    Optional[str] = Query(None),
    source_type: Optional[str] = Query(None),
):
    store = _event_store()
    alerts = store.get_alerts(limit=limit, offset=offset, severity=severity, source_type=source_type)
    total = store.get_alert_count(severity=severity)
    return {"total": total, "limit": limit, "offset": offset, "alerts": alerts}


@router.get("/incidents")
async def get_incidents(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    store = _event_store()
    incidents = store.get_incidents(limit=limit, offset=offset)
    # Dashboard expects `correlated_at`, `source_ip`, `severity`, `sources` (array), `alert_count`, `risk_score`
    items = []
    for inc in incidents:
        sources = inc.get("sources", [])
        if isinstance(sources, str):
            try:
                import json as _json
                sources = _json.loads(sources)
            except Exception:
                sources = [sources] if sources else []
        items.append({
            "correlated_at": inc.get("created_at", ""),
            "source_ip":     inc.get("source_ip", "unknown"),
            "severity":      inc.get("severity", "medium"),
            "sources":       sources,
            "alert_count":   inc.get("alert_count", 0),
            "risk_score":    inc.get("risk_score", 0),
        })
    return {"total": len(items), "incidents": items}


@router.get("/correlated")
async def get_correlated(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    """Alias for /incidents — used by the dashboard HTML."""
    return await get_incidents(limit=limit, offset=offset)


@router.get("/predictions")
async def get_predictions(limit: int = Query(50, ge=1, le=200)):
    store = _event_store()
    predictions = store.get_predictions(limit=limit)
    # Dashboard expects `live_forecasts` with specific fields
    forecasts = []
    for p in predictions:
        forecasts.append({
            "source_ip":      p.get("source_ip", "unknown"),
            "predicted_stage": p.get("predicted_attack", "Unknown"),
            "probability":    round((p.get("confidence") or 0) * 100, 1),
            "current_stage":  p.get("context", ""),
            "campaign":       "",
            "risk":           p.get("confidence", 0),
            "time":           p.get("created_at", ""),
        })
    return {"total": len(forecasts), "live_forecasts": forecasts}


@router.get("/investigations")
async def get_investigations(limit: int = Query(100, ge=1, le=500)):
    store = _event_store()
    investigations = store.get_investigations(limit=limit)
    # Dashboard expects `incident_id`, `created_at`, `source_ip`, `severity`, `status`, `assigned_analyst`
    items = []
    for inv in investigations:
        items.append({
            "incident_id":      inv.get("incident_id", ""),
            "created_at":       inv.get("created_at", ""),
            "source_ip":        inv.get("source_ip", "—"),
            "severity":         inv.get("severity", "medium"),
            "status":           inv.get("status", "open"),
            "assigned_analyst": inv.get("assigned_analyst", "unassigned"),
        })
    return {"total": len(items), "investigations": items}


@router.get("/timeline")
async def get_timeline(limit: int = Query(200, ge=1, le=1000)):
    store = _event_store()
    timeline = store.get_timeline(limit=limit)
    # Dashboard expects `kind`, `ts`, `label`, `source_ip`, `severity`
    items = []
    for t in timeline:
        items.append({
            "kind":      t.get("event_type", "event"),
            "ts":        t.get("timestamp", ""),
            "label":     t.get("description", ""),
            "source_ip": t.get("source_ip"),
            "severity":  t.get("severity", "informational"),
        })
    return {"total": len(items), "timeline": items}


@router.get("/metrics")
async def get_metrics():
    store = _event_store()
    metrics = store.get_metrics()
    return metrics


@router.get("/ioc")
async def get_iocs(ioc_type: Optional[str] = Query(None), limit: int = Query(100, ge=1, le=500)):
    store = _event_store()
    iocs = store.get_iocs(ioc_type=ioc_type, limit=limit)
    return {"total": len(iocs), "iocs": iocs}


@router.get("/mitre")
async def get_mitre():
    store = _event_store()
    hits = store.get_mitre_hits()
    return {"total": len(hits), "techniques": hits}


@router.get("/top-attackers")
async def get_top_attackers(limit: int = Query(20, ge=1, le=100)):
    store = _event_store()
    attackers = store.get_top_attackers(limit=limit)
    return {"total": len(attackers), "attackers": attackers}


@router.get("/top-targets")
async def get_top_targets(limit: int = Query(20, ge=1, le=100)):
    store = _event_store()
    targets = store.get_top_targets(limit=limit)
    return {"total": len(targets), "targets": targets}


@router.get("/search")
async def search_events(q: str = Query(..., min_length=2), limit: int = Query(50, ge=1, le=200)):
    store = _event_store()
    results = store.search_events(query=q, limit=limit)
    return {"total": len(results), "results": results}


@router.get("/assets")
async def get_assets(limit: int = Query(100, ge=1, le=500)):
    store = _event_store()
    assets = store.get_assets(limit=limit)
    return {"total": len(assets), "assets": assets}


@router.get("/users")
async def get_users(limit: int = Query(100, ge=1, le=500)):
    store = _event_store()
    users = store.get_users(limit=limit)
    return {"total": len(users), "users": users}


@router.get("/status")
async def get_status():
    store = _event_store()
    try:
        metrics = store.get_metrics()
        return {
            "status":          "online",
            "total_events":    metrics.get("total_events", 0),
            "total_alerts":    metrics.get("total_alerts", 0),
            "critical_alerts": metrics.get("critical_alerts", 0),
            "high_alerts":     metrics.get("high_alerts", 0),
            "unique_attackers":metrics.get("unique_attackers", 0),
            "avg_risk_score":  metrics.get("avg_risk_score", 0),
        }
    except Exception as e:
        logger.error("[DashboardAPI] Status error: %s", e)
        return {"status": "degraded"}
