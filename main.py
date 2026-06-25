"""
Sentrix V8 — Enterprise Unified SOC/XDR Platform
Main FastAPI Entrypoint.
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from sentrix_core.config.settings import get_settings

# Setup centralized configuration first
settings = get_settings()
settings.ensure_dirs()

# Ensure default rules exist before engine loads them
from sentrix_core.rule_define_studio.default_pack import ensure_default_pack
ensure_default_pack(settings.rules_dir)

# Import the engines
from sentrix_core.threat_engine.engine import SentrixThreatEngine
from sentrix_core.prediction_engine.engine import PredictionEngine
from sentrix_core.investigation_engine.engine import InvestigationStudioEngine
from sentrix_core.rule_define_studio.studio import RuleStudio
from sentrix_core.rule_define_studio.rule_tester import RuleTester
from sentrix_core.rule_define_studio.hot_reload import RuleReloader
from sentrix_core.connector_framework.registry import ConnectorRegistry
from sentrix_core.event_bus.bus import init_bus
# Import all routers
from sentrix_core.api.threat_routes import router as threat_router
from sentrix_core.api.prediction_routes import router as prediction_router
from sentrix_core.api.investigation_routes import router as investigation_router
from sentrix_core.api.incident_routes import router as incident_router
from sentrix_core.api.rule_routes import router as rule_router
from sentrix_core.api.connector_routes import router as connector_router
from sentrix_core.api.admin_routes import router as admin_router
from sentrix_core.api.suppression_routes import router as suppression_router
from sentrix_core.api.dashboard_routes import router as dashboard_router
from sentrix_core.api.ws_routes import router as ws_router

import time

logger = logging.getLogger("sentrix.main")

class EnginesState:
    pass

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start engines and initialize singletons
    logger.info("Starting Sentrix V8 Enterprise SOC/XDR Platform engines...")
    start_time = time.time()
    
    engines = EnginesState()
    
    # 1. Initialize Event Bus
    init_bus(settings.event_bus_db)
    
    # 2. Initialize Core Engines
    engines.threat = SentrixThreatEngine()
    engines.prediction = PredictionEngine()
    engines.investigation = InvestigationStudioEngine()

    from sentrix_core.suppression.suppression_engine import SuppressionEngine
    engines.suppression = SuppressionEngine()

    # 2b. Initialize Persistence + Correlation
    from sentrix_core.storage.event_store import get_event_store
    from sentrix_core.threat_engine.correlation.correlation_engine import get_correlation_engine
    engines.event_store = get_event_store()
    engines.correlation = get_correlation_engine()
    
    # 2c. Initialize Pub/Sub Event Bus Subscribers
    from sentrix_core.event_bus.subscribers import init_subscribers
    init_subscribers(engines)
    
    # 2d. Initialize SOAR
    from sentrix_core.response_engine.soar_engine import get_soar_engine
    engines.soar = get_soar_engine()
    
    # 3. Initialize Rule Studio
    engines.rule_studio = RuleStudio()
    engines.rule_tester = RuleTester()
    
    # Start hot reloader
    engines.reloader = RuleReloader(
        engines.threat, 
        [settings.rules_dir, settings.custom_rules_dir]
    )
    engines.reloader.start()
    
    # 4. Initialize Connectors
    engines.connector_registry = ConnectorRegistry()
    
    # Attach engines to app state for route handlers
    app.state.engines = engines
    app.state.start_time = start_time
    
    logger.info("Sentrix Core Platform successfully started.")
    yield
    
    # Shutdown gracefully
    logger.info("Shutting down Sentrix Core Platform...")
    engines.investigation.shutdown()
    engines.reloader.stop()
    logger.info("Shutdown complete.")

app = FastAPI(
    title="Sentrix Core Platform",
    version="7.0.0",
    description="Unified Sentrix Cybersecurity Platform",
    lifespan=lifespan
)

# Include all routers
app.include_router(threat_router, prefix="/api/v1/threat")
app.include_router(prediction_router, prefix="/api/v1/predictions")
app.include_router(investigation_router, prefix="/api/v1/investigations")
app.include_router(incident_router, prefix="/api/v1/incidents")
app.include_router(rule_router, prefix="/api/v1/rules")
app.include_router(connector_router, prefix="/api/v1/connectors")
app.include_router(admin_router, prefix="/api/v1/admin")
app.include_router(suppression_router, prefix="/api/v1/suppression")
app.include_router(dashboard_router, prefix="/api/v1/dashboard")
app.include_router(ws_router)

from sentrix_core.api.soar_routes import router as soar_router
app.include_router(soar_router, prefix="/api/v1/soar")

@app.get("/ready", tags=["Observability"])
def readiness_probe():
    return {"status": "ready", "version": "8.0.0"}

@app.get("/metrics", tags=["Observability"])
def metrics_probe():
    return {"status": "healthy", "engines_active": True}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.HOST, port=settings.PORT, reload=False)
