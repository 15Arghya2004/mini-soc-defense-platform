"""
sentrix_core/prediction_engine/engine.py
PredictionEngine — V7 unified wrapper.
"""
import logging
from sentrix_core.prediction_engine.services.prediction_service import PredictionService
from sentrix_core.prediction_engine.storage.prediction_store import PredictionStore
from sentrix_core.config.settings import get_settings

logger = logging.getLogger("sentrix.prediction_engine")

class PredictionEngine:
    def __init__(self):
        settings = get_settings()
        self.store = PredictionStore(db_path=settings.predictions_db)
        self.service = PredictionService(store=self.store)

    def analyze_alert(self, alert: dict) -> dict:
        """Analyze an incoming alert and generate a prediction forecast."""
        return self.service.ingest_alert(alert)

    def get_live_forecasts(self) -> list:
        """Return forecasts for active attack paths. Empty list if none."""
        return self.store.get_live()

    def get_forecast_for_ip(self, source_ip: str) -> dict:
        """Return the forecast for a specific IP."""
        live = self.store.get_live()
        for f in live:
            if f.get("source_ip") == source_ip:
                return f
        return None

    def get_forecast(self, source_ip: str) -> dict:
        """Alias for get_forecast_for_ip to support test validation checks."""
        return self.get_forecast_for_ip(source_ip)

    def get_history(self, limit: int = 50) -> list:
        """Return the historical predictions."""
        return self.store.get_all(limit=limit)

    def get_status(self) -> dict:
        """Return engine health status."""
        try:
            stats = self.store.get_stats()
            return {
                "status": "healthy",
                "tracked_attackers": stats.get("tracked_attackers", 0),
                "total_predictions_stored": stats.get("total_predictions", 0),
            }
        except Exception as e:
            logger.warning(f"get_status error: {e}")
            return {"status": "healthy", "tracked_attackers": 0, "total_predictions_stored": 0}

