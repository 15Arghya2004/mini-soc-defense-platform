"""
prediction_service.py
──────────────────────
Stateful session manager for the Prediction Engine.

Maintains a per-source-IP AttackPath registry.
On each ingested alert:
  1. Updates or creates the AttackPath for the source IP
  2. Runs all three predictors (next_attack, compromise, escalation)
  3. Classifies the campaign type
  4. Persists the forecast to PredictionStore
  5. Returns the full composite forecast dict
"""
import logging
from datetime import datetime, timezone

from sentrix_core.prediction_engine.models.attack_path import AttackPath
from sentrix_core.prediction_engine.models.attack_graph import AttackGraph
from sentrix_core.prediction_engine.models.markov_chain import MarkovChain
from sentrix_core.prediction_engine.models.mitre_campaign_patterns import MitreCampaignClassifier
from sentrix_core.prediction_engine.predictors.next_attack_predictor import NextAttackPredictor
from sentrix_core.prediction_engine.predictors.compromise_predictor import CompromisePredictor
from sentrix_core.prediction_engine.predictors.escalation_predictor import EscalationPredictor
from sentrix_core.prediction_engine.services.timeline_builder import ForecastTimelineBuilder
from sentrix_core.prediction_engine.storage.prediction_store import PredictionStore

logger = logging.getLogger("sentrix.prediction.service")


class PredictionService:
    """
    Core stateful orchestration service for the Prediction Engine.

    Maintains:
      _paths : dict[source_ip → AttackPath]
    """

    def __init__(self, store: PredictionStore = None):
        self.graph      = AttackGraph()
        self.markov     = MarkovChain(self.graph)
        self.classifier = MitreCampaignClassifier()
        self.timeline   = ForecastTimelineBuilder(self.graph, self.markov)
        self.store      = store or PredictionStore()

        self.next_predictor       = NextAttackPredictor(self.graph, self.markov)
        self.compromise_predictor = CompromisePredictor(self.graph)
        self.escalation_predictor = EscalationPredictor(self.graph, self.markov)

        self._paths: dict = {}

    def ingest_alert(self, alert_contract: dict) -> dict:
        """
        Processes one AlertContract dict and returns a full forecast.

        Parameters
        ----------
        alert_contract : dict — normalized alert from AlertAdapter

        Returns
        -------
        dict — composite forecast including all predictions
        """
        source_ip = alert_contract.get("source_ip", "unknown")

        # Get or create AttackPath for this source IP
        if source_ip not in self._paths:
            self._paths[source_ip] = AttackPath(source_ip=source_ip)
            logger.info("[PredictionService] New attacker tracked: %s", source_ip)

        path = self._paths[source_ip]
        path.update(alert_contract)

        # Run all predictors
        next_attack  = self.next_predictor.predict(path)
        compromise   = self.compromise_predictor.predict(
            path,
            hostname=alert_contract.get("affected_host")
        )
        escalation   = self.escalation_predictor.predict(path)

        # Get profiles / campaign info if available
        profile = None
        campaign_info = None
        p_store = None
        c_tracker = None
        try:
            from profiles.profile_store import ProfileStore
            from campaign_memory.campaign_tracker import CampaignTracker
            p_store = ProfileStore()
            c_tracker = CampaignTracker()
            profile = p_store.get_profile(source_ip)
            campaign_info = c_tracker.get_active_campaign(source_ip)
        except ImportError:
            pass

        # Adjust next_attack predictor based on attacker profile
        if profile:
            # If historical highest risk is high, increase forecast confidence
            if profile.highest_risk >= 80:
                next_attack["confidence"] = min(99, next_attack["confidence"] + 10)
            # If alert count is high, increase transition probability
            if profile.total_alerts > 10:
                next_attack["probability"] = min(100, next_attack["probability"] + 5)

        # If campaign_info exists, verify the prediction aligns or use the history
        if campaign_info:
            # Optionally leverage campaign historical stages count to adjust escalation
            pass

        campaign     = self.classifier.classify(path.get_unique_stages())
        timeline     = self.timeline.build(
            current_stage=path.get_latest_stage(),
            steps=5
        )

        # Update Campaign Memory with the forecast prediction
        if c_tracker and campaign_info:
            c_tracker.update_prediction(source_ip, next_attack["next_attack"])

        # Update Attacker Profile and Context prediction counts
        if p_store and profile:
            if next_attack["next_attack"] not in profile.predictions:
                profile.predictions.append(next_attack["next_attack"])
            p_store.save_profile(profile)
            try:
                from context.context_manager import ContextManager
                cm = ContextManager()
                cm.increment_prediction_count(source_ip)
            except ImportError:
                pass

        # Composite forecast
        forecast = {
            "source_ip":         source_ip,
            "alert_count":       path.alert_count,
            "current_stage":     path.get_latest_stage(),
            "unique_stages":     path.get_unique_stages(),
            "next_attack":       next_attack["next_attack"],
            "technique":         next_attack["technique"],
            "technique_name":    next_attack["technique_name"],
            "probability":       next_attack["probability"],
            "confidence":        next_attack["confidence"],
            "top_alternatives":  next_attack["top_alternatives"],
            "compromise":        compromise,
            "risk_level":        compromise["risk"],
            "escalation":        escalation,
            "campaign":          campaign,
            "forecast_timeline": timeline,
            "generated_at":      datetime.now(timezone.utc).isoformat(),
        }

        # Persist
        self.store.save(forecast)

        logger.info(
            "[PredictionService] %s → next=%s prob=%d conf=%d risk=%s campaign=%s",
            source_ip,
            forecast["next_attack"],
            forecast["probability"],
            forecast["confidence"],
            forecast["risk_level"],
            campaign.get("likely_campaign"),
        )
        return forecast

    def get_live_paths(self) -> list:
        """Returns all currently tracked AttackPath state dicts."""
        return [p.to_dict() for p in self._paths.values()]

    def get_tracked_attacker_count(self) -> int:
        """Returns the number of unique source IPs being tracked."""
        return len(self._paths)

    def get_path(self, source_ip: str) -> dict:
        """Returns the AttackPath dict for a specific source IP, or None."""
        p = self._paths.get(source_ip)
        return p.to_dict() if p else None

    def reset(self):
        """Clears all tracked paths (for testing)."""
        self._paths.clear()
