"""
escalation_predictor.py
────────────────────────
Forecasts whether the current risk tier will escalate, and estimates
how many more attacker events it will take to reach the next tier.

Risk Tiers (matching Threat Engine severity bands):
  informational : risk 0–25
  low           : risk 26–45
  medium        : risk 46–65
  high          : risk 66–85
  critical      : risk 86–100

Escalation logic:
  - Current tier is derived from the attacker's current max_risk_score
  - Escalation probability = f(Markov stage depth progression, alert velocity)
  - Events until escalation = estimated based on stage transition speed
  - Confidence uses the standard ConfidenceEngine output
"""
import logging
from sentrix_core.prediction_engine.models.attack_path import AttackPath
from sentrix_core.prediction_engine.models.markov_chain import MarkovChain
from sentrix_core.prediction_engine.models.attack_graph import AttackGraph, STAGE_DEPTH
from sentrix_core.prediction_engine.scoring.confidence_engine import ConfidenceEngine

logger = logging.getLogger("sentrix.prediction.escalation")

# Risk tier bands (upper bound → tier name)
_RISK_TIERS = [
    (86, "critical"),
    (66, "high"),
    (46, "medium"),
    (26, "low"),
    (0,  "informational"),
]

# Tier escalation map
_NEXT_TIER = {
    "informational": "low",
    "low":           "medium",
    "medium":        "high",
    "high":          "critical",
    "critical":      "critical",  # already at max
}


class EscalationPredictor:
    """
    Forecasts risk tier escalation from the attacker's current state.
    """

    def __init__(
        self,
        graph: AttackGraph = None,
        markov: MarkovChain = None,
        conf_engine: ConfidenceEngine = None,
    ):
        self.graph       = graph       or AttackGraph()
        self.markov      = markov      or MarkovChain(self.graph)
        self.conf_engine = conf_engine or ConfidenceEngine(self.graph)

    def predict(self, path: AttackPath) -> dict:
        """
        Returns escalation forecast for the given attack path.

        Output dict:
          current                  : str — current risk tier
          forecast                 : str — predicted next risk tier
          events_until_escalation  : int — estimated events before escalation
          escalation_probability   : int — 0–100
          confidence               : int — 0–99
          will_escalate            : bool
        """
        current_risk  = path.get_max_risk_score()
        current_tier  = self._risk_to_tier(current_risk)
        forecast_tier = _NEXT_TIER.get(current_tier, current_tier)
        will_escalate = (forecast_tier != current_tier)

        escalation_prob   = self._escalation_probability(path)
        events_until      = self._events_until_escalation(path)
        confidence        = self.conf_engine.calculate(
            current_stage=path.get_latest_stage(),
            observation_count=path.alert_count,
            last_seen=path.last_seen,
            stages_observed=path.stages_observed,
        )

        logger.debug(
            "[EscalationPredictor] current=%s forecast=%s events_until=%d prob=%d conf=%d",
            current_tier, forecast_tier, events_until, escalation_prob, confidence
        )

        return {
            "current":                 current_tier,
            "current_risk_score":      current_risk,
            "forecast":                forecast_tier,
            "events_until_escalation": events_until,
            "escalation_probability":  escalation_prob,
            "confidence":              confidence,
            "will_escalate":           will_escalate,
        }

    def _risk_to_tier(self, score: int) -> str:
        """Maps a numeric risk score to its tier name."""
        for threshold, name in _RISK_TIERS:
            if score >= threshold:
                return name
        return "informational"

    def _escalation_probability(self, path: AttackPath) -> int:
        """
        Estimates escalation probability (0–100) based on:
          - Current stage depth (deeper = more likely to escalate)
          - Alert velocity (more alerts = escalating threat)
          - Markov forward momentum (high transition prob = escalating)
        """
        current_stage = path.get_latest_stage()
        depth         = self.graph.get_stage_depth(current_stage)
        depth_factor  = (depth / 14) * 40          # 0–40

        alert_factor  = min(30, path.alert_count * 3)  # 0–30

        # Forward momentum: probability of the next stage being deeper
        top_next = self.markov.get_top_next_stages(current_stage, n=1)
        if top_next:
            next_stage, next_prob = top_next[0]
            next_depth   = self.graph.get_stage_depth(next_stage)
            momentum     = next_prob * 30 if next_depth > depth else next_prob * 10
        else:
            momentum = 0.0

        raw  = depth_factor + alert_factor + momentum
        prob = int(min(100, max(0, round(raw))))
        return prob

    def _events_until_escalation(self, path: AttackPath) -> int:
        """
        Estimates how many more events (alerts) before risk tier escalates.
        Uses stage depth proximity to next tier boundary.
        """
        current_risk = path.get_max_risk_score()
        current_tier = self._risk_to_tier(current_risk)

        # Distance to the next tier threshold
        tier_bounds = {
            "informational": 26,
            "low":           46,
            "medium":        66,
            "high":          86,
            "critical":      100,
        }
        next_bound = tier_bounds.get(current_tier, 100)
        gap        = max(0, next_bound - current_risk)

        # Estimate events needed: each event adds ~avg_risk_increment
        avg_risk = path.get_average_risk_score()
        if avg_risk > 0 and gap > 0:
            events_estimate = max(1, round(gap / max(1, avg_risk * 0.2)))
        else:
            events_estimate = 3  # Default estimate

        return min(events_estimate, 10)  # Cap at 10 events
