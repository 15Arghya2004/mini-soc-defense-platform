"""
compromise_predictor.py
────────────────────────
Calculates host compromise probability for an attacker's target.

Formula:
  stage_score  = max_depth_reached / 14 × 50       (kill-chain depth, 0–50)
  alert_score  = min(20, alert_count × 2)           (volume, 0–20)
  severity_score = avg_risk_score / 100 × 20        (risk intensity, 0–20)
  recency_bonus  = 10 if last event < 10 min ago    (active threat bonus)

  raw_probability = stage_score + alert_score + severity_score + recency_bonus
  probability     = int(min(99, max(1, raw_probability)))

Risk thresholds:
  CRITICAL : ≥ 80
  HIGH     : 60–79
  MEDIUM   : 30–59
  LOW      :  < 30
"""
import logging
from datetime import datetime, timezone
from sentrix_core.prediction_engine.models.attack_path import AttackPath
from sentrix_core.prediction_engine.models.attack_graph import AttackGraph, STAGE_DEPTH

logger = logging.getLogger("sentrix.prediction.compromise")

_RISK_THRESHOLDS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (30, "MEDIUM"),
    (0,  "LOW"),
]

_MAX_DEPTH         = 14
_ACTIVE_THRESHOLD  = 600   # 10 minutes in seconds


class CompromisePredictor:
    """
    Predicts the probability that a target host has been or will be compromised.
    """

    def __init__(self, graph: AttackGraph = None):
        self.graph = graph or AttackGraph()

    def predict(self, path: AttackPath, hostname: str = None) -> dict:
        """
        Returns compromise probability and risk level for the most-targeted host.

        Parameters
        ----------
        path     : AttackPath — tracked attacker path
        hostname : str        — specific target hostname (optional; uses path.affected_hosts[0])

        Output dict:
          host                  : str  — target hostname
          compromise_probability: int  — 0–99
          risk                  : str  — LOW / MEDIUM / HIGH / CRITICAL
          factors               : dict — score breakdown for explainability
        """
        host = hostname or (path.affected_hosts[0] if path.affected_hosts else "unknown")

        stage_score    = self._stage_score(path)
        alert_score    = self._alert_score(path.alert_count)
        severity_score = self._severity_score(path.get_average_risk_score())
        recency_bonus  = self._recency_bonus(path.last_seen)

        raw         = stage_score + alert_score + severity_score + recency_bonus
        probability = int(min(99, max(1, round(raw))))
        risk        = self._to_risk_level(probability)

        factors = {
            "stage_depth_score":  round(stage_score, 1),
            "alert_volume_score": round(alert_score, 1),
            "severity_score":     round(severity_score, 1),
            "recency_bonus":      round(recency_bonus, 1),
        }

        logger.debug(
            "[CompromisePredictor] host=%s prob=%d risk=%s factors=%s",
            host, probability, risk, factors
        )

        return {
            "host":                   host,
            "compromise_probability": probability,
            "risk":                   risk,
            "factors":                factors,
            "stages_observed":        path.get_unique_stages(),
            "alert_count":            path.alert_count,
        }

    def _stage_score(self, path: AttackPath) -> float:
        """Maps the deepest reached kill-chain stage to 0–50."""
        unique_stages = path.get_unique_stages()
        max_depth = max(
            (STAGE_DEPTH.get(s, 1) for s in unique_stages),
            default=1
        )
        return (max_depth / _MAX_DEPTH) * 50.0

    def _alert_score(self, alert_count: int) -> float:
        """Maps alert volume to 0–20 (capped at 10 alerts)."""
        return min(20.0, alert_count * 2.0)

    def _severity_score(self, avg_risk: float) -> float:
        """Maps average risk score (0–100) to 0–20."""
        return (avg_risk / 100.0) * 20.0

    def _recency_bonus(self, last_seen: datetime) -> float:
        """+10 if last event occurred within the last 10 minutes."""
        if not last_seen:
            return 0.0
        now = datetime.now(timezone.utc)
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        elapsed = (now - last_seen).total_seconds()
        return 10.0 if elapsed <= _ACTIVE_THRESHOLD else 0.0

    @staticmethod
    def _to_risk_level(probability: int) -> str:
        for threshold, label in _RISK_THRESHOLDS:
            if probability >= threshold:
                return label
        return "LOW"
