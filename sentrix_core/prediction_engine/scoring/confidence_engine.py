"""
confidence_engine.py
────────────────────
Computes forecast confidence (0–100) — the degree of certainty in the prediction.

Confidence is separate from probability:
  Probability = "How likely is the next stage to happen?"
  Confidence  = "How certain are we that this prediction is correct?"

Formula:
  base_confidence     = 50 (always present)
  observation_factor  = min(30, observation_count × 3)  — more data = more confident
  path_uniqueness     = 10 if stages are on a common APT path (Recon→IA→Exec→...)
  recency_factor      = -20 if last event was > 1 hour ago (stale path)
  depth_factor        = 10 if current_stage depth ≥ 6 (deep engagement = more predictable)

  raw        = base + observation_factor + path_uniqueness + recency_factor + depth_factor
  confidence = int(min(99, max(5, raw)))
"""
import logging
from datetime import datetime, timezone, timedelta
from sentrix_core.prediction_engine.models.attack_graph import AttackGraph

logger = logging.getLogger("sentrix.prediction.confidence")

# Stages considered to be on the high-frequency APT paths
_COMMON_STAGES = {
    "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Credential Access", "Lateral Movement",
    "Collection", "Exfiltration",
}

_STALE_THRESHOLD_SECONDS = 3600   # 1 hour


class ConfidenceEngine:
    """
    Computes how confident we are in a given prediction.
    """

    def __init__(self, graph: AttackGraph = None):
        self.graph = graph or AttackGraph()

    def calculate(
        self,
        current_stage: str,
        observation_count: int,
        last_seen: datetime = None,
        stages_observed: list = None,
    ) -> int:
        """
        Returns a confidence score (0–99).

        Parameters
        ----------
        current_stage     : str      — Last observed MITRE stage
        observation_count : int      — Total number of alerts for this attacker
        last_seen         : datetime — Timestamp of most recent alert
        stages_observed   : list     — All stages in the attack path
        """
        base               = 50
        observation_factor = self._observation_factor(observation_count)
        path_uniqueness    = self._path_uniqueness(current_stage, stages_observed or [])
        recency_factor     = self._recency_factor(last_seen)
        depth_factor       = self._depth_factor(current_stage)

        raw        = base + observation_factor + path_uniqueness + recency_factor + depth_factor
        confidence = int(min(99, max(5, round(raw))))

        logger.debug(
            "[ConfidenceEngine] stage=%s obs=%d → obs_f=%.1f path_f=%.1f rec_f=%.1f depth_f=%.1f total=%d",
            current_stage, observation_count,
            observation_factor, path_uniqueness, recency_factor, depth_factor, confidence
        )
        return confidence

    def _observation_factor(self, count: int) -> float:
        """Returns 0–30 based on how many alerts have been seen."""
        return min(30.0, count * 3.0)

    def _path_uniqueness(self, current_stage: str, stages_observed: list) -> float:
        """
        +10 if the current stage is on a common, well-documented APT path.
        +5 if at least 2 previous stages are common stages.
        """
        if current_stage in _COMMON_STAGES:
            common_count = sum(1 for s in stages_observed if s in _COMMON_STAGES)
            if common_count >= 2:
                return 10.0
            return 5.0
        return 0.0

    def _recency_factor(self, last_seen: datetime) -> float:
        """
        -20 if the last event was more than 1 hour ago (stale attack path).
        0 if last_seen is recent or unknown.
        """
        if not last_seen:
            return 0.0
        now = datetime.now(timezone.utc)
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        elapsed = (now - last_seen).total_seconds()
        if elapsed > _STALE_THRESHOLD_SECONDS:
            return -20.0
        return 0.0

    def _depth_factor(self, stage: str) -> float:
        """
        +10 if stage depth >= 6 (deep kill-chain stages are more predictable).
        +5 if depth is 3-5.
        0 otherwise.
        """
        depth = self.graph.get_stage_depth(stage)
        if depth >= 6:
            return 10.0
        if depth >= 3:
            return 5.0
        return 0.0
