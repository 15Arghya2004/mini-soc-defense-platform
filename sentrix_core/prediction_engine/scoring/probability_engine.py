"""
probability_engine.py
─────────────────────
Computes the composite next-stage probability score (0–100).

Formula:
  markov_component   = markov_transition_probability × 60    (primary signal)
  depth_bonus        = stage_depth_factor × 25              (deeper stages = more certain path)
  frequency_bonus    = observation_count_factor × 15        (more observations = more confident)

  raw   = markov_component + depth_bonus + frequency_bonus
  score = int(min(100, max(0, raw)))
"""
import logging
from sentrix_core.prediction_engine.models.attack_graph import AttackGraph, STAGE_DEPTH

logger = logging.getLogger("sentrix.prediction.probability")

_MAX_MARKOV   = 60.0
_MAX_DEPTH    = 25.0
_MAX_FREQ     = 15.0
_DEPTH_STAGES = len(STAGE_DEPTH)   # 14


class ProbabilityEngine:
    """
    Computes the composite probability that a predicted next stage will actually occur.

    Inputs
    ------
    markov_prob      : float (0.0–1.0) — transition probability from Markov Chain
    current_stage    : str             — current MITRE tactic stage
    observation_count: int             — number of alerts seen for this attacker
    """

    def __init__(self, graph: AttackGraph = None):
        self.graph = graph or AttackGraph()

    def calculate(
        self,
        markov_prob: float,
        current_stage: str,
        observation_count: int = 1,
    ) -> int:
        """
        Returns a composite probability score (0–100).
        """
        markov_component = self._markov_component(markov_prob)
        depth_bonus      = self._depth_bonus(current_stage)
        freq_bonus       = self._frequency_bonus(observation_count)

        raw   = markov_component + depth_bonus + freq_bonus
        score = int(min(100, max(0, round(raw))))

        logger.debug(
            "[ProbabilityEngine] stage=%s markov=%.2f → component=%.1f depth=%.1f freq=%.1f total=%d",
            current_stage, markov_prob, markov_component, depth_bonus, freq_bonus, score
        )
        return score

    def _markov_component(self, prob: float) -> float:
        """Maps Markov probability [0,1] to [0, 60]."""
        return min(_MAX_MARKOV, prob * _MAX_MARKOV)

    def _depth_bonus(self, stage: str) -> float:
        """
        Stages deeper in the kill-chain are more certain to progress forward.
        Stage depth 1 (Recon) = 0 bonus. Stage depth 14 (Impact) = 25 bonus.
        """
        depth = self.graph.get_stage_depth(stage)
        return round(((depth - 1) / (_DEPTH_STAGES - 1)) * _MAX_DEPTH, 2)

    def _frequency_bonus(self, observation_count: int) -> float:
        """
        More observed events = higher probability score (capped at 15).
        1 event = 0 bonus. 10+ events = full 15 bonus.
        """
        count = min(observation_count, 10)
        return round(((count - 1) / 9) * _MAX_FREQ, 2) if count > 1 else 0.0
