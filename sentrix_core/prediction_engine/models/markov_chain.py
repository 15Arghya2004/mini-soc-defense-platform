"""
markov_chain.py
───────────────
Markov Chain transition probability model for MITRE ATT&CK stage transitions.
Pre-seeded from embedded historical attack chain frequency data.
No external training required — deterministic and explainable.
"""
import os
import json
import logging
from sentrix_core.prediction_engine.models.attack_graph import AttackGraph

logger = logging.getLogger("sentrix.prediction.markov")

_DATA_DIR         = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_TRANSITIONS_PATH = os.path.join(_DATA_DIR, "markov_transitions.json")


class MarkovChain:
    """
    Stage transition probability matrix.

    P(next_stage | current_stage) — derived from pre-seeded APT campaign data.
    Probabilities are normalized per source state to sum to 1.0.
    """

    def __init__(self, graph: AttackGraph = None):
        self.graph = graph or AttackGraph()
        self.raw_transitions = self._load_transitions()
        self.matrix = self._normalize(self.raw_transitions)

    def _load_transitions(self) -> dict:
        try:
            with open(_TRANSITIONS_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Markov transitions file not found: %s. Using empty matrix.", e)
            return {}

    def _normalize(self, raw: dict) -> dict:
        """
        Normalizes each row so transition probabilities sum to 1.0.
        Handles zero-sum rows gracefully.
        """
        normalized = {}
        for from_stage, targets in raw.items():
            total = sum(targets.values())
            if total > 0:
                normalized[from_stage] = {k: v / total for k, v in targets.items()}
            else:
                normalized[from_stage] = {}
        return normalized

    def get_transition_probability(self, from_stage: str, to_stage: str) -> float:
        """
        Returns P(to_stage | from_stage) as a float in [0.0, 1.0].
        Returns 0.0 if the transition is unknown.
        """
        row = self.matrix.get(from_stage, {})
        return row.get(to_stage, 0.0)

    def get_top_next_stages(self, current_stage: str, n: int = 3) -> list:
        """
        Returns the top-n most probable next stages from current_stage.
        Returns: list of (stage, probability_float) tuples, sorted descending.
        """
        row = self.matrix.get(current_stage, {})
        if not row:
            # Fallback: use graph adjacency with uniform distribution
            adjacents = self.graph.get_next_stages(current_stage)
            if adjacents:
                count = len(adjacents)
                row = {s: 1.0 / count for s in adjacents}
        sorted_stages = sorted(row.items(), key=lambda x: x[1], reverse=True)
        return sorted_stages[:n]

    def get_most_probable_next(self, current_stage: str) -> tuple:
        """
        Returns (next_stage, probability) for the single most likely transition.
        Returns ('Unknown', 0.0) if no transitions available.
        """
        top = self.get_top_next_stages(current_stage, n=1)
        if top:
            return top[0]
        return ("Unknown", 0.0)

    def multi_step_forecast(self, start_stage: str, steps: int = 5) -> list:
        """
        Generates a probabilistic multi-step forecast from start_stage.
        Returns: list of {step, stage, probability, cumulative_probability}
        """
        forecast = []
        current = start_stage
        cumulative_prob = 1.0

        for step in range(1, steps + 1):
            next_stage, prob = self.get_most_probable_next(current)
            if next_stage == "Unknown" or prob == 0.0:
                break
            cumulative_prob *= prob
            forecast.append({
                "step":                 step,
                "stage":               next_stage,
                "probability":         round(prob * 100),
                "cumulative_probability": round(cumulative_prob * 100, 1),
            })
            current = next_stage
            # Stop at terminal stages
            if next_stage in ("Impact", "Exfiltration") and step > 2:
                break

        return forecast
