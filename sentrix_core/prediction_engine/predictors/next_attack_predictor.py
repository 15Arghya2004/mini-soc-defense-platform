"""
next_attack_predictor.py
─────────────────────────
Forecasts the most likely next MITRE ATT&CK stage for an active attacker.

Input  : AttackPath (observed stage history for a source IP)
Output : {next_attack, technique, technique_name, probability, confidence}

Uses:
  - MarkovChain for transition probability
  - ProbabilityEngine for composite probability score
  - ConfidenceEngine for forecast confidence
  - AttackGraph for technique ID lookup
"""
import logging
from sentrix_core.prediction_engine.models.attack_graph import AttackGraph
from sentrix_core.prediction_engine.models.markov_chain import MarkovChain
from sentrix_core.prediction_engine.models.attack_path import AttackPath
from sentrix_core.prediction_engine.scoring.probability_engine import ProbabilityEngine
from sentrix_core.prediction_engine.scoring.confidence_engine import ConfidenceEngine

logger = logging.getLogger("sentrix.prediction.next_attack")


class NextAttackPredictor:
    """
    Predicts the most likely next MITRE stage from the current attack path.
    """

    def __init__(
        self,
        graph: AttackGraph = None,
        markov: MarkovChain = None,
        prob_engine: ProbabilityEngine = None,
        conf_engine: ConfidenceEngine = None,
    ):
        self.graph       = graph       or AttackGraph()
        self.markov      = markov      or MarkovChain(self.graph)
        self.prob_engine = prob_engine or ProbabilityEngine(self.graph)
        self.conf_engine = conf_engine or ConfidenceEngine(self.graph)

    def predict(self, path: AttackPath) -> dict:
        """
        Returns the next attack forecast for the given AttackPath.

        Output dict:
          next_attack      : str  — Predicted next MITRE stage name
          technique        : str  — Representative technique ID (e.g. 'T1021')
          technique_name   : str  — Human-readable technique name
          probability      : int  — 0-100 composite probability
          confidence       : int  — 0-99 forecast confidence
          top_alternatives : list — Top 3 next stages with raw probabilities
        """
        current_stage = path.get_latest_stage()

        # Get top-3 Markov transitions
        top_stages = self.markov.get_top_next_stages(current_stage, n=3)

        if not top_stages or top_stages[0][1] == 0.0:
            return self._no_prediction(current_stage, path)

        best_stage, best_markov_prob = top_stages[0]

        # Calculate composite probability
        probability = self.prob_engine.calculate(
            markov_prob=best_markov_prob,
            current_stage=current_stage,
            observation_count=path.alert_count,
        )

        # Calculate forecast confidence
        confidence = self.conf_engine.calculate(
            current_stage=current_stage,
            observation_count=path.alert_count,
            last_seen=path.last_seen,
            stages_observed=path.stages_observed,
        )

        # Resolve technique
        technique      = self.graph.get_representative_technique(best_stage)
        technique_name = self.graph.get_technique_name(technique)

        # Format alternatives
        alternatives = [
            {
                "stage":       stage,
                "raw_prob":    round(prob * 100),
                "technique":   self.graph.get_representative_technique(stage),
            }
            for stage, prob in top_stages[1:]  # skip the best, already used above
        ]

        return {
            "current_stage":    current_stage,
            "next_attack":      best_stage,
            "technique":        technique,
            "technique_name":   technique_name,
            "probability":      probability,
            "confidence":       confidence,
            "top_alternatives": alternatives,
        }

    def _no_prediction(self, current_stage: str, path: AttackPath) -> dict:
        """Returns a safe empty-result when no transition is available."""
        logger.debug("[NextAttackPredictor] No transitions available from stage=%s", current_stage)
        return {
            "current_stage":    current_stage,
            "next_attack":      "Unknown",
            "technique":        "N/A",
            "technique_name":   "No prediction available",
            "probability":      0,
            "confidence":       0,
            "top_alternatives": [],
        }
