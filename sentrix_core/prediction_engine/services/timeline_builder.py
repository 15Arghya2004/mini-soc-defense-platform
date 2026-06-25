"""
timeline_builder.py
────────────────────
Constructs the PREDICTED future attack timeline — a forward-looking sequence
of expected MITRE ATT&CK stages with probabilities at each step.

This is distinct from the historical timeline in threat-engine/storytelling/:
  - storytelling/timeline_builder.py  : "What happened" (past events)
  - prediction-engine/timeline_builder: "What will happen next" (future forecast)

Output format (list of steps):
  [
    {"step": 1, "stage": "Lateral Movement", "technique": "T1021",
     "technique_name": "Remote Services", "probability": 72, "cumulative_probability": 72.0},
    {"step": 2, "stage": "Collection", "technique": "T1074",
     "technique_name": "Data Staged", "probability": 58, "cumulative_probability": 41.8},
    ...
  ]
"""
import logging
from sentrix_core.prediction_engine.models.attack_graph import AttackGraph
from sentrix_core.prediction_engine.models.markov_chain import MarkovChain

logger = logging.getLogger("sentrix.prediction.timeline")


class ForecastTimelineBuilder:
    """
    Generates a multi-step forward attack progression timeline.
    Uses the Markov Chain to walk the most probable sequence of stages.
    """

    def __init__(self, graph: AttackGraph = None, markov: MarkovChain = None):
        self.graph  = graph  or AttackGraph()
        self.markov = markov or MarkovChain(self.graph)

    def build(self, current_stage: str, steps: int = 5) -> list:
        """
        Generates up to `steps` forecasted future stages from `current_stage`.

        Parameters
        ----------
        current_stage : str — The last observed MITRE stage (starting point)
        steps         : int — Number of future steps to forecast

        Returns
        -------
        list of step dicts with stage, technique, probability, cumulative_probability
        """
        raw_steps  = self.markov.multi_step_forecast(current_stage, steps=steps)
        enriched   = []

        for step_dict in raw_steps:
            stage     = step_dict["stage"]
            technique = self.graph.get_representative_technique(stage)
            enriched.append({
                "step":                   step_dict["step"],
                "stage":                  stage,
                "technique":              technique,
                "technique_name":         self.graph.get_technique_name(technique),
                "probability":            step_dict["probability"],
                "cumulative_probability": step_dict["cumulative_probability"],
            })

        if not enriched:
            logger.debug("[ForecastTimeline] No forecast steps available from stage=%s", current_stage)

        return enriched

    def build_narrative(self, current_stage: str, steps: int = 5) -> str:
        """
        Returns a human-readable text narrative of the predicted attack timeline.
        """
        steps_list = self.build(current_stage, steps)
        if not steps_list:
            return f"No forecast available from stage: {current_stage}"

        lines = [f"Predicted attack progression from '{current_stage}':"]
        lines.append(f"  [Observed] {current_stage}")
        for step in steps_list:
            lines.append(
                f"  → [{step['step']}] {step['stage']} ({step['technique']}: "
                f"{step['technique_name']}) — {step['probability']}% probability"
            )
        return "\n".join(lines)
