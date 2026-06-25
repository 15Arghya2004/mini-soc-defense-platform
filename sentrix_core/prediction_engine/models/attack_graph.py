"""
attack_graph.py
───────────────
Static MITRE ATT&CK 14-stage directed transition graph.
Embeds stage adjacency with base weights and technique-to-stage mappings.
No external API calls — all data is embedded.
"""
import os
import json
import logging

logger = logging.getLogger("sentrix.prediction.attack_graph")

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_TECHNIQUE_MAP_PATH = os.path.join(_DATA_DIR, "mitre_technique_map.json")
_TRANSITIONS_PATH   = os.path.join(_DATA_DIR, "markov_transitions.json")

# All 14 MITRE ATT&CK tactics in kill-chain order
ALL_STAGES = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command & Control",
    "Exfiltration",
    "Impact",
]

STAGE_DEPTH = {stage: idx + 1 for idx, stage in enumerate(ALL_STAGES)}


class AttackGraph:
    """
    Directed MITRE ATT&CK stage transition graph.

    Provides:
      - Technique ID → Stage lookup
      - Stage → possible next stages with base weights
      - Stage depth (kill-chain progress index 1-14)
    """

    def __init__(self):
        self.technique_map = self._load_technique_map()
        self.transitions   = self._load_transitions()
        self.all_stages    = ALL_STAGES
        self.stage_depth   = STAGE_DEPTH

    def _load_technique_map(self) -> dict:
        try:
            with open(_TECHNIQUE_MAP_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Could not load technique map: %s. Using empty map.", e)
            return {}

    def _load_transitions(self) -> dict:
        try:
            with open(_TRANSITIONS_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Could not load transitions: %s. Using empty map.", e)
            return {}

    def get_technique_stage(self, technique_id: str) -> str:
        """
        Returns the MITRE tactic stage for a given technique ID.
        Example: 'T1046' -> 'Discovery'
        """
        entry = self.technique_map.get(technique_id)
        if entry:
            return entry.get("stage", "Discovery")
        return "Discovery"  # Default fallback

    def get_technique_name(self, technique_id: str) -> str:
        """Returns the human-readable technique name for a given technique ID."""
        entry = self.technique_map.get(technique_id)
        if entry:
            return entry.get("name", technique_id)
        return technique_id

    def get_next_stages(self, current_stage: str) -> dict:
        """
        Returns {next_stage: base_weight} dict for a given current stage.
        Returns empty dict if stage is terminal or unknown.
        """
        return self.transitions.get(current_stage, {})

    def get_stage_depth(self, stage: str) -> int:
        """Returns kill-chain depth (1=Reconnaissance, 14=Impact)."""
        return self.stage_depth.get(stage, 1)

    def get_representative_technique(self, stage: str) -> str:
        """
        Returns a representative technique ID for a given stage.
        Used for constructing prediction outputs.
        """
        stage_to_technique = {
            "Reconnaissance":       "T1046",
            "Resource Development": "T1587",
            "Initial Access":       "T1566",
            "Execution":            "T1059",
            "Persistence":          "T1547",
            "Privilege Escalation": "T1068",
            "Defense Evasion":      "T1055",
            "Credential Access":    "T1110",
            "Discovery":            "T1082",
            "Lateral Movement":     "T1021",
            "Collection":           "T1074",
            "Command & Control":    "T1071",
            "Exfiltration":         "T1041",
            "Impact":               "T1486",
        }
        return stage_to_technique.get(stage, "T1082")

    def is_valid_stage(self, stage: str) -> bool:
        """Returns True if the given stage is a recognized MITRE tactic."""
        return stage in self.all_stages

    def get_all_stages_by_depth(self) -> list:
        """Returns all stages ordered by kill-chain depth."""
        return list(self.all_stages)
