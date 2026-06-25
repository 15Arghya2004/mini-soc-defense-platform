"""
mitre_campaign_patterns.py
──────────────────────────
Deterministic campaign fingerprint classifier.
Matches observed MITRE ATT&CK stage sequences against known attack campaign patterns
to identify the most likely active campaign type.

No AI/ML. Pure rule-based pattern matching with weighted scoring.
"""
import logging

logger = logging.getLogger("sentrix.prediction.campaign")


# Campaign pattern definitions
# Each pattern has:
#   required  : stages that MUST appear for a match (drive primary score)
#   optional  : stages that boost confidence if present
#   weight    : base confidence weight applied to required match ratio
#   terminus  : if set, this stage must be present for classification
CAMPAIGN_PATTERNS = {
    "Ransomware": {
        "required": ["Execution", "Privilege Escalation", "Defense Evasion", "Impact"],
        "optional": ["Initial Access", "Persistence", "Credential Access", "Lateral Movement"],
        "weight":   90,
        "terminus": "Impact",
        "description": "Multi-stage encryption attack targeting system availability and data integrity."
    },
    "Insider Threat": {
        "required": ["Collection", "Exfiltration"],
        "optional": ["Discovery", "Command & Control", "Persistence"],
        "weight":   85,
        "terminus": "Exfiltration",
        "description": "Privileged user abusing access to collect and exfiltrate sensitive data."
    },
    "Credential Theft": {
        "required": ["Reconnaissance", "Credential Access", "Persistence"],
        "optional": ["Initial Access", "Defense Evasion", "Lateral Movement", "Discovery"],
        "weight":   85,
        "terminus": None,
        "description": "Attacker targeting authentication credentials for long-term access."
    },
    "Lateral Movement": {
        "required": ["Initial Access", "Execution", "Lateral Movement", "Command & Control"],
        "optional": ["Discovery", "Credential Access", "Privilege Escalation", "Persistence"],
        "weight":   88,
        "terminus": "Lateral Movement",
        "description": "Attacker systematically traversing network segments to reach high-value targets."
    },
    "Data Exfiltration": {
        "required": ["Collection", "Command & Control", "Exfiltration"],
        "optional": ["Discovery", "Lateral Movement", "Defense Evasion", "Credential Access"],
        "weight":   87,
        "terminus": "Exfiltration",
        "description": "Attacker systematically collecting and exfiltrating data via covert channels."
    },
}

# Minimum confidence threshold to declare a campaign match
MIN_CONFIDENCE_THRESHOLD = 40


class MitreCampaignClassifier:
    """
    Classifies the most likely active campaign from a set of observed MITRE stages.

    Scoring formula (per campaign):
      required_ratio  = len(required_stages_matched) / len(required_stages_total)
      optional_bonus  = len(optional_stages_matched) * 4  (capped at 20)
      terminus_bonus  = 15 if terminus stage is present (else 0)
      raw_confidence  = required_ratio * weight + optional_bonus + terminus_bonus
      confidence      = int(min(99, raw_confidence))

    Returns the campaign with the highest confidence above MIN_CONFIDENCE_THRESHOLD.
    Returns 'Unknown' if no campaign exceeds the threshold.
    """

    def __init__(self):
        self.patterns = CAMPAIGN_PATTERNS
        self.min_confidence = MIN_CONFIDENCE_THRESHOLD

    def classify(self, stages_observed: list) -> dict:
        """
        Classifies the observed stage sequence against all campaign patterns.

        Parameters
        ----------
        stages_observed : list of stage strings (may contain duplicates)

        Returns
        -------
        dict with keys:
          likely_campaign : str   — Best matching campaign name or 'Unknown'
          confidence      : int   — 0-99
          matched_stages  : list  — Required stages that were matched
          missing_stages  : list  — Required stages that were NOT matched
          description     : str   — Campaign description
          all_scores      : dict  — {campaign_name: confidence} for all patterns
        """
        stage_set = set(stages_observed)
        all_scores = {}
        detailed = {}

        for campaign, pattern in self.patterns.items():
            score, matched, missing = self._score_pattern(stage_set, pattern)
            all_scores[campaign] = score
            detailed[campaign] = {
                "score":   score,
                "matched": matched,
                "missing": missing,
            }

        # Select winner
        best_campaign = max(all_scores, key=all_scores.get)
        best_score    = all_scores[best_campaign]

        if best_score < self.min_confidence:
            return {
                "likely_campaign": "Unknown",
                "confidence":      best_score,
                "matched_stages":  [],
                "missing_stages":  [],
                "description":     "Insufficient data to classify campaign type.",
                "all_scores":      all_scores,
            }

        return {
            "likely_campaign": best_campaign,
            "confidence":      best_score,
            "matched_stages":  detailed[best_campaign]["matched"],
            "missing_stages":  detailed[best_campaign]["missing"],
            "description":     self.patterns[best_campaign]["description"],
            "all_scores":      all_scores,
        }

    def _score_pattern(self, stage_set: set, pattern: dict) -> tuple:
        """
        Returns (confidence_score, matched_required, missing_required).
        """
        required = pattern["required"]
        optional = pattern["optional"]
        weight   = pattern["weight"]
        terminus = pattern.get("terminus")

        # Required stage matching
        matched_required = [s for s in required if s in stage_set]
        missing_required = [s for s in required if s not in stage_set]
        required_ratio   = len(matched_required) / len(required) if required else 0.0

        # Optional bonus (capped at 20)
        matched_optional = [s for s in optional if s in stage_set]
        optional_bonus   = min(20, len(matched_optional) * 4)

        # Terminus bonus
        terminus_bonus = 15 if terminus and terminus in stage_set else 0

        raw = required_ratio * weight + optional_bonus + terminus_bonus
        confidence = int(min(99, round(raw)))

        return confidence, matched_required, missing_required

    def get_all_patterns(self) -> dict:
        """Returns the full campaign pattern definitions for inspection."""
        return {name: {"required": p["required"], "optional": p["optional"],
                       "description": p["description"]} for name, p in self.patterns.items()}
