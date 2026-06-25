"""
risk_calculator.py
──────────────────
Sentrix Enterprise Risk Scoring Engine — V2.1

DESIGN:
  Risk and Confidence are SEPARATE outputs.

  Risk Score (0–100):
    Represents the DANGER LEVEL if the detection is genuine.
    Composed of 7 independent factors, normalized to [0, 100].

  Confidence Score (0–100):
    Represents the PROBABILITY that the detection is genuine.
    Never embedded in the risk calculation.

RISK FORMULA (raw 20–130, normalized to 0–100):
  Base Risk          20–60   (rule severity — floor)
  Threshold Bonus     0–10   (correlation event count)
  Sequence Bonus      0–15   (kill-chain sequence completion)
  Campaign Bonus      0–15   (multi-stage attack chain depth)
  Asset Criticality   0–10   (CMDB criticality of affected asset)
  Threat Intel        0–10   (external TI feed confirmation)
  Crisis Mode         0–10   (engine-controlled only, never from YAML)

  Normalization: ((raw - 20) / 110) × 100 → clamped [0, 100]

SEVERITY MAP:
   0–25  → informational
  26–45  → low
  46–65  → medium
  66–85  → high
  86–100 → critical

RESPONSE GATE (Risk × Confidence):
  Risk ≥ 86 AND Confidence ≥ 80 → Full automation
  Risk ≥ 66 AND Confidence ≥ 60 → Partial automation (forensics, webhook)
  Risk ≥ 46 AND Confidence ≥ 40 → Analyst queue (no auto action)
  else                           → Log to SIEM only
"""

import logging

logger = logging.getLogger("sentrix.scoring.risk")

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_RAW_MIN = 20.0   # minimum possible raw score (informational, no signals)
_RAW_MAX = 130.0  # maximum possible raw score (all factors maxed)

_SEVERITY_WEIGHTS = {
    "informational": 20,
    "low":           30,
    "medium":        40,
    "high":          50,
    "critical":      60,
}

_SEVERITY_MAP = [
    (86, "critical"),
    (66, "high"),
    (46, "medium"),
    (26, "low"),
    (0,  "informational"),
]

# Default confidence values by rule evaluation mode
_DEFAULT_CONFIDENCE = {
    "single_event": 85,
    "behavioral":   40,
    "correlation":  70,
    "anomaly":      25,
}


# ─────────────────────────────────────────────────────────────────────────────
# RiskCalculator
# ─────────────────────────────────────────────────────────────────────────────

class RiskCalculator:
    """
    Computes (risk_score, confidence_score, severity) for a triggered rule.

    All seven risk factors are independently computed and additively composed.
    The raw total is linearly normalized to [0, 100] — it is mathematically
    impossible to exceed 100.

    Confidence is a fully separate output: it is never added to the risk score.
    """

    def __init__(self, threat_context_manager=None, asset_context_manager=None):
        self.threat_context = threat_context_manager
        self.asset_context  = asset_context_manager

    # ── Public interface ──────────────────────────────────────────────────────

    def calculate_risk(self, rule, context, event, progression_score=0,
                       threshold_info=None, sequence_info=None):
        """
        Returns (risk_score: int, confidence_score: int, severity: str).

        Parameters
        ----------
        rule              : dict — loaded RDF rule
        context           : dict — output of AssetContextManager.build_context()
        event             : dict — SCEF-normalized event
        progression_score : int  — 0–100 from AttackChainEngine.get_progression_score()
        threshold_info    : dict — {triggered: bool, event_count: int, limit: int} or None
        sequence_info     : dict — {triggered: bool, steps_completed: int,
                                    total_steps: int, span_seconds: int} or None
        """
        # ── Factor 1: Base Risk (20–60) ───────────────────────────────────────
        raw_severity = (
            rule.get("severity")
            or rule.get("threat_scoring", {}).get("base_severity")
            or "medium"
        ).lower()
        base = _SEVERITY_WEIGHTS.get(raw_severity, 40)

        # ── Factor 2: Threshold Correlation Bonus (0–10) ──────────────────────
        threshold_bonus = self._threshold_bonus(threshold_info, rule)

        # ── Factor 3: Sequence Correlation Bonus (0–15) ───────────────────────
        sequence_bonus = self._sequence_bonus(sequence_info, rule)

        # ── Factor 4: Campaign / Attack Chain Bonus (0–15) ───────────────────
        campaign_bonus = self._campaign_bonus(progression_score)

        # ── Factor 5: Asset Criticality (0–10) ───────────────────────────────
        asset_bonus = self._asset_bonus(context)

        # ── Factor 6: Threat Intelligence (0–10) ─────────────────────────────
        ti_bonus = self._ti_bonus(event)

        # ── Factor 7: Crisis Mode (0–10, engine-controlled only) ─────────────
        crisis_bonus = self._crisis_bonus(context, rule)

        raw = base + threshold_bonus + sequence_bonus + campaign_bonus + \
              asset_bonus + ti_bonus + crisis_bonus

        # ── Normalize to [0, 100] ─────────────────────────────────────────────
        normalized = ((raw - _RAW_MIN) / (_RAW_MAX - _RAW_MIN)) * 100.0
        risk_score  = int(round(min(100.0, max(0.0, normalized))))

        # ── Derive severity from normalized risk score ─────────────────────────
        severity = self._risk_to_severity(risk_score)

        # ── Compute Confidence (separate, never touches risk) ─────────────────
        confidence = self._calculate_confidence(rule, event, context)

        logger.debug(
            "[RiskCalc] raw=%d norm=%d risk=%d conf=%d sev=%s "
            "(base=%d thr=%d seq=%d camp=%d asset=%d ti=%d crisis=%d)",
            raw, int(normalized), risk_score, confidence, severity,
            base, threshold_bonus, sequence_bonus, campaign_bonus,
            asset_bonus, ti_bonus, crisis_bonus,
        )

        return risk_score, confidence, severity

    # ── Factor implementations ────────────────────────────────────────────────

    def _threshold_bonus(self, threshold_info, rule):
        """
        0  — no threshold matched
        5  — threshold matched, count < 2× the configured limit
        10 — threshold matched, count ≥ 2× the limit (high-volume event)
        """
        if not threshold_info or not threshold_info.get("triggered"):
            return 0
        count = threshold_info.get("event_count", 0)
        limit = threshold_info.get("limit", 1)
        return 10 if count >= 2 * limit else 5

    def _sequence_bonus(self, sequence_info, rule):
        """
        0  — no sequence matched
        5  — sequence in progress (partial)
        10 — sequence fully completed
        15 — sequence completed AND spans > 30 minutes (slow kill-chain)
        """
        if not sequence_info or not sequence_info.get("triggered"):
            # Check if rule IS a sequence rule — partial credit
            mode = rule.get("mode") or rule.get("detection", {}).get("mode")
            if mode == "correlation":
                detection = rule.get("detection", {}) or rule
                corr = detection.get("correlation", {}) or rule.get("correlation", {})
                if "sequence" in corr or "sequence" in rule:
                    return 5  # Partial — sequence in progress
            return 0
        steps_done = sequence_info.get("steps_completed", 0)
        total      = sequence_info.get("total_steps", 1)
        span_secs  = sequence_info.get("span_seconds", 0)
        if steps_done >= total and span_secs > 1800:
            return 15
        if steps_done >= total:
            return 10
        return 5

    def _campaign_bonus(self, progression_score):
        """
        Maps AttackChainEngine progression_score to campaign bonus (0–15).
        Single isolated event (prog=15):  0
        2–3 MITRE stages (prog 30–50):   5
        4+ MITRE stages (prog 70–85):    10
        Full kill chain (prog=100):      15
        """
        if progression_score <= 15:   return 0
        if progression_score <= 50:   return 5
        if progression_score <= 85:   return 10
        return 15

    def _asset_bonus(self, context):
        """
        Returns asset criticality as bonus (0–10).
        Default for unknown assets: 3 (not inflated).
        """
        asset = context.get("asset_context", {})
        criticality = float(asset.get("criticality", 0.3))
        return round(min(10.0, criticality * 10.0))

    def _ti_bonus(self, event):
        """
        0  — no TI feed configured or no signal
        3  — IP in low-confidence threat list
        6  — IP in high-confidence threat list
        8  — TOR exit node confirmed
        10 — Known APT C2 / active malware domain
        """
        if not self.threat_context:
            return 0
        try:
            raw_score = self.threat_context.get_reputation_score(event)
        except Exception:
            return 0

        # Map raw ThreatContext score (0–100) to TI bonus (0–10) in tiers
        if raw_score >= 90:   return 10
        if raw_score >= 80:   return 8
        if raw_score >= 60:   return 6
        if raw_score >= 40:   return 3
        return 0

    def _crisis_bonus(self, context, rule):
        """
        Engine-controlled crisis bonus. NEVER taken from rule YAML.
        Crisis OFF:                    0
        Crisis ON, no rule override:   5
        Crisis ON, rule has override: 10
        Maximum is 10 — no rule can self-boost beyond this.
        """
        crisis = context.get("crisis_mode", {})
        if not crisis.get("enabled", False):
            return 0
        overrides = rule.get("crisis_mode_overrides", {})
        return 10 if overrides else 5

    # ── Confidence Model ──────────────────────────────────────────────────────

    def _calculate_confidence(self, rule, event, context):
        """
        Confidence represents probability that the detection is a true positive.
        Range: 0–100. Never mixed into risk_score.

        Base from rule author's confidence setting.
        Adjusted by: TI corroboration, user privilege context.
        """
        mode = (rule.get("mode") or rule.get("detection", {}).get("mode") or "single_event").lower()
        rule_confidence = rule.get("confidence") or rule.get("threat_scoring", {}).get("confidence")

        if rule_confidence is None:
            base_conf = _DEFAULT_CONFIDENCE.get(mode, 70)
        else:
            base_conf = int(rule_confidence)

        # TI corroboration bonus (+10 if TI confirms source)
        ti_conf_bonus = 0
        if self.threat_context:
            try:
                ti_raw = self.threat_context.get_reputation_score(event)
                if ti_raw >= 80:
                    ti_conf_bonus = 10
                elif ti_raw >= 40:
                    ti_conf_bonus = 5
            except Exception:
                pass

        # Privilege context — elevated user increases confidence in high-sev alerts
        priv_bonus = 0
        user_ctx = context.get("user_context", {})
        priv = user_ctx.get("privilege_level", "user")
        if priv in ("system", "admin"):
            priv_bonus = 5

        confidence = int(min(100, base_conf + ti_conf_bonus + priv_bonus))
        return confidence

    # ── Utilities ─────────────────────────────────────────────────────────────

    @staticmethod
    def _risk_to_severity(risk_score):
        for threshold, label in _SEVERITY_MAP:
            if risk_score >= threshold:
                return label
        return "informational"

    @staticmethod
    def response_gate(risk_score, confidence_score):
        """
        Determines the automation tier based on Risk × Confidence joint evaluation.

        Returns one of:
          'full_auto'    → block, isolate, create_incident, collect_forensics
          'partial_auto' → collect_forensics, webhook_alert, log_to_siem
          'analyst_queue'→ log_to_siem only (no automated action)
          'log_only'     → log_to_siem only
        """
        if risk_score >= 86 and confidence_score >= 80:
            return "full_auto"
        if risk_score >= 66 and confidence_score >= 60:
            return "partial_auto"
        if risk_score >= 46 and confidence_score >= 40:
            return "analyst_queue"
        return "log_only"
