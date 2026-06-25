"""
response_dispatcher.py
───────────────────────
Sentrix SOAR Response Dispatcher — V2.1

Implements the Risk × Confidence Response Gate:

  Full Auto     Risk ≥ 86 AND Confidence ≥ 80
  Partial Auto  Risk ≥ 66 AND Confidence ≥ 60
  Analyst Queue Risk ≥ 46 AND Confidence ≥ 40  (log only — no auto action)
  Log Only      anything below

In Crisis Mode, the Confidence gate is lowered by 20 points.

Action filtering per gate:
  full_auto:     all rule-defined actions executed
  partial_auto:  only 'safe' actions: collect_forensics, webhook_alert,
                 log_to_siem, notify_soc, create_incident
  analyst_queue: no automated execution — log_to_siem only
  log_only:      log_to_siem only
"""

import logging

from .action_builder import SOARActionBuilder
from sentrix_core.threat_engine.scoring.risk_calculator import RiskCalculator

logger = logging.getLogger("sentrix.response.dispatcher")

# Actions allowed in partial automation mode
_PARTIAL_AUTO_ACTIONS = frozenset({
    "collect_forensics",
    "webhook_alert",
    "log_to_siem",
    "notify_soc",
    "create_incident",
})

# Actions that ALWAYS run regardless of gate (audit trail)
_AUDIT_ACTIONS = frozenset({"log_to_siem"})

# Crisis mode reduces confidence gate by this amount
_CRISIS_CONFIDENCE_REDUCTION = 20


class ResponseDispatcher:
    """
    Evaluates the Risk × Confidence gate and dispatches SOAR actions
    accordingly.  No action is executed without clearing the gate.
    """

    def __init__(self, response_engine=None):
        self.response_engine = response_engine
        self.action_builder  = SOARActionBuilder()

    def dispatch_alert(self, alert_payload, rule):
        """
        Main entry point.  Evaluates the gate, filters actions, dispatches.
        Returns list of action records with execution status.
        """
        risk_score       = alert_payload.get("risk_score", 0)
        confidence_score = alert_payload.get("confidence_score", 70)  # safe default
        crisis_active    = self._is_crisis(alert_payload)
        target           = (
            alert_payload.get("affected_host")
            or alert_payload.get("user")
            or "Unknown"
        )

        gate = self._evaluate_gate(risk_score, confidence_score, crisis_active)
        actions = self.action_builder.build_actions(alert_payload, rule)

        triggered_actions = []
        for action in actions:
            action_type = action.get("action_type")
            params      = action.get("parameters", {})

            should_execute, gate_reason = self._should_execute(
                action_type, gate, action
            )

            record = {
                "action_type":   action_type,
                "parameters":    params,
                "target":        target,
                "gate":          gate,
                "auto_executed": should_execute,
                "status":        "triggered" if should_execute else gate_reason,
            }

            if self.response_engine and should_execute:
                try:
                    self.response_engine.execute_action(action_type, params, target)
                except Exception as exc:
                    logger.error("[Dispatcher] SOAR action %s failed: %s", action_type, exc)
                    record["status"] = "execution_failed"
                    record["error"]  = str(exc)

            triggered_actions.append(record)
            logger.info(
                "[Dispatcher] %s → %s [gate=%s status=%s risk=%d conf=%d]",
                action_type.upper(), target, gate, record["status"],
                risk_score, confidence_score,
            )
            print(
                f"[Dispatcher] Active response dispatched: "
                f"{action_type.upper()} on {target} "
                f"(Gate: {gate} | Status: {record['status']})"
            )

        return triggered_actions

    # ── Gate Evaluation ───────────────────────────────────────────────────────

    def _evaluate_gate(self, risk_score, confidence_score, crisis_active):
        """
        Returns the automation tier string.
        In Crisis Mode, the confidence threshold is reduced by 20 points.
        """
        conf_adj = confidence_score + (_CRISIS_CONFIDENCE_REDUCTION if crisis_active else 0)
        return RiskCalculator.response_gate(risk_score, min(100, conf_adj))

    def _should_execute(self, action_type, gate, action_def):
        """
        Determines whether an action should execute and returns (bool, reason).
        """
        auto         = action_def.get("auto_execution", False)
        approval_req = action_def.get("approval_required", True)

        # Audit actions (log_to_siem) always run
        if action_type in _AUDIT_ACTIONS:
            return True, "triggered"

        if gate == "full_auto":
            if auto and not approval_req:
                return True, "triggered"
            if approval_req:
                return False, "pending_soc_approval"
            return True, "triggered"

        elif gate == "partial_auto":
            if action_type in _PARTIAL_AUTO_ACTIONS and auto and not approval_req:
                return True, "triggered"
            return False, f"gate_restricted_{gate}"

        elif gate == "analyst_queue":
            return False, "analyst_queue_pending"

        else:  # log_only
            return False, "log_only_gate"

    # ── Utilities ─────────────────────────────────────────────────────────────

    @staticmethod
    def _is_crisis(alert_payload):
        """
        Crisis active if the trigger event carries the crisis_active tag
        (set by CrisisModeController.apply_overrides_to_event).
        """
        story = alert_payload.get("attack_story") or {}
        # Check for crisis tag in the alert story or a top-level field
        return bool(alert_payload.get("crisis_active"))
