class CrisisModeController:
    def __init__(self):
        self.enabled = False
        self.scope = None  # e.g., "production-subnets" or a specific hostname/IP

    def set_crisis_mode(self, enabled, scope=None):
        self.enabled = enabled
        self.scope = scope

    def get_state(self):
        return {
            "enabled": self.enabled,
            "scope": self.scope
        }

    def apply_overrides_to_event(self, event):
        """Enriches event copy if Crisis Mode is enabled."""
        if not self.enabled:
            return event
        
        event_copy = event.copy()
        if "event" not in event_copy:
            event_copy["event"] = {}
        
        # Tag event with crisis status
        event_copy["event"]["crisis_active"] = True
        if self.scope:
            event_copy["event"]["crisis_scope"] = self.scope
            
        return event_copy

    def apply_overrides_to_rule(self, rule):
        """
        Applies runtime overrides to rule configuration in Crisis Mode:
        - division of thresholds (lower count to increase sensitivity)
        - division of sliding window sizes (faster correlation)
        - overrides execution approvals to force auto-containment.
        """
        if not self.enabled:
            return rule

        rule_copy = rule.copy()
        detection = rule_copy.get("detection", {})
        corr = detection.get("correlation", {}) or rule_copy.get("correlation", {})

        # Lower threshold limits (increase sensitivity by 50%)
        if "thresholds" in rule_copy:
            thresh = rule_copy["thresholds"]
            thresh["count"] = max(2, int(thresh.get("count", 10) / 2))
        elif "threshold" in corr:
            thresh = corr["threshold"]
            thresh["count"] = max(2, int(thresh.get("count", 10) / 2))

        # Enforce automatic containment on response actions
        response = rule_copy.get("response", {})
        if response and "actions" in response:
            actions_copy = []
            for action in response["actions"]:
                act = action.copy()
                act["auto_execution"] = True
                act["approval_required"] = False
                actions_copy.append(act)
            rule_copy["response"]["actions"] = actions_copy

        return rule_copy
