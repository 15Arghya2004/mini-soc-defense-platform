from sentrix_core.threat_engine.detection.matcher import EventMatcher

class RDFExecutor:
    def __init__(self, threshold_engine=None, sequence_engine=None, attack_chain_engine=None):
        self.matcher = EventMatcher()
        self.threshold_engine = threshold_engine
        self.sequence_engine = sequence_engine
        self.attack_chain_engine = attack_chain_engine

    def evaluate_signature_rule(self, event, rule):
        """Evaluates a single signature rule using the matcher. Handles nested AND/OR logic."""
        detection = rule.get("detection", {}) or rule.get("conditions", {})
        if not detection:
            return True
            
        # Standardize nested structure if "conditions" is inside "detection"
        if "conditions" in detection:
            conds = detection["conditions"]
        else:
            conds = detection

        return self.evaluate_condition_block(event, conds)

    def evaluate_condition_block(self, event, block):
        """Recursively evaluates nested logical condition blocks (all/any)."""
        if not isinstance(block, dict):
            return False

        # Support AND logic
        if "all" in block:
            for cond in block["all"]:
                if not self.evaluate_sub_condition(event, cond):
                    return False
            return True

        # Support OR logic
        if "any" in block:
            for cond in block["any"]:
                if self.evaluate_sub_condition(event, cond):
                    return True
            return False

        return True

    def evaluate_sub_condition(self, event, cond):
        """Evaluates an item in a condition list, which can be a single condition or a nested block."""
        if "all" in cond or "any" in cond:
            return self.evaluate_condition_block(event, cond)
        return self.matcher.evaluate_condition(event, cond)

    def execute_rule(self, event, rule, active_session_callback=None):
        """
        Executes an RDF rule against a normalized event.
        Routes to stateful correlation engines if rule mode is 'correlation'.
        """
        mode = rule.get("mode") or rule.get("detection", {}).get("mode", "single_event")

        # Single event match
        if mode in ["single_event", "behavioral"]:
            if self.evaluate_signature_rule(event, rule):
                return True, [event]
            return False, []

        # Stateful correlation match
        elif mode == "correlation":
            # Match baseline conditions first before updating state
            if not self.evaluate_signature_rule(event, rule):
                return False, []

            detection = rule.get("detection", {}) or rule
            corr = detection.get("correlation", {}) or rule.get("correlation", {})
            group_by = corr.get("group_by", [])
            
            # Resolve grouping session keys
            key_parts = []
            for field in group_by:
                val = self.matcher.get_field_value(event, field)
                key_parts.append(str(val or "unknown"))
            session_key = "|".join(key_parts)

            # Route to threshold engine
            if "thresholds" in rule or "threshold" in corr:
                if self.threshold_engine:
                    triggered, matched_events = self.threshold_engine.process_event(event, rule, self.matcher, session_key)
                    if triggered:
                        return True, matched_events
                return False, []

            # Route to sequence engine
            elif "sequence" in corr or "sequence" in rule:
                if self.sequence_engine:
                    triggered, matched_events = self.sequence_engine.process_event(event, rule, self.matcher, session_key)
                    if triggered:
                        return True, matched_events
                return False, []

        return False, []

