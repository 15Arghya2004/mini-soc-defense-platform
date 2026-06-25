class BehavioralDetector:
    def __init__(self, matcher=None):
        self.matcher = matcher

    def evaluate_rule(self, event, rule):
        """Matches a normalized event against a behavioral anomaly rule."""
        anomaly_type = rule.get("anomaly_type")
        if not anomaly_type:
            return False

        scope = rule.get("scope", {})
        filter_conditions = scope.get("filter_conditions", {})

        # Verify baseline conditions (e.g. event category must match)
        if filter_conditions:
            # We can use the nested logic evaluator
            if not self.evaluate_filter(event, filter_conditions):
                return False

        logic = rule.get("anomaly_logic", {})
        metric = logic.get("metric")
        operator = logic.get("operator")

        # 1. Process Lineage Anomaly
        if anomaly_type == "process_lineage_anomaly" or metric == "process_ancestry":
            parent_name = self.matcher.get_field_value(event, "process.parent.name")
            child_name = self.matcher.get_field_value(event, "process.name")
            
            # Anomalous shell spawns
            shells = ["cmd.exe", "powershell.exe", "bash", "sh", "wscript.exe"]
            document_hosts = ["winword.exe", "excel.exe", "spoolsv.exe", "acrord32.exe", "outlook.exe", "mshta.exe"]
            
            if child_name in shells and parent_name in document_hosts:
                return True
                
            # Whitelist checks
            whitelist = logic.get("whitelist", [])
            if whitelist and parent_name not in whitelist and child_name in shells:
                return True

        # 2. High Entropy File modification Anomaly
        elif anomaly_type == "file_entropy_anomaly" or metric == "entropy_level":
            entropy_val = self.matcher.get_field_value(event, "file.entropy")
            if entropy_val is not None:
                threshold = float(logic.get("threshold_value", 7.8))
                try:
                    if float(entropy_val) > threshold:
                        return True
                except (ValueError, TypeError):
                    return False

        return False

    def evaluate_filter(self, event, filters):
        """Simple filter checker supporting all/any logic."""
        if "all" in filters:
            for cond in filters["all"]:
                if not self.matcher.evaluate_condition(event, cond):
                    return False
            return True
        if "any" in filters:
            for cond in filters["any"]:
                if self.matcher.evaluate_condition(event, cond):
                    return True
            return False
        return True
