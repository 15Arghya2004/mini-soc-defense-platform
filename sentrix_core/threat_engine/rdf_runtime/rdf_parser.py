import re

class RDFConditionParser:
    def __init__(self):
        pass

    def compile_condition(self, cond):
        operator = cond.get("operator")
        val = cond.get("value")
        
        # JIT compilation of regex matches to avoid compile overhead in event loops
        if operator == "regex_match":
            try:
                cond["_compiled_regex"] = re.compile(val, re.IGNORECASE)
            except Exception as e:
                raise ValueError(f"Failed to compile regex '{val}': {e}")
                
        # Speed up CIDR or list operations by indexing set operations
        elif operator == "in_list" or operator == "not_in_list":
            if isinstance(val, list):
                cond["_indexed_set"] = {str(x).lower() for x in val}
                
        return cond

    def compile_rule_conditions(self, rule):
        detection = rule.get("conditions", {})
        if not detection:
            return rule

        if "all" in detection:
            compiled = []
            for cond in detection["all"]:
                compiled.append(self.compile_condition(cond))
            detection["all"] = compiled

        if "any" in detection:
            compiled = []
            for cond in detection["any"]:
                compiled.append(self.compile_condition(cond))
            detection["any"] = compiled

        # Compile thresholds unique value configurations if present
        return rule
