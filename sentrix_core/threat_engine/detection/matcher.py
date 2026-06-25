import re

class EventMatcher:
    def __init__(self):
        pass

    def get_field_value(self, event, field_path):
        """Resolves dotted fields like process.parent.name within a dictionary."""
        if not field_path:
            return None
        val = event
        for key in field_path.split('.'):
            if isinstance(val, dict):
                val = val.get(key)
            else:
                return None
        return val

    def evaluate_condition(self, event, cond):
        """Evaluates a single rule condition against a normalized event."""
        field = cond.get("field")
        operator = cond.get("operator")
        expected_value = cond.get("value")

        val = self.get_field_value(event, field)

        # Handle existence operators first since they don't require the value to be present
        if operator == "exists":
            return val is not None and val != ""
        elif operator == "not_exists":
            return val is None or val == ""

        if val is None:
            return False

        # Convert to string for general operators
        val_str = str(val)

        # regex/regex_match JIT support
        if operator in ["regex", "regex_match"]:
            compiled = cond.get("_compiled_regex")
            if not compiled and expected_value:
                try:
                    compiled = re.compile(str(expected_value), re.IGNORECASE)
                    cond["_compiled_regex"] = compiled
                except Exception:
                    return False
            return bool(compiled.search(val_str)) if compiled else False

        elif operator == "in_list":
            indexed = cond.get("_indexed_set")
            if not indexed and isinstance(expected_value, list):
                indexed = {str(x).lower() for x in expected_value}
                cond["_indexed_set"] = indexed
            if indexed:
                return val_str.lower() in indexed
            if isinstance(expected_value, list):
                return val_str.lower() in [str(x).lower() for x in expected_value]
            return False

        elif operator == "not_in_list":
            indexed = cond.get("_indexed_set")
            if not indexed and isinstance(expected_value, list):
                indexed = {str(x).lower() for x in expected_value}
                cond["_indexed_set"] = indexed
            if indexed:
                return val_str.lower() not in indexed
            if isinstance(expected_value, list):
                return val_str.lower() not in [str(x).lower() for x in expected_value]
            return True

        elif operator == "equals":
            return val_str.lower() == str(expected_value).lower()

        elif operator == "not_equals":
            return val_str.lower() != str(expected_value).lower()

        elif operator == "contains":
            return str(expected_value).lower() in val_str.lower()

        elif operator == "not_contains":
            return str(expected_value).lower() not in val_str.lower()

        elif operator == "starts_with":
            return val_str.lower().startswith(str(expected_value).lower())

        elif operator == "ends_with":
            return val_str.lower().endswith(str(expected_value).lower())

        elif operator == "greater_than":
            try:
                return float(val) > float(expected_value)
            except (ValueError, TypeError):
                return False

        elif operator == "less_than":
            try:
                return float(val) < float(expected_value)
            except (ValueError, TypeError):
                return False

        return False

    def evaluate_rule(self, event, rule):
        """Evaluates detection conditions (all/any) for a signature rule."""
        detection = rule.get("conditions", {})
        if not detection:
            return True

        if "all" in detection:
            for cond in detection["all"]:
                if not self.evaluate_condition(event, cond):
                    return False
            return True

        if "any" in detection:
            for cond in detection["any"]:
                if self.evaluate_condition(event, cond):
                    return True
            return False

        return True
