import os
import json
import yaml
import jsonschema

class RDFValidator:
    def __init__(self, schema_path=None):
        if not schema_path:
            schema_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                "schemas", 
                "rdf_schema.json"
            )
        self.schema_path = schema_path
        self.schema = self._load_schema()

    def _load_schema(self):
        with open(self.schema_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _standardize_rule(self, rule):
        if not isinstance(rule, dict):
            return rule
        if "metadata" in rule:
            rule_copy = rule.copy()
            meta = rule_copy["metadata"]
            if isinstance(meta, dict):
                rule_copy["rule_id"] = meta.get("id")
                rule_copy["rule_name"] = meta.get("name")
                rule_copy["description"] = meta.get("description")
                rule_copy["category"] = meta.get("threat_category")
                rule_copy["version"] = meta.get("version")
                rule_copy["mitre_mapping"] = meta.get("mitre_attack")
            threat_scoring = rule_copy.get("threat_scoring", {})
            if isinstance(threat_scoring, dict):
                rule_copy["severity"] = threat_scoring.get("base_severity")
                rule_copy["confidence"] = threat_scoring.get("confidence")
                rule_copy["base_risk_score"] = threat_scoring.get("default_risk_score", 50)
            detection = rule_copy.get("detection", {})
            if isinstance(detection, dict):
                rule_copy["conditions"] = detection.get("conditions")
            explanation = rule_copy.get("explanation", {})
            if isinstance(explanation, dict):
                rule_copy["recommended_actions"] = explanation.get("recommended_actions")
            return rule_copy
        return rule

    def validate_dict(self, data):
        standardized_data = self._standardize_rule(data)
        try:
            jsonschema.validate(instance=standardized_data, schema=self.schema)
            return True, None
        except jsonschema.exceptions.ValidationError as err:
            return False, f"Validation failed at path {list(err.path)}: {err.message}"

    def validate_file(self, file_path):
        if not os.path.exists(file_path):
            return False, f"File {file_path} not found"
        
        with open(file_path, "r", encoding="utf-8") as f:
            try:
                if file_path.endswith(".json"):
                    data = json.load(f)
                else:
                    data = yaml.safe_load(f)
            except Exception as e:
                return False, f"Failed to parse file: {e}"
        
        # In case the file represents a rules list wrapper (like {"rules": [...]})
        if isinstance(data, dict) and "rules" in data:
            for idx, rule in enumerate(data["rules"]):
                ok, err = self.validate_dict(rule)
                if not ok:
                    return False, f"Rule at index {idx} in {os.path.basename(file_path)}: {err}"
            return True, None
            
        return self.validate_dict(data)
