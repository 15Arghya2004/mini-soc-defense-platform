import os
import json
import yaml
from .rdf_validator import RDFValidator
from .rdf_parser import RDFConditionParser

class RDFLoader:
    def __init__(self, rules_dir, schema_path=None):
        # Support single directory string or a list of directory strings
        if isinstance(rules_dir, list):
            self.rules_dirs = rules_dir
        else:
            self.rules_dirs = [rules_dir]
        self.validator = RDFValidator(schema_path)
        self.parser = RDFConditionParser()

    def load_all_rules(self):
        rules = {}
        for r_dir in self.rules_dirs:
            if not os.path.exists(r_dir):
                continue

            # Recursively search files under rules repository directories
            for root, _, files in os.walk(r_dir):
                if "unknown-attacks" in os.path.basename(root) or "unknown-attacks" in root.split(os.sep):
                    continue
                for file in files:
                    if file.endswith((".json", ".yaml", ".yml")):
                        file_path = os.path.join(root, file)
                        ok, err = self.validator.validate_file(file_path)
                        if not ok:
                            print(f"[-] Excluding invalid rule file {file}: {err}")
                            continue
                        
                        # Parse rules list or single rule
                        with open(file_path, "r", encoding="utf-8") as f:
                            if file_path.endswith(".json"):
                                data = json.load(f)
                            else:
                                data = yaml.safe_load(f)
                                
                        is_custom = "custom-rules" in r_dir or "custom-rules" in root
                        if isinstance(data, dict) and "rules" in data:
                            for rule in data["rules"]:
                                if is_custom:
                                    rule["is_custom"] = True
                                self._add_rule(rule, rules)
                        else:
                            if is_custom:
                                data["is_custom"] = True
                            self._add_rule(data, rules)
                            
        # Resolve inheritance configurations (parent-child dependencies)
        self._resolve_inheritance(rules)
        
        # Compile condition ASTs
        for rule_id, rule in rules.items():
            rules[rule_id] = self.parser.compile_rule_conditions(rule)
            
        return rules

    def _add_rule(self, rule, rules_map):
        rule_id = rule.get("rule_id") or rule.get("metadata", {}).get("id")
        if rule_id:
            # Standardize keys depending on format: convert metadata-based keys into top-level keys
            if "metadata" in rule:
                meta = rule["metadata"]
                rule["rule_id"] = meta.get("id")
                rule["rule_name"] = meta.get("name")
                rule["description"] = meta.get("description")
                rule["category"] = meta.get("threat_category")
                rule["severity"] = rule.get("threat_scoring", {}).get("base_severity")
                rule["confidence"] = rule.get("threat_scoring", {}).get("confidence")
                rule["base_risk_score"] = rule.get("threat_scoring", {}).get("default_risk_score", 50)
                rule["version"] = meta.get("version")
                rule["conditions"] = rule.get("detection", {}).get("conditions")
                rule["mitre_mapping"] = meta.get("mitre_attack")
                rule["recommended_actions"] = rule.get("explanation", {}).get("recommended_actions")
                rule["is_custom"] = rule.get("is_custom", False)
            
            rules_map[rule_id] = rule

    def _resolve_inheritance(self, rules_map):
        # Scan rules for parent-child linkages
        for rule_id, rule in list(rules_map.items()):
            parent_id = rule.get("parent_rule_id") or rule.get("metadata", {}).get("parent_rule_id")
            if parent_id and parent_id in rules_map:
                parent = rules_map[parent_id]
                # Merge logic: child inherits missing keys from parent
                merged = parent.copy()
                merged.update(rule)
                # Ensure child conditions overwrite parent conditions
                if "conditions" in rule:
                    merged["conditions"] = rule["conditions"]
                rules_map[rule_id] = merged
