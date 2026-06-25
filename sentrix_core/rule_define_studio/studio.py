"""
sentrix_core/rule_define_studio/studio.py
Rule CRUD operations for the Rule Define Studio.
"""
import os
import json
import uuid
import logging
from datetime import datetime, timezone
from sentrix_core.config.settings import get_settings
from sentrix_core.threat_engine.rdf_runtime.rdf_validator import RDFValidator

logger = logging.getLogger("sentrix.rule_studio")

class RuleStudio:
    def __init__(self):
        settings = get_settings()
        self.rules_dir = settings.custom_rules_dir
        self.archive_dir = os.path.join(settings.DATA_DIR, "custom-rules", "archived")
        os.makedirs(self.archive_dir, exist_ok=True)
        self.validator = RDFValidator()

    def _get_rule_path(self, rule_id: str) -> str:
        return os.path.join(self.rules_dir, f"{rule_id}.json")

    def validate_rule(self, rule_dict: dict) -> list:
        """Return list of validation errors, or empty list if valid."""
        try:
            result = self.validator.validate_dict(rule_dict)
            # validate_dict returns True if valid, or raises/returns errors
            if result is True or result is None:
                return []
            if isinstance(result, list):
                return result
            return []
        except Exception as e:
            return [str(e)]

    def create_rule(self, rule_dict: dict) -> dict:
        errors = self.validate_rule(rule_dict)
        if errors:
            raise ValueError(f"Rule validation failed: {errors}")

        metadata = rule_dict.get("metadata", {})
        rule_id = metadata.get("id")
        if not rule_id:
            rule_id = f"custom-rule-{uuid.uuid4().hex[:8]}"
            if "metadata" not in rule_dict:
                rule_dict["metadata"] = {}
            rule_dict["metadata"]["id"] = rule_id

        rule_dict["metadata"]["created_at"] = datetime.now(timezone.utc).isoformat()
        rule_dict["metadata"]["version"] = rule_dict["metadata"].get("version", 1)
        
        path = self._get_rule_path(rule_id)
        if os.path.exists(path):
            raise ValueError(f"Rule {rule_id} already exists. Use update.")

        with open(path, "w") as f:
            json.dump(rule_dict, f, indent=4)
        
        logger.info(f"Created rule: {rule_id}")
        return rule_dict

    def update_rule(self, rule_id: str, rule_dict: dict) -> dict:
        path = self._get_rule_path(rule_id)
        if not os.path.exists(path):
            raise ValueError(f"Rule {rule_id} not found.")

        errors = self.validate_rule(rule_dict)
        if errors:
            raise ValueError(f"Rule validation failed: {errors}")

        if "metadata" not in rule_dict:
            rule_dict["metadata"] = {}
        rule_dict["metadata"]["id"] = rule_id
        rule_dict["metadata"]["updated_at"] = datetime.now(timezone.utc).isoformat()
        
        with open(path, "r") as f:
            old_rule = json.load(f)
            old_version = old_rule.get("metadata", {}).get("version", 1)
            rule_dict["metadata"]["version"] = old_version + 1

        with open(path, "w") as f:
            json.dump(rule_dict, f, indent=4)

        logger.info(f"Updated rule: {rule_id} (v{rule_dict['metadata']['version']})")
        return rule_dict

    def get_rule(self, rule_id: str) -> dict:
        path = self._get_rule_path(rule_id)
        if not os.path.exists(path):
            return None
        with open(path, "r") as f:
            return json.load(f)

    def list_rules(self) -> list:
        rules = []
        for filename in os.listdir(self.rules_dir):
            if filename.endswith(".json"):
                with open(os.path.join(self.rules_dir, filename), "r") as f:
                    try:
                        rules.append(json.load(f))
                    except Exception as e:
                        logger.error(f"Failed to load {filename}: {e}")
        return rules

    def delete_rule(self, rule_id: str):
        path = self._get_rule_path(rule_id)
        if os.path.exists(path):
            archive_path = os.path.join(self.archive_dir, f"{rule_id}.json")
            os.rename(path, archive_path)
            logger.info(f"Deleted (archived) rule: {rule_id}")
            return True
        return False
