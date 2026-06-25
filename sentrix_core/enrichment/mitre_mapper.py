"""
sentrix_core/enrichment/mitre_mapper.py
Enriches detections with MITRE ATT&CK context.
"""
import json
import os
import logging

logger = logging.getLogger("sentrix.mitre")

class MitreMapper:
    def __init__(self, map_path: str = None):
        if not map_path:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            map_path = os.path.join(base_dir, "prediction_engine", "data", "mitre_technique_map.json")
            
        self.map_path = map_path
        self.technique_map = {}
        self._load_map()

    def _load_map(self):
        try:
            if os.path.exists(self.map_path):
                with open(self.map_path, "r") as f:
                    self.technique_map = json.load(f)
            else:
                logger.warning(f"MITRE map not found at {self.map_path}, creating a default stub.")
                self.technique_map = {
                    "T1110": {"name": "Brute Force", "tactic": "Credential Access", "description": "Adversaries may use brute force techniques to gain access to accounts."},
                    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access", "description": "Adversaries may obtain and abuse credentials of existing accounts."},
                    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution", "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries."},
                    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery", "description": "Adversaries may attempt to get a listing of services listening on remote hosts."},
                    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control", "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering."},
                }
                # Save the stub so it exists for future runs
                os.makedirs(os.path.dirname(self.map_path), exist_ok=True)
                with open(self.map_path, "w") as f:
                    json.dump(self.technique_map, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to load MITRE map: {e}")

    def enrich(self, technique_id: str) -> dict:
        """Returns MITRE context for a given technique ID."""
        if technique_id in self.technique_map:
            return self.technique_map[technique_id]
        return {"name": "Unknown", "tactic": "Unknown", "description": "No description available."}
