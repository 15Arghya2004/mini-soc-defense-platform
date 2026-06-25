import logging

logger = logging.getLogger("sentrix.investigation.attack_chain_builder")

# Mappings of rules/categories to the 6 target progression stages
STAGE_CRITERIA = {
    "Port Scan": {
        "keywords": ["port scan", "recon", "network scan", "discovery"],
        "stages": ["Reconnaissance", "Discovery"]
    },
    "Bruteforce": {
        "keywords": ["brute force", "bruteforce", "credential stuff", "login spray"],
        "stages": ["Credential Access"]
    },
    "Credential Access": {
        "keywords": ["credential dump", "credential access", "mimikatz", "dumping", "pass the hash"],
        "stages": ["Credential Access"]
    },
    "Lateral Movement": {
        "keywords": ["lateral movement", "remote service", "remote desktop", "smb", "psexec"],
        "stages": ["Lateral Movement"]
    },
    "Collection": {
        "keywords": ["collection", "insider", "data staged", "archive data", "sensitive files"],
        "stages": ["Collection"]
    },
    "Exfiltration": {
        "keywords": ["exfiltration", "data exfil", "exfil", "upload", "c2 exfil"],
        "stages": ["Exfiltration"]
    }
}

class AttackChainBuilder:
    def build(self, threat_findings: list) -> dict:
        """
        Reconstructs the kill-chain progression based strictly on actual alert evidence.
        NO AI GUESSING or fabricated stages.
        
        Parameters:
            threat_findings : list of alerts
            
        Returns:
            dict: Chain mapping of 6 stages and chronological progression log.
        """
        chain = {
            "Port Scan": {"matched": False},
            "Bruteforce": {"matched": False},
            "Credential Access": {"matched": False},
            "Lateral Movement": {"matched": False},
            "Collection": {"matched": False},
            "Exfiltration": {"matched": False}
        }

        if not threat_findings:
            return {
                "chain": chain,
                "progression": [],
                "graph_text": "No alerts detected."
            }

        # Sort threats chronologically
        sorted_threats = sorted(threat_findings, key=lambda x: x.get("timestamp", ""))
        
        progression = []
        matched_stages_set = set()

        for alert in sorted_threats:
            rule_name = alert.get("rule_name", "").lower()
            mitre_stages = alert.get("mitre_stages") or []
            timestamp = alert.get("timestamp")

            # Check matching against our 6 stages
            for stage_name, criteria in STAGE_CRITERIA.items():
                # Avoid duplicate matching for the same stage
                if chain[stage_name]["matched"]:
                    continue

                # Match by rule name keywords
                keyword_match = any(k in rule_name for k in criteria["keywords"])
                
                # Match by MITRE stage category
                stage_match = any(s in mitre_stages for s in criteria["stages"])
                
                # Special cases for certain built-in rule matches
                if stage_name == "Bruteforce" and "brute" in rule_name:
                    keyword_match = True
                if stage_name == "Port Scan" and "scan" in rule_name:
                    keyword_match = True

                if keyword_match or stage_match:
                    chain[stage_name] = {
                        "matched": True,
                        "alert_id": alert.get("alert_id"),
                        "rule_name": alert.get("rule_name"),
                        "timestamp": timestamp,
                        "severity": alert.get("severity", "low"),
                        "risk_score": alert.get("risk_score", 0)
                    }
                    
                    progression.append({
                        "stage": stage_name,
                        "timestamp": timestamp,
                        "rule_name": alert.get("rule_name"),
                        "risk_score": alert.get("risk_score", 0)
                    })
                    matched_stages_set.add(stage_name)

        # Generate a beautiful graphical chain text
        stages_order = ["Port Scan", "Bruteforce", "Credential Access", "Lateral Movement", "Collection", "Exfiltration"]
        graph_parts = []
        for s in stages_order:
            if chain[s]["matched"]:
                graph_parts.append(f"[{s}]")
            else:
                graph_parts.append(f"({s} - Not Observed)")
        
        graph_text = " -> ".join(graph_parts)

        return {
            "chain": chain,
            "progression": progression,
            "graph_text": graph_text,
            "stages_observed_count": len(matched_stages_set)
        }
