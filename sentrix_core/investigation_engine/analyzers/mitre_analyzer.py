import logging

logger = logging.getLogger("sentrix.investigation.mitre_analyzer")

# Standard 14 MITRE tactics in kill chain order
MITRE_TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command & Control",
    "Exfiltration",
    "Impact"
]

class MitreAnalyzer:
    def analyze(self, threat_findings: list) -> dict:
        """
        Extracts MITRE mapping details and computes matrix coverage.
        
        Parameters:
            threat_findings : list of alerts
            
        Returns:
            dict: MITRE mapping metrics
        """
        techniques = set()
        stages = set()

        for alert in threat_findings:
            alert_techs = alert.get("mitre_techniques") or []
            alert_stages = alert.get("mitre_stages") or []

            for tech in alert_techs:
                if tech:
                    techniques.add(tech)
            for stage in alert_stages:
                if stage:
                    stages.add(stage)

        # Calculate coverage over 14 stages
        coverage_pct = (len(stages) / len(MITRE_TACTICS) * 100) if len(MITRE_TACTICS) > 0 else 0.0

        return {
            "mapped_techniques": sorted(list(techniques)),
            "mapped_stages": sorted(list(stages)),
            "total_techniques_count": len(techniques),
            "total_stages_count": len(stages),
            "matrix_coverage_percentage": round(coverage_pct, 1),
            "tactics_ordered": [t for t in MITRE_TACTICS if t in stages]
        }
