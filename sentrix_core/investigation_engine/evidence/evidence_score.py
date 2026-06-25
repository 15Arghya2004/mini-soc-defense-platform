import logging

logger = logging.getLogger("sentrix.investigation.evidence_score")

SEVERITY_WEIGHTS = {
    "critical": 90,
    "high": 75,
    "medium": 50,
    "low": 25,
    "informational": 10
}

class EvidenceScorer:
    def calculate_scores(self, threat_findings: list) -> dict:
        """
        Calculates mathematical scores for evidence strength and confidence.
        
        Parameters:
            threat_findings : list of alerts
            
        Returns:
            dict: Contains calculated strength and confidence integers
        """
        if not threat_findings:
            return {
                "strength": 0,
                "confidence": 0
            }

        total_alerts = len(threat_findings)
        
        # 1. Base Severity Weight Calculation
        severity_sum = 0
        for alert in threat_findings:
            sev = alert.get("severity", "low").lower()
            severity_sum += SEVERITY_WEIGHTS.get(sev, 25)
        
        base_strength = severity_sum / total_alerts if total_alerts > 0 else 25.0

        # 2. Additive Boosts
        # Alert Volume Boost: +3% for each alert, max +20%
        volume_boost = min(20, total_alerts * 3)
        
        # Unique Rule Diversity Boost: +4% for each unique rule triggered, max +20%
        unique_rules = {a.get("rule_name") for a in threat_findings if a.get("rule_name")}
        rule_boost = min(20, len(unique_rules) * 4)

        evidence_strength = min(99, base_strength + volume_boost + rule_boost)

        # 3. Confidence Calculation
        # Check explicit confidence_score inside alert payload
        conf_sum = sum(int(a.get("confidence_score", 0)) for a in threat_findings)
        avg_conf = conf_sum / total_alerts if total_alerts > 0 else 0.0

        if avg_conf > 0:
            confidence = avg_conf
        else:
            # Fallback based on unique rules count if not set in telemetry
            confidence = min(95, 60 + len(unique_rules) * 5)

        return {
            "strength": int(evidence_strength),
            "confidence": int(confidence)
        }
