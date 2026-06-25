import logging

logger = logging.getLogger("sentrix.investigation.evidence_analyzer")

class EvidenceAnalyzer:
    def analyze(self, threat_findings: list) -> dict:
        """
        Computes the strength of evidence and confidence scores.
        
        Parameters:
            threat_findings : list of alerts
            
        Returns:
            dict: Evidence strength, confidence, counts of correlated alerts,
                  sources, and rules.
        """
        if not threat_findings:
            return {
                "evidence_strength": 0,
                "confidence": 0,
                "correlated_alerts": 0,
                "unique_sources_count": 0,
                "unique_sources": [],
                "supporting_rules_count": 0,
                "supporting_rules": []
            }

        total_alerts = len(threat_findings)
        
        # 1. Compute Confidence Score (average of alert confidence scores)
        conf_sum = sum(a.get("confidence_score", 0) for a in threat_findings)
        confidence = conf_sum / total_alerts if total_alerts > 0 else 0.0

        # 2. Compute Evidence Strength
        # Base is the maximum risk score of any alert seen
        max_risk = max(a.get("risk_score", 0) for a in threat_findings)
        # Add a volume boost: +2% for each alert after the first (up to +15% boost)
        volume_boost = min(15, (total_alerts - 1) * 2) if total_alerts > 1 else 0
        evidence_strength = min(99, max_risk + volume_boost)

        # 3. Correlated Events (count of alerts + correlation matches listed in alerts)
        corr_count = total_alerts
        for alert in threat_findings:
            matches = alert.get("correlation_matches") or []
            corr_count += len(matches)

        # 4. Unique Sources (e.g., suricata, wazuh, splunk)
        # Since source is not directly passed in alert payload, infer from rule category/name or use default fallback.
        # Let's check rule name to guess source if not explicitly defined.
        sources = set()
        for alert in threat_findings:
            rule_name = alert.get("rule_name", "").lower()
            if "suricata" in rule_name:
                sources.add("suricata")
            elif "wazuh" in rule_name:
                sources.add("wazuh")
            elif "sysmon" in rule_name:
                sources.add("sysmon")
            elif "splunk" in rule_name:
                sources.add("splunk")
            else:
                sources.add("agent")
        
        unique_sources = sorted(list(sources))

        # 5. Supporting Rules
        rules = set()
        for alert in threat_findings:
            rule_name = alert.get("rule_name")
            if rule_name:
                rules.add(rule_name)
        
        supporting_rules = sorted(list(rules))

        return {
            "evidence_strength": int(evidence_strength),
            "confidence": int(confidence),
            "correlated_alerts": corr_count,
            "unique_sources_count": len(unique_sources),
            "unique_sources": unique_sources,
            "supporting_rules_count": len(supporting_rules),
            "supporting_rules": supporting_rules
        }
