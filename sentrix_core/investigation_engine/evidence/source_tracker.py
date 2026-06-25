import logging

logger = logging.getLogger("sentrix.investigation.source_tracker")

class SourceTracker:
    def track_sources(self, threat_findings: list) -> dict:
        """
        Traces the log/alert source origins contributing to the evidence pool.
        
        Parameters:
            threat_findings : list of alerts
            
        Returns:
            dict: Counts of alerts per source system (suricata, wazuh, splunk, etc.)
        """
        source_counts = {}
        for alert in threat_findings:
            # 1. Look for explicit 'source' key in alert payload or raw alert
            raw_alert = alert.get("raw_alert") or {}
            source = alert.get("source") or raw_alert.get("source")
            
            if isinstance(source, dict):
                source_name = source.get("type") or source.get("name")
            else:
                source_name = str(source) if source else None

            # 2. Check rule name and categories if no explicit source
            if not source_name or source_name.lower() in ("unknown", "none"):
                rule_name = alert.get("rule_name", "").lower()
                if "suricata" in rule_name:
                    source_name = "suricata"
                elif "wazuh" in rule_name:
                    source_name = "wazuh"
                elif "sysmon" in rule_name:
                    source_name = "sysmon"
                elif "splunk" in rule_name:
                    source_name = "splunk"
                elif "filebeat" in rule_name:
                    source_name = "filebeat"
                elif "winlogbeat" in rule_name:
                    source_name = "winlogbeat"
                else:
                    source_name = "custom_agent"

            source_key = source_name.lower()
            source_counts[source_key] = source_counts.get(source_key, 0) + 1

        return {
            "source_distribution": source_counts,
            "unique_sources_count": len(source_counts),
            "sources_list": sorted(list(source_counts.keys()))
        }
