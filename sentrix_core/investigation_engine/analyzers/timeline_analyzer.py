from datetime import datetime
import logging

logger = logging.getLogger("sentrix.investigation.timeline_analyzer")

class TimelineAnalyzer:
    def analyze(self, threat_findings: list, response_findings: dict = None) -> list:
        """
        Sorts alerts chronologically and creates a detailed chronological timeline.
        
        Parameters:
            threat_findings   : list from ThreatCollector.collect()
            response_findings : dict from ResponseCollector.collect()
            
        Returns:
            list: Cron events list sorted by timestamp
        """
        if not threat_findings:
            return []

        # Sort threat findings by timestamp
        sorted_threats = sorted(threat_findings, key=lambda x: x.get("timestamp", ""))
        
        # Build response action dictionary by alert_id for fast correlation
        action_map = {}
        if response_findings:
            # Join executed, pending and recommended actions
            all_actions = (
                response_findings.get("executed", []) + 
                response_findings.get("pending", []) + 
                response_findings.get("recommended", [])
            )
            for act in all_actions:
                aid = act.get("alert_id")
                if aid:
                    action_map[aid] = act.get("action_type")

        timeline = []
        for alert in sorted_threats:
            # Resolve response action
            alert_id = alert.get("alert_id")
            action = action_map.get(alert_id) or "Log Only"
            
            # Format timestamp nicely (extract just HH:MM:SS if possible or keep full)
            raw_ts = alert.get("timestamp", "")
            time_str = raw_ts
            try:
                # Try parsing ISO timestamp
                dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                time_str = dt.strftime("%H:%M:%S")
            except Exception:
                pass

            timeline.append({
                "timestamp": raw_ts,
                "time_display": time_str,
                "rule_name": alert.get("rule_name"),
                "affected_host": alert.get("affected_host"),
                "mitre_techniques": alert.get("mitre_techniques") or [],
                "risk_score": alert.get("risk_score", 0),
                "response_action": action
            })

        return timeline
