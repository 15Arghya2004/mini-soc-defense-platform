from datetime import datetime
import logging

logger = logging.getLogger("sentrix.investigation.attacker_behavior_analyzer")

class AttackerBehaviorAnalyzer:
    def analyze(self, context_findings: dict, threat_findings: list) -> dict:
        """
        Analyzes attacker behavioral characteristics and risk patterns.
        
        Parameters:
            context_findings : dict from ContextCollector.collect()
            threat_findings  : list from ThreatCollector.collect()
            
        Returns:
            dict: Attacker behavior analysis
        """
        alert_count = context_findings.get("alert_count", len(threat_findings))
        risk_trend = context_findings.get("risk_trend", "Stable")
        
        # 1. Determine alert volume classification
        if alert_count > 30:
            volume_class = "Critical"
        elif alert_count > 10:
            volume_class = "High"
        elif alert_count > 0:
            volume_class = "Medium"
        else:
            volume_class = "Low"

        # 2. Check for Off-Hours Activity (Standard Working Hours: 09:00 - 18:00)
        off_hours_alerts = 0
        total_time_alerts = 0
        for alert in threat_findings:
            raw_ts = alert.get("timestamp")
            if not raw_ts:
                continue
            total_time_alerts += 1
            try:
                # Parse timestamp to isolate hour
                dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                hour = dt.hour
                if hour < 9 or hour > 18:
                    off_hours_alerts += 1
            except Exception:
                pass
        
        has_off_hours = (off_hours_alerts > 0)
        off_hours_pct = (off_hours_alerts / total_time_alerts * 100) if total_time_alerts > 0 else 0.0

        # 3. Determine Multi-Category Target status
        unique_categories = set()
        for alert in threat_findings:
            stages = alert.get("mitre_stages") or []
            for s in stages:
                unique_categories.add(s)
        
        category_count = len(unique_categories)
        if category_count >= 3:
            multi_cat_status = "Advanced Multi-Stage Target"
        elif category_count >= 2:
            multi_cat_status = "Multi-Stage Target"
        else:
            multi_cat_status = "Single Stage Focus"

        # 4. Repeated Offender classification
        if alert_count >= 30:
            offender_tier = "Critical Repeated Offender"
        elif alert_count >= 10:
            offender_tier = "Repeated Offender"
        else:
            offender_tier = "New Attacker profile"

        return {
            "alert_volume": volume_class,
            "total_alerts": alert_count,
            "risk_trend": risk_trend,
            "off_hours_activity": {
                "triggered": has_off_hours,
                "off_hours_count": off_hours_alerts,
                "off_hours_percentage": round(off_hours_pct, 1)
            },
            "multi_category_target": {
                "status": multi_cat_status,
                "categories_seen_count": category_count,
                "categories": list(unique_categories)
            },
            "repeated_offender_tier": offender_tier
        }
