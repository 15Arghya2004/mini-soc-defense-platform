class ExecutiveSummaryFormatter:
    def format(self, payload: dict) -> str:
        """
        Formats a non-technical summary explaining 'What exactly happened?'
        and its business impact for executives.
        """
        source_ip = payload.get("source_ip")
        severity = payload.get("severity", "LOW")
        host = payload.get("destination_host", "unknown")
        total_alerts = len(payload.get("threat_findings", []))
        behavior = payload.get("behavior_analysis", {})
        
        off_hours = behavior.get("off_hours_activity", {}).get("triggered", False)
        offender_tier = behavior.get("repeated_offender_tier", "New Attacker profile")
        risk_trend = behavior.get("risk_trend", "Stable")
        
        # Build narrative
        summary = (
            f"On host **{host}**, Sentrix identified threat activity rated at **{severity}** severity, "
            f"originating from source IP **{source_ip}**. A total of **{total_alerts}** alert signatures "
            f"were generated during the analysis window.\n\n"
            f"**Key Findings**:\n"
            f"- The threat actor is classified as a **{offender_tier}** with an **{risk_trend}** risk trend, "
            f"indicating persistent or accelerating attempts to compromise network assets.\n"
        )
        
        if off_hours:
            oh_pct = behavior.get("off_hours_activity", {}).get("off_hours_percentage", 0)
            summary += f"- A significant portion ({oh_pct}%) of the attack occurred outside standard business hours, a common tactic used to bypass active security monitoring teams.\n"
            
        multi_cat = behavior.get("multi_category_target", {})
        if multi_cat.get("categories_seen_count", 0) > 1:
            summary += f"- The attack was multi-staged, traversing {multi_cat.get('categories_seen_count')} unique tactical steps, proving structured intent rather than a random scan.\n"

        # General recommendation
        summary += (
            f"\n**Business Impact Assessment**:\n"
            f"Unmitigated progression of these techniques exposes key corporate data on host {host} to "
            f"potential credential theft, unauthorized access, and exfiltration. Immediate containment "
            f"playbooks have been recommended to isolate the source IP and preserve host integrity."
        )

        return summary
