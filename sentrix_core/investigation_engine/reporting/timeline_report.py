class TimelineReportFormatter:
    def format(self, timeline_payload: list) -> str:
        """
        Formats chronological timeline list into a Markdown table.
        """
        if not timeline_payload:
            return "*No chronological events recorded.*"

        table = (
            "| Time | Target Host | Rule Triggered | MITRE Technique | Risk Score | Response Action |\n"
            "|---|---|---|---|---|---|\n"
        )

        for event in timeline_payload:
            techs = ", ".join(event.get("mitre_techniques", []))
            if not techs:
                techs = "N/A"
            table += (
                f"| {event.get('time_display')} | {event.get('affected_host')} | "
                f"{event.get('rule_name')} | {techs} | {event.get('risk_score')}/100 | "
                f"{event.get('response_action')} |\n"
            )

        return table
