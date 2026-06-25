class AnalystSummaryFormatter:
    def format(self, payload: dict) -> str:
        """
        Formats a technical summary of the incident for SOC analysts.
        """
        threats = payload.get("threat_findings", [])
        rules_hits = {}
        for t in threats:
            rname = t.get("rule_name", "Unknown Rule")
            rules_hits[rname] = rules_hits.get(rname, 0) + 1

        summary = (
            f"### Technical Brief\n"
            f"Sentrix correlated **{len(threats)}** alert(s) for this attacker IP.\n\n"
            f"#### Signature Distribution:\n"
        )
        
        for rule, count in rules_hits.items():
            summary += f"- **{rule}**: Triggered {count} time(s)\n"

        summary += (
            f"\n#### Threat Intel Context:\n"
            f"- Attacker Profile Risk Tier: **{payload.get('prediction_analysis', {}).get('risk_level', 'LOW')}**\n"
            f"- Next Stage Forecast: **{payload.get('prediction_analysis', {}).get('next_attack', 'Unknown')}** (probability: {payload.get('prediction_analysis', {}).get('probability', 0)}%)\n"
            f"- Host Compromise Likelihood: **{payload.get('prediction_analysis', {}).get('compromise_probability', 0)}%**\n"
        )

        return summary
