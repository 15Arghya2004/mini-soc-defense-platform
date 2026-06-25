class AttackStoryGenerator:
    def __init__(self):
        pass

    def build_narrative(self, rule, triggering_events, risk_score, timeline=None):
        """Generates structured incident story summaries, technical details, risk justifications, and analyst guidance."""
        explanation = rule.get("explanation", {}) or rule
        summary = explanation.get("summary") or rule.get("description") or "A security anomaly was identified."
        tech_details = explanation.get("technical_details") or f"Rule matched conditions across {len(triggering_events)} event nodes."

        # MITRE Mapping
        mitre_mapping = rule.get("mitre_mapping") or rule.get("metadata", {}).get("mitre_attack") or []

        # Timeline
        if not timeline:
            timeline = [f"{ev.get('timestamp')}: Event matched action '{ev.get('event', {}).get('action')}'" for ev in triggering_events]

        # Analyst Notes
        analyst_notes = explanation.get("analyst_guidance") or "Validate process parameters. Inspect network connections from affected host. Verify user authentication status."

        story = {
            "summary": summary,
            "technical_details": tech_details,
            "risk_justification": f"Dynamic risk calculated at {risk_score}/100 using severity, asset criticality, threat intelligence context, and progression depth.",
            "timeline": timeline,
            "mitre_mapping": mitre_mapping,
            "analyst_notes": analyst_notes
        }
        return story
