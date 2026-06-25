class EvidenceReportFormatter:
    def format(self, payload: dict) -> str:
        """
        Formats evidence summary details.
        """
        scores = payload.get("evidence_scores", {})
        evidence = payload.get("evidence_analysis", {})
        sources = payload.get("sources_map", {})

        report = (
            f"**Evidence Strength**: {scores.get('strength', 0)}%\n\n"
            f"**Confidence**: {scores.get('confidence', 0)}%\n\n"
            f"**Correlated Alerts**: {evidence.get('correlated_alerts', 0)}\n\n"
            f"**Unique Sources**: {evidence.get('unique_sources_count', 0)} ({', '.join(evidence.get('unique_sources', []))})\n\n"
            f"**Supporting Rules**: {evidence.get('supporting_rules_count', 0)}\n"
        )
        
        # Add source system distribution details
        source_dist = sources.get("source_distribution", {})
        if source_dist:
            report += "\n**Source Distribution Log**:\n"
            for src, cnt in source_dist.items():
                report += f"- **{src.upper()}**: {cnt} alert(s) logged\n"

        return report
