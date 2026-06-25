class AttackPathReportFormatter:
    def format(self, attack_chain_payload: dict) -> str:
        """
        Formats the attack chain graph and progression log.
        """
        graph_text = attack_chain_payload.get("graph_text", "No path observed.")
        progression = attack_chain_payload.get("progression", [])

        report = (
            f"**Attack Path Graph**:\n"
            f"```text\n"
            f"{graph_text}\n"
            f"```\n\n"
            f"**Observed Stages Log**:\n"
        )

        if not progression:
            report += "*No stages observed on the network.*"
        else:
            for idx, step in enumerate(progression):
                report += f"{idx + 1}. **{step.get('stage')}** (Observed alert: *{step.get('rule_name')}*, Risk: {step.get('risk_score')}/100, Timestamp: {step.get('timestamp')})\n"

        return report
