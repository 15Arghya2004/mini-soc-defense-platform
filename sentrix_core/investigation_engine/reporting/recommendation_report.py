class RecommendationReportFormatter:
    def format(self, response_findings: dict) -> str:
        """
        Formats recommendations and containment playbook actions into structured lists.
        """
        executed = response_findings.get("executed", [])
        pending = response_findings.get("pending", [])
        recommended = response_findings.get("recommended", [])

        report = "### Containment & Remediation Playbooks\n\n"

        # 1. Executed actions
        report += "#### 1. Executed Actions (Automated Containment)\n"
        if not executed:
            report += "*No automated response playbooks were executed.*\n\n"
        else:
            for act in executed:
                report += f"- **{act.get('action_type').upper()}** executed against target `{act.get('target')}` (Gate: `{act.get('gate')}`, Time: `{act.get('timestamp')}`)\n"
            report += "\n"

        # 2. Pending Actions (Awaiting Analyst Gate Approval)
        report += "#### 2. Actions Awaiting SOC Approval\n"
        if not pending:
            report += "*No response actions are currently pending approval.*\n\n"
        else:
            for act in pending:
                report += f"- **[AWAITING APPROVAL] {act.get('action_type').upper()}** against target `{act.get('target')}` (Reason: Gate threshold restriction)\n"
            report += "\n"

        # 3. Recommended Manual Containment
        report += "#### 3. Recommended Manual Actions\n"
        if not recommended:
            report += "*No manual recommendations generated.*\n\n"
        else:
            for act in recommended:
                report += f"- **{act.get('action_type').upper()}** against target `{act.get('target')}` (Rationale: Block source telemetry/actor access)\n"
            report += "\n"

        # 4. Analyst Action Checklist
        report += (
            "#### 4. SOC Analyst Next-Step Checklist\n"
            "1. [ ] **Verify Host Isolation**: Check if the host isolation command completed successfully.\n"
            "2. [ ] **Approve Pending SOAR Gates**: Inspect the pending action queue and approve block/isolate playbooks if appropriate.\n"
            "3. [ ] **Collect Forensic Evidence**: Retrieve local process memory dumps and security logs for target processes.\n"
            "4. [ ] **Validate Rule Adjustments**: Check if any dynamic rule studio tuning or notes update is required.\n"
        )

        return report
