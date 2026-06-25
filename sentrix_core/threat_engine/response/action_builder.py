class SOARActionBuilder:
    def __init__(self):
        pass

    def build_actions(self, alert_payload, rule):
        """
        Compiles list of response actions.
        If the rule has no explicit response block, dynamically generates default playbooks based on severity.
        """
        response_config = rule.get("response", {})
        actions = []

        if response_config and "actions" in response_config:
            actions = response_config["actions"]
        else:
            # Fallback dynamic playbooks based on alert severity
            severity = str(alert_payload.get("severity", "medium")).lower()
            risk_score = alert_payload.get("risk_score", 50)
            
            # Ticketing and SOC notification are always generated
            actions.append({
                "action_type": "create_incident",
                "parameters": {"ticket_type": "security_alert"},
                "auto_execution": True,
                "approval_required": False
            })
            actions.append({
                "action_type": "notify_soc",
                "parameters": {"channel": "slack-alerts"},
                "auto_execution": True,
                "approval_required": False
            })

            # Containments for high/critical risks
            if severity == "critical" or risk_score >= 80:
                actions.append({
                    "action_type": "isolate_host",
                    "parameters": {"mode": "strict"},
                    "auto_execution": True,
                    "approval_required": False
                })
                actions.append({
                    "action_type": "kill_process",
                    "parameters": {"signal": "SIGKILL"},
                    "auto_execution": True,
                    "approval_required": False
                })
            elif severity == "high" or risk_score >= 60:
                actions.append({
                    "action_type": "block_ip",
                    "parameters": {"duration_minutes": 60},
                    "auto_execution": False,
                    "approval_required": True
                })
                actions.append({
                    "action_type": "disable_user",
                    "parameters": {"lock_duration_hours": 24},
                    "auto_execution": False,
                    "approval_required": True
                })

        return actions
