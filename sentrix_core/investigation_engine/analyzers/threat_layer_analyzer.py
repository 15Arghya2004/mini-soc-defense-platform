import logging

logger = logging.getLogger("sentrix.investigation.threat_layer_analyzer")

class ThreatLayerAnalyzer:
    def analyze(self, threat_findings: list, context_findings: dict, 
                campaign_findings: list, prediction_findings: dict, 
                response_findings: dict, rule_studio_findings: list) -> dict:
        """
        Analyzes and explains how every Threat Engine layer contributed to the decision.
        
        Parameters:
            threat_findings      : list of alerts
            context_findings     : dict of context data
            campaign_findings    : list of campaign data
            prediction_findings  : dict of predictions
            response_findings    : dict of SOAR actions
            rule_studio_findings : list of rule studio config metadata
            
        Returns:
            dict: Layer trace analysis
        """
        # 1. Detection Layer Summary
        triggered_rules = [a.get("rule_name") for a in threat_findings]
        detection_desc = (
            f"Triggered {len(triggered_rules)} unique rules. "
            f"Highest severity was {max([a.get('severity', 'low') for a in threat_findings], key=lambda x: {'informational':0,'low':1,'medium':2,'high':3,'critical':4}.get(x.lower(), 0)) if threat_findings else 'low'}."
        )

        # 2. Correlation Layer Summary
        corr_count = 0
        sequences = 0
        chains = 0
        for a in threat_findings:
            matches = a.get("correlation_matches") or []
            corr_count += len(matches)
            # Infer sequence and chain matches from matching keywords
            rule_name = a.get("rule_name", "").lower()
            if "sequence" in rule_name or "timeline" in rule_name:
                sequences += 1
            if "chain" in rule_name or "progression" in rule_name:
                chains += 1

        correlation_desc = (
            f"Identified {corr_count} correlated events, {sequences} sequence match(es), "
            f"and {chains} active attack chain match(es) in threat telemetry."
        )

        # 3. Context Layer Summary
        alert_count = context_findings.get("alert_count", 0)
        risk_trend = context_findings.get("risk_trend", "Stable")
        context_desc = (
            f"Attacker has a history of {alert_count} alert(s) on the network. "
            f"The overall risk trend is currently classified as '{risk_trend}'."
        )

        # 4. Campaign Layer Summary
        in_campaign = len(campaign_findings) > 0
        campaign_desc = "Attacker activity does not match any classified threat actor campaign patterns."
        if in_campaign:
            primary = campaign_findings[0]
            campaign_desc = (
                f"Matched APT campaign pattern '{primary.get('campaign_id')}' "
                f"currently at stage '{primary.get('current_stage')}' (Risk score: {primary.get('current_risk')}/100)."
            )

        # 5. Prediction Layer Summary
        pred_dict = prediction_findings[0] if (isinstance(prediction_findings, list) and len(prediction_findings) > 0) else (prediction_findings or {})
        if isinstance(pred_dict, str):
            pred_dict = {}
        next_attack = pred_dict.get("next_attack", "Unknown")
        probability = pred_dict.get("probability", 0)
        escalation = pred_dict.get("escalation_forecast", "LOW")
        prediction_desc = (
            f"Forecasted next attack vector as '{next_attack}' with a probability of {probability}% "
            f"and escalation threshold forecast of '{escalation}'."
        )
 
        # 6. Response Layer Summary
        resp_dict = response_findings
        if isinstance(response_findings, list):
            resp_dict = {
                "executed": [r for r in response_findings if r.get("status") in ("success", "success_simulated")],
                "pending": [r for r in response_findings if r.get("status") == "pending"],
                "recommended": [r for r in response_findings if r.get("status") == "recommended"]
            }
        elif not isinstance(resp_dict, dict):
            resp_dict = {}
            
        executed = len(resp_dict.get("executed", []))
        pending = len(resp_dict.get("pending", []))
        recommended = len(resp_dict.get("recommended", []))
        response_desc = (
            f"SOAR response engine has executed {executed} action(s), "
            f"holds {pending} pending manual approval(s), and recommends {recommended} action(s)."
        )

        return {
            "detection_layer": {
                "summary": detection_desc,
                "triggered_rules": list(set(triggered_rules)),
                "rule_metadata": rule_studio_findings
            },
            "correlation_layer": {
                "summary": correlation_desc,
                "correlated_alerts_count": corr_count,
                "sequence_matches_count": sequences,
                "attack_chain_matches_count": chains
            },
            "context_layer": {
                "summary": context_desc,
                "alert_count": alert_count,
                "risk_trend": risk_trend,
                "categories_seen": context_findings.get("categories_seen", [])
            },
            "campaign_layer": {
                "summary": campaign_desc,
                "is_campaign_active": in_campaign,
                "active_campaigns": campaign_findings
            },
            "prediction_layer": {
                "summary": prediction_desc,
                "next_attack": next_attack,
                "probability": probability,
                "escalation_forecast": escalation
            },
            "response_layer": {
                "summary": response_desc,
                "executed_count": executed,
                "pending_count": pending,
                "recommended_count": recommended
            }
        }
