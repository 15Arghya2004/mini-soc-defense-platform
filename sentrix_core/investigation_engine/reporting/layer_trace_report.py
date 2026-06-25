class LayerTraceReportFormatter:
    def format(self, layer_trace_payload: dict) -> dict:
        """
        Formats each layer's contribution to decision logic.
        
        Returns:
            dict: Formatted trace string sections (detection, correlation, context, campaign, prediction, response)
        """
        dt = layer_trace_payload.get("detection_layer", {})
        co = layer_trace_payload.get("correlation_layer", {})
        cx = layer_trace_payload.get("context_layer", {})
        ca = layer_trace_payload.get("campaign_layer", {})
        pr = layer_trace_payload.get("prediction_layer", {})
        re = layer_trace_payload.get("response_layer", {})

        # 1. Detection
        det_str = f"**Summary**: {dt.get('summary')}\n\n**Triggered Signature rules**:\n"
        for r in dt.get("triggered_rules", []):
            det_str += f"- `{r}`\n"
        
        # 2. Correlation
        corr_str = (
            f"**Summary**: {co.get('summary')}\n\n"
            f"- Mapped Correlation Alerts: {co.get('correlated_alerts_count')}\n"
            f"- Active Sequences Logged: {co.get('sequence_matches_count')}\n"
            f"- Reconstructed Chain Hops: {co.get('attack_chain_matches_count')}\n"
        )

        # 3. Context
        ctx_str = (
            f"**Summary**: {cx.get('summary')}\n\n"
            f"- Alert count from context: {cx.get('alert_count')}\n"
            f"- Attacker Risk Trend: **{cx.get('risk_trend')}**\n"
            f"- Targeted Categories: {', '.join(cx.get('categories_seen', [])) if cx.get('categories_seen') else 'None'}\n"
        )

        # 4. Campaign
        camp_str = f"**Summary**: {ca.get('summary')}\n"
        if ca.get("is_campaign_active"):
            camp_str += "\n**Active Campaign Logs**:\n"
            for camp in ca.get("active_campaigns", []):
                camp_str += f"- Campaign ID: `{camp.get('campaign_id')}` (Current stage: **{camp.get('current_stage')}**, risk: {camp.get('current_risk')}/100)\n"

        # 5. Prediction
        pred_str = (
            f"**Summary**: {pr.get('summary')}\n\n"
            f"- Forecasted next attack: **{pr.get('next_attack')}**\n"
            f"- Transition Probability: **{pr.get('probability')}%**\n"
            f"- Escalation Trend Forecast: **{pr.get('escalation_forecast')}**\n"
        )

        # 6. Response
        resp_str = (
            f"**Summary**: {re.get('summary')}\n\n"
            f"- Playbooks executed: {re.get('executed_count')}\n"
            f"- Playbooks awaiting analyst approval: {re.get('pending_count')}\n"
            f"- Playbooks recommended: {re.get('recommended_count')}\n"
        )

        return {
            "detection": det_str,
            "correlation": corr_str,
            "context": ctx_str,
            "campaign": camp_str,
            "prediction": pred_str,
            "response": resp_str
        }
