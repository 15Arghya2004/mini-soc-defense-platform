import logging

logger = logging.getLogger("sentrix.investigation.escalation_analyzer")

class EscalationAnalyzer:
    def analyze(self, prediction_findings: dict) -> dict:
        """
        Parses threat forecasts to determine escalation trends and compromise likelihoods.
        
        Parameters:
            prediction_findings : dict from PredictionCollector.collect()
            
        Returns:
            dict: Escalation and compromise analysis
        """
        if not prediction_findings:
            return {
                "next_attack": "Unknown",
                "probability": 0,
                "confidence": 0,
                "escalation_forecast": "LOW",
                "compromise_probability": 0,
                "risk_level": "LOW",
                "status": "Stable"
            }

        next_attack = prediction_findings.get("next_attack", "Unknown")
        probability = prediction_findings.get("probability", 0)
        confidence = prediction_findings.get("confidence", 0)
        compromise_prob = prediction_findings.get("compromise_probability", 0)
        escalation_forecast = prediction_findings.get("escalation_forecast", "LOW")
        risk_level = prediction_findings.get("risk_level", "LOW")

        # Determine escalation state transition
        if risk_level == "CRITICAL" or escalation_forecast == "CRITICAL":
            status = "Immediate Escalation Risk"
        elif risk_level == "HIGH" or escalation_forecast == "HIGH":
            status = "High Escalation Risk"
        elif risk_level == "MEDIUM" or escalation_forecast == "MEDIUM":
            status = "Moderate Escalation Risk"
        else:
            status = "Stable"

        return {
            "next_attack": next_attack,
            "probability": probability,
            "confidence": confidence,
            "escalation_forecast": escalation_forecast,
            "compromise_probability": compromise_prob,
            "risk_level": risk_level,
            "status": status
        }
