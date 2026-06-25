"""
sentrix_core/ai_layer/tasks.py
AI Task Functions.
"""
import json
from sentrix_core.ai_layer.provider import get_ai_provider

def generate_executive_summary(report_data: dict) -> str:
    provider = get_ai_provider()
    prompt = f"Summarize this cybersecurity incident report for an executive audience:\n\n{json.dumps(report_data, indent=2)}"
    sys_prompt = "You are a CISO-level security analyst. Keep the summary under 150 words, focusing on risk, business impact, and resolution status."
    
    ai_text = provider.generate_text(prompt, sys_prompt)
    if ai_text and "disabled" not in ai_text.lower():
        return ai_text
        
    # Fallback
    sev = report_data.get("severity", "UNKNOWN")
    ip = report_data.get("source_ip", "UNKNOWN")
    return f"Incident involving {ip} resulted in {sev} severity alert. Manual review required."

def generate_threat_narrative(alert_data: dict) -> str:
    provider = get_ai_provider()
    prompt = f"Create a technical threat narrative based on this alert:\n\n{json.dumps(alert_data, indent=2)}"
    sys_prompt = "You are a SOC analyst. Provide a clear, chronological narrative of the attack."
    
    ai_text = provider.generate_text(prompt, sys_prompt)
    if ai_text and "disabled" not in ai_text.lower():
        return ai_text
        
    return alert_data.get("attack_story", "Narrative unavailable.")

def generate_remediation(findings_data: dict) -> list:
    provider = get_ai_provider()
    prompt = f"Provide 3 step-by-step remediation actions for these findings:\n\n{json.dumps(findings_data, indent=2)}"
    sys_prompt = "You are an incident responder. Output the response as a simple JSON array of strings. Do not include markdown blocks."
    
    ai_text = provider.generate_text(prompt, sys_prompt)
    if ai_text and "disabled" not in ai_text.lower():
        try:
            # Try to parse the JSON array if the model actually returned JSON
            import ast
            if ai_text.startswith("[") and ai_text.endswith("]"):
                return ast.literal_eval(ai_text)
            else:
                return [ai_text]
        except Exception:
            return [ai_text]
            
    return ["Isolate the affected host.", "Block the source IP.", "Reset compromised credentials."]
