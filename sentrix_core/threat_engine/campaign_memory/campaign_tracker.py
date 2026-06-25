import logging
from datetime import datetime, timezone
from .campaign_store import CampaignStore

logger = logging.getLogger("sentrix.threat_engine.campaign_memory")

try:
    from models.mitre_campaign_patterns import MitreCampaignClassifier
except ImportError:
    class MitreCampaignClassifier:
        def classify(self, stages):
            # In-situ simplified fallback
            stages_set = set(stages)
            if "Impact" in stages_set:
                return {"likely_campaign": "Ransomware"}
            if "Exfiltration" in stages_set and "Collection" in stages_set:
                return {"likely_campaign": "Insider_Threat"}
            return {"likely_campaign": "Unknown"}

class CampaignTracker:
    def __init__(self, db_path=None):
        self.store = CampaignStore(db_path=db_path)
        self.classifier = MitreCampaignClassifier()

    def update_campaign(self, src_ip, stage, risk_score) -> dict:
        campaign = self.store.get_active_campaign_for_ip(src_ip)
        
        # Determine stages history
        if campaign:
            hist = list(campaign["historical_stages"])
            c_id = campaign["campaign_id"]
        else:
            hist = []
            c_id = None
            
        if stage and stage not in hist:
            hist.append(stage)
            
        # Classify campaign type
        classification = self.classifier.classify(hist)
        camp_type = classification.get("likely_campaign", "Unknown")
        
        # Build or verify campaign ID
        expected_cid = f"camp-{src_ip}-{camp_type.lower().replace(' ', '_')}"
        if not c_id:
            c_id = expected_cid
        elif c_id.endswith("-unknown") and camp_type != "Unknown":
            # Upgrade campaign ID if now classified
            c_id = expected_cid
            
        if not campaign:
            campaign = {
                "campaign_id": c_id,
                "src_ip": src_ip,
                "current_stage": stage,
                "historical_stages": hist,
                "current_risk": int(risk_score),
                "predicted_next_stage": "Unknown"
            }
        else:
            campaign["campaign_id"] = c_id
            campaign["current_stage"] = stage
            campaign["historical_stages"] = hist
            campaign["current_risk"] = max(campaign["current_risk"], int(risk_score))
            
        self.store.save_campaign(campaign)
        return campaign

    def get_active_campaign(self, src_ip) -> dict:
        return self.store.get_active_campaign_for_ip(src_ip)

    def update_prediction(self, src_ip, predicted_next_stage):
        campaign = self.store.get_active_campaign_for_ip(src_ip)
        if campaign:
            campaign["predicted_next_stage"] = predicted_next_stage
            self.store.save_campaign(campaign)
            return campaign
        return None
