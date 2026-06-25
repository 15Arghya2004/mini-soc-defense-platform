import logging
from datetime import datetime, timezone
from .context_store import ContextStore
from .attacker_profile import AttackerContextProfile

logger = logging.getLogger("sentrix.threat_engine.context")

class ContextManager:
    def __init__(self, db_path=None):
        self.store = ContextStore(db_path=db_path)

    def update_context(self, src_ip, category, risk_score) -> AttackerContextProfile:
        profile = self.store.get_context(src_ip)
        now_str = datetime.now(timezone.utc).isoformat()
        
        if not profile:
            profile = AttackerContextProfile(src_ip=src_ip, first_seen=now_str)
            
        profile.alert_count += 1
        profile.last_seen = now_str
        
        # Normalize category
        norm_cat = str(category).strip().upper().replace(" ", "_").replace("-", "_")
        if norm_cat and norm_cat not in profile.categories_seen:
            profile.categories_seen.append(norm_cat)
            
        # Update risk history and trend
        profile.risk_history.append(int(risk_score))
        if len(profile.risk_history) > 5:
            profile.risk_history.pop(0)
            
        if len(profile.risk_history) >= 2:
            if profile.risk_history[-1] > profile.risk_history[-2]:
                profile.risk_trend = "Increasing"
            elif profile.risk_history[-1] < profile.risk_history[-2]:
                profile.risk_trend = "Decreasing"
            else:
                profile.risk_trend = "Stable"
        else:
            profile.risk_trend = "Stable"
            
        self.store.save_context(profile)
        return profile

    def get_context(self, src_ip) -> AttackerContextProfile:
        return self.store.get_context(src_ip)

    def increment_prediction_count(self, src_ip):
        profile = self.store.get_context(src_ip)
        if profile:
            profile.prediction_count += 1
            self.store.save_context(profile)
            return profile
        return None

    def increment_campaign_count(self, src_ip):
        profile = self.store.get_context(src_ip)
        if profile:
            profile.campaign_count += 1
            self.store.save_context(profile)
            return profile
        return None
