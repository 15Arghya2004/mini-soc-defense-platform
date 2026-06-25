import logging
from datetime import datetime

logger = logging.getLogger("sentrix.threat_engine.scoring.modifiers")

class RiskModifierEngine:
    def __init__(self):
        pass

    def apply_modifiers(self, base_score, context, event_timestamp=None, is_campaign=False) -> int:
        """
        Calculates and applies modifiers to base risk score.
        Caps final score at [0, 100].
        
        Parameters:
        -----------
        base_score : int — base risk score
        context : dict or AttackerContextProfile — attacker context profile
        event_timestamp : str or datetime — ISO timestamp or datetime object
        is_campaign : bool — whether event matches campaign rules
        """
        modifiers = 0
        
        # Get context dict
        if hasattr(context, "to_dict"):
            c_data = context.to_dict()
        else:
            c_data = context or {}
            
        alert_count = c_data.get("alert_count", 0)
        categories = c_data.get("categories_seen", [])
        campaign_count = c_data.get("campaign_count", 0)
        
        # 1. Repeated Offender
        if alert_count > 30:
            modifiers += 25
            logger.debug("[Modifier] Repeated Offender Tier 2 (+25)")
        elif alert_count > 10:
            modifiers += 15
            logger.debug("[Modifier] Repeated Offender Tier 1 (+15)")
            
        # 2. Off Hours Activity
        is_off_hours = False
        dt = None
        if event_timestamp:
            try:
                if isinstance(event_timestamp, str):
                    # Strip Z or offset if needed for basic iso format parsing
                    ts = event_timestamp
                    if ts.endswith("Z"):
                        ts = ts[:-1] + "+00:00"
                    dt = datetime.fromisoformat(ts)
                else:
                    dt = event_timestamp
            except Exception as e:
                logger.warning(f"Failed to parse timestamp {event_timestamp}: {e}")
                
        if not dt:
            dt = datetime.now()
            
        # Off hours is Hour < 9 or Hour >= 18
        if dt.hour < 9 or dt.hour >= 18:
            is_off_hours = True
            
        if is_off_hours:
            modifiers += 10
            logger.debug("[Modifier] Off Hours Activity (+10)")
            
        # 3. Multi Category Activity
        cat_count = len(categories)
        if cat_count >= 3:
            modifiers += 15
            logger.debug("[Modifier] Multi Category Tier 2 (+15)")
        elif cat_count == 2:
            modifiers += 10
            logger.debug("[Modifier] Multi Category Tier 1 (+10)")
            
        # 4. Campaign Participation
        if is_campaign or campaign_count > 0:
            modifiers += 20
            logger.debug("[Modifier] Campaign Participation (+20)")
            
        # Apply and clamp final score
        final_score = min(100, max(0, base_score + modifiers))
        logger.info(f"[ModifierEngine] Base: {base_score} -> Modified: {final_score} (+{modifiers} modifiers)")
        return final_score
