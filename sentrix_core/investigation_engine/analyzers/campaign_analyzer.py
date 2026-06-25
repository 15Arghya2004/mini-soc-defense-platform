import logging

logger = logging.getLogger("sentrix.investigation.campaign_analyzer")

class CampaignAnalyzer:
    def analyze(self, campaign_findings: list) -> dict:
        """
        Processes campaign tracking data to identify target threat actor campaigns.
        
        Parameters:
            campaign_findings : list from CampaignCollector.collect()
            
        Returns:
            dict: Campaign summary details
        """
        if not campaign_findings:
            return {
                "in_campaign": False,
                "campaign_id": "N/A",
                "current_stage": "N/A",
                "historical_stages": [],
                "current_risk": 0,
                "predicted_next_stage": "N/A",
                "campaigns_count": 0,
                "all_campaigns": []
            }

        # Use the latest updated campaign as primary
        sorted_camps = sorted(campaign_findings, key=lambda x: x.get("last_updated", ""), reverse=True)
        primary = sorted_camps[0]

        return {
            "in_campaign": True,
            "campaign_id": primary.get("campaign_id"),
            "current_stage": primary.get("current_stage"),
            "historical_stages": primary.get("historical_stages") or [],
            "current_risk": primary.get("current_risk", 0),
            "predicted_next_stage": primary.get("predicted_next_stage", "Unknown"),
            "campaigns_count": len(campaign_findings),
            "all_campaigns": sorted_camps
        }
