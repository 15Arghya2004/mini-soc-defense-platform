import json
from datetime import datetime, timezone

class AttackerContextProfile:
    def __init__(self, src_ip, first_seen=None, last_seen=None, alert_count=0, categories_seen=None, campaign_count=0, risk_trend="Stable", prediction_count=0, risk_history=None):
        self.src_ip = src_ip
        now_str = datetime.now(timezone.utc).isoformat()
        self.first_seen = first_seen or now_str
        self.last_seen = last_seen or now_str
        self.alert_count = alert_count
        self.categories_seen = categories_seen or []
        self.campaign_count = campaign_count
        self.risk_trend = risk_trend
        self.prediction_count = prediction_count
        self.risk_history = risk_history or []

    def to_dict(self):
        return {
            "src_ip": self.src_ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "alert_count": self.alert_count,
            "categories_seen": self.categories_seen,
            "campaign_count": self.campaign_count,
            "risk_trend": self.risk_trend,
            "prediction_count": self.prediction_count,
            "risk_history": self.risk_history
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            src_ip=data.get("src_ip"),
            first_seen=data.get("first_seen"),
            last_seen=data.get("last_seen"),
            alert_count=data.get("alert_count", 0),
            categories_seen=data.get("categories_seen"),
            campaign_count=data.get("campaign_count", 0),
            risk_trend=data.get("risk_trend", "Stable"),
            prediction_count=data.get("prediction_count", 0),
            risk_history=data.get("risk_history")
        )
