from datetime import datetime, timezone

class AttackerProfile:
    def __init__(self, src_ip, total_alerts=0, campaigns=None, predictions=None, highest_risk=0, first_seen=None, last_seen=None):
        self.src_ip = src_ip
        self.total_alerts = total_alerts
        self.campaigns = campaigns or []
        self.predictions = predictions or []
        self.highest_risk = highest_risk
        now_str = datetime.now(timezone.utc).isoformat()
        self.first_seen = first_seen or now_str
        self.last_seen = last_seen or now_str

    def to_dict(self):
        return {
            "src_ip": self.src_ip,
            "total_alerts": self.total_alerts,
            "campaigns": self.campaigns,
            "predictions": self.predictions,
            "highest_risk": self.highest_risk,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            src_ip=data.get("src_ip"),
            total_alerts=data.get("total_alerts", 0),
            campaigns=data.get("campaigns"),
            predictions=data.get("predictions"),
            highest_risk=data.get("highest_risk", 0),
            first_seen=data.get("first_seen"),
            last_seen=data.get("last_seen")
        )
