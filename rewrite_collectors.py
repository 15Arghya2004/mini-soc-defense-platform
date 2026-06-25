import os

base = r"C:\Users\15arg\OneDrive\Desktop\Sentrix_V6_Release\Sentrix_V7\sentrix_core\investigation_engine\collectors"

collectors = {
    "threat_collector.py": """
from sentrix_core.event_bus.bus import read_topic_events

class ThreatCollector:
    def __init__(self, db_path=None): pass
    def collect(self, source_ip: str) -> list:
        events = read_topic_events("threat.alerts", limit=50)
        return [e for e in events if e.get("source_ip") == source_ip]
""",
    "context_collector.py": """
class ContextCollector:
    def __init__(self, db_path=None): pass
    def collect(self, source_ip: str) -> dict:
        return {}
""",
    "campaign_collector.py": """
class CampaignCollector:
    def __init__(self, db_path=None): pass
    def collect(self, source_ip: str) -> list:
        return []
""",
    "prediction_collector.py": """
from sentrix_core.event_bus.bus import read_topic_events

class PredictionCollector:
    def __init__(self, db_path=None): pass
    def collect(self, source_ip: str) -> list:
        events = read_topic_events("prediction.forecasts", limit=50)
        return [e for e in events if e.get("target_ip") == source_ip]
""",
    "response_collector.py": """
from sentrix_core.event_bus.bus import read_topic_events

class ResponseCollector:
    def __init__(self, db_path=None): pass
    def collect(self, source_ip: str) -> list:
        events = read_topic_events("response.actions", limit=50)
        return [e for e in events if e.get("target") == source_ip]
""",
    "rule_studio_collector.py": """
class RuleStudioCollector:
    def __init__(self, db_path=None): pass
    def search_rules(self, query): return []
    def get_rule_by_id(self, rule_id): return None
"""
}

for name, content in collectors.items():
    with open(os.path.join(base, name), "w") as f:
        f.write(content.strip() + "\n")
print("Collectors rewritten.")
