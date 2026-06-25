from sentrix_core.event_bus.bus import read_topic_events

class ThreatCollector:
    def __init__(self, db_path=None): pass
    def collect(self, source_ip: str) -> list:
        events = read_topic_events("threat.alerts", limit=50)
        return [e for e in events if e.get("source_ip") == source_ip]
