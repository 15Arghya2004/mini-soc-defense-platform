from sentrix_core.event_bus.bus import read_topic_events

class ResponseCollector:
    def __init__(self, db_path=None): pass
    def collect(self, source_ip: str, affected_host: str = None, **kwargs) -> list:
        events = read_topic_events("response.actions", limit=50)
        targets = {source_ip, affected_host} - {None, ""}
        return [e for e in events if e.get("target") in targets]
