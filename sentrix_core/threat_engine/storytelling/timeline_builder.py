class TimelineBuilder:
    def __init__(self):
        pass

    def build_timeline(self, matched_events):
        """Constructs a chronological description list of matched security events."""
        if not matched_events:
            return []

        # Sort events by timestamp
        sorted_events = sorted(matched_events, key=lambda x: x.get("timestamp", ""))
        timeline = []
        for idx, ev in enumerate(sorted_events):
            step = idx + 1
            ts = ev.get("timestamp")
            category = ev.get("event", {}).get("category", "unknown").upper()
            action = ev.get("event", {}).get("action", "activity")
            user = ev.get("user", {}).get("name", "system")
            host = ev.get("host", {}).get("hostname", "unknown")
            
            line = f"[{ts}] Step {step}: {category} Action '{action}' by user '{user}' on host '{host}'"
            timeline.append(line)

        return timeline
