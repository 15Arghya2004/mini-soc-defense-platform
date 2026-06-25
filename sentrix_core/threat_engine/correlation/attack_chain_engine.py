class AttackChainEngine:
    def __init__(self):
        # Maps event action strings or category identifiers to attack progression stages (1 to 6)
        self.progression_stages = {
            # 1. Reconnaissance
            "dns-query": 1,
            "ping": 1,
            "host-discovery": 1,
            
            # 2. Port Scan / Recon
            "connection-attempt": 2,
            "port-scan": 2,
            "host-scan": 2,
            
            # 3. Web Exploitation (SQL Injection / XSS)
            "sql-injection": 3,
            "xss": 3,
            "http-request": 3,
            
            # 4. Web Shell Upload / Core Execution
            "web-shell-upload": 4,
            "command-injection": 4,
            "reverse-shell": 4,
            
            # 5. Privilege Escalation / Lateral Movement
            "privilege-escalation": 5,
            "lateral-movement": 5,
            "process-created": 5,
            
            # 6. Data Exfiltration
            "data-exfiltration": 6,
            "outbound-leak": 6
        }

    def get_event_progression_level(self, event):
        """Resolves the attack chain stage index for a given event based on action/category."""
        action = str(event.get("event", {}).get("action", "")).lower()
        category = str(event.get("event", {}).get("category", "")).lower()

        # Try matching action first
        for key, stage in self.progression_stages.items():
            if key in action:
                return stage

        # Fallback to category mapping
        if category == "network":
            return 2  # Scan / network tier
        elif category == "process":
            return 5  # Execution / PrivEsc tier
        elif category == "authentication":
            return 4  # Access tier
        elif category == "file":
            return 4  # Shell/persistence tier

        return 1

    def get_progression_score(self, matched_events):
        """Calculates the progression depth score (0-100) based on the highest stage reached."""
        if not matched_events:
            return 0

        max_stage = 1
        for ev in matched_events:
            stage = self.get_event_progression_level(ev)
            if stage > max_stage:
                max_stage = stage

        # Scale stage (1 to 6) to progression score (0 to 100)
        # Stage 1 = 15, Stage 2 = 30, Stage 3 = 50, Stage 4 = 70, Stage 5 = 85, Stage 6 = 100
        score_mapping = {
            1: 15,
            2: 30,
            3: 50,
            4: 70,
            5: 85,
            6: 100
        }
        return score_mapping.get(max_stage, 15)

    def build_chain_timeline(self, matched_events):
        """Sorts and generates formatted chronological progression description lists."""
        sorted_events = sorted(matched_events, key=lambda x: x.get("timestamp", ""))
        timeline = []
        
        for idx, ev in enumerate(sorted_events):
            step = idx + 1
            category = ev.get("event", {}).get("category", "unknown")
            action = ev.get("event", {}).get("action", "activity")
            user = ev.get("user", {}).get("name", "system")
            host = ev.get("host", {}).get("hostname", "unknown host")
            stage_idx = self.get_event_progression_level(ev)
            
            log_desc = f"Stage {step} (Progression Level {stage_idx}): [{category.upper()}] '{action}' performed by user '{user}' on host '{host}'."
            timeline.append(log_desc)
            
        return timeline
