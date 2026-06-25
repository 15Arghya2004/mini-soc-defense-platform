import threading

class RDFRegistry:
    def __init__(self):
        self._lock = threading.Lock()
        self._active_rules = {}

    def update_rules(self, new_rules):
        with self._lock:
            # Atomic pointer swap simulation (double buffering reload)
            self._active_rules = new_rules
            print(f"[Registry] Atomic Hot Reload completed. Active rules count: {len(self._active_rules)}")

    def get_rule(self, rule_id):
        with self._lock:
            return self._active_rules.get(rule_id)

    def get_all_rules(self):
        with self._lock:
            # Return copy to prevent mutations outside locks
            return list(self._active_rules.values())

    def get_rules_by_category(self, category):
        with self._lock:
            return [r for r in self._active_rules.values() if r.get("category") == category]
