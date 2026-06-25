import time
import logging

try:
    from infrastructure.redis_cache import redis_client
except ImportError:
    redis_client = None

logger = logging.getLogger("sentrix.correlation.sequence")


class SequenceEngine:
    def __init__(self, cache_manager=None):
        self.cache_manager = cache_manager
        # Fallback buffer if no cache manager is provided
        self.states = {}

    def process_event(self, event, rule, matcher, session_key):
        """Evaluates multi-stage state machines over sliding time windows."""
        detection = rule.get("detection", {}) or rule
        corr = detection.get("correlation", {}) or rule.get("correlation", {})
        seq = corr.get("sequence") or rule.get("sequence")
        if not seq:
            return False, []

        rule_id = rule.get("rule_id") or rule.get("metadata", {}).get("id")
        window = corr.get("time_window_seconds", 60)
        now_ts = time.time()

        if self.cache_manager:
            current_state = self.cache_manager.get_sequence_state(rule_id, session_key)
        else:
            if rule_id not in self.states:
                self.states[rule_id] = {}
            current_state = self.states[rule_id].get(session_key)

        # Expire old states
        if current_state and now_ts > current_state["expires_at"]:
            if self.cache_manager:
                self.cache_manager.set_sequence_state(rule_id, session_key, None)
            else:
                self.states[rule_id].pop(session_key, None)
            current_state = None

        next_step_idx = 0 if not current_state else current_state["current_step"]

        if next_step_idx < len(seq):
            target_step = seq[next_step_idx]
            
            # Evaluate the conditions for this step
            if matcher.evaluate_rule(event, target_step):
                if not current_state:
                    # Start sequence state machine
                    new_state = {
                        "current_step": 1,
                        "matched_events": [event],
                        "expires_at": now_ts + window
                    }
                    if self.cache_manager:
                        self.cache_manager.set_sequence_state(rule_id, session_key, new_state)
                    else:
                        self.states[rule_id][session_key] = new_state
                    print(f"[Sequence] Sequence initiated for rule {rule_id} on key {session_key}")
                    
                    if len(seq) == 1:
                        if self.cache_manager:
                            self.cache_manager.set_sequence_state(rule_id, session_key, None)
                        else:
                            self.states[rule_id].pop(session_key, None)
                        return True, [event]
                else:
                    # Advance sequence state machine
                    current_state["current_step"] += 1
                    current_state["matched_events"].append(event)
                    current_state["expires_at"] = now_ts + window
                    
                    if self.cache_manager:
                        self.cache_manager.set_sequence_state(rule_id, session_key, current_state)
                    else:
                        self.states[rule_id][session_key] = current_state
                    
                    print(f"[Sequence] Sequence advanced for rule {rule_id} step {current_state['current_step']} on key {session_key}")

                    # Check if sequence completed
                    if current_state["current_step"] == len(seq):
                        matched_list = current_state["matched_events"]
                        if self.cache_manager:
                            self.cache_manager.set_sequence_state(rule_id, session_key, None)
                        else:
                            self.states[rule_id].pop(session_key, None)
                        return True, matched_list

        return False, []


class DistributedSequenceEngine:
    """
    Evaluates ordered sequence correlations across multiple distributed workers using Redis.
    """
    def __init__(self, cache, tenant_id="default"):
        self.cache = cache
        self.tenant_id = tenant_id
        self.r = redis_client
        self.prefix = f"tenant:{self.tenant_id}:sequence"

    def evaluate(self, event: dict, rule: dict) -> tuple[bool, list]:
        """
        Checks sequence progression in Redis.
        Returns (True, [matched_events]) if sequence completes, else (False, []).
        """
        if self.r is None:
            logger.warning("Redis client is not configured. DistributedSequenceEngine bypassed.")
            return False, []

        rule_id = rule.get("rule_id", rule.get("metadata", {}).get("id"))
        correlation = rule.get("correlation", {})
        
        if correlation.get("type") != "sequence":
            return False, []
            
        sequence = correlation.get("sequence", [])
        time_window = correlation.get("time_window_seconds", 300)
        group_by = correlation.get("group_by", ["source.ip"])

        group_vals = []
        for field in group_by:
            parts = field.split('.')
            val = event
            for p in parts:
                val = val.get(p, {}) if isinstance(val, dict) else val
            if isinstance(val, dict):
                val = "unknown"
            group_vals.append(str(val))

        group_key = ":".join(group_vals)
        state_key = f"{self.prefix}:{rule_id}:{group_key}"

        # Distributed lock to prevent race conditions across workers
        lock_name = f"lock:{state_key}"
        if not self.r.acquire_lock(lock_name, timeout=5):
            logger.warning(f"Failed to acquire lock for {state_key}")
            return False, []

        try:
            current_state = self.r.get_json(state_key) or {"step_index": 0, "events": []}
            current_step = current_state["step_index"]

            if current_step >= len(sequence):
                self.r.delete(state_key)
                return False, []

            step_def = sequence[current_step]
            
            action_matches = True
            if "action" in step_def:
                action_matches = event.get("event", {}).get("action") == step_def["action"]
            
            if action_matches:
                current_state["events"].append(event)
                current_state["step_index"] += 1
                
                if current_state["step_index"] == len(sequence):
                    self.r.delete(state_key)
                    return True, current_state["events"]
                else:
                    self.r.set_json(state_key, current_state, expire_seconds=time_window)
                    return False, []
            
            return False, []

        finally:
            self.r.release_lock(lock_name)
