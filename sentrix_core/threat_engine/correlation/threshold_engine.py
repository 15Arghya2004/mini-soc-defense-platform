import time
import logging

try:
    from infrastructure.redis_cache import redis_client
except ImportError:
    redis_client = None

logger = logging.getLogger("sentrix.correlation.threshold")


class ThresholdEngine:
    def __init__(self, cache_manager=None):
        self.cache_manager = cache_manager
        # Fallback buffer if no cache manager is provided
        self.buffers = {}

    def process_event(self, event, rule, matcher, session_key):
        """Processes event frequency count aggregations within a sliding window."""
        detection = rule.get("conditions", {}) or rule.get("detection", {}).get("conditions", {})
        corr = rule.get("thresholds") or rule.get("detection", {}).get("correlation", {}).get("threshold") or rule.get("correlation", {}).get("threshold")
        if not corr:
            return False, []

        rule_id = rule.get("rule_id") or rule.get("metadata", {}).get("id")
        now_ts = time.time()
        window = corr.get("time_window_seconds", 60)
        count_limit = corr.get("count", 10)
        uniq_field = corr.get("unique_values_for")

        # Resolve buffer storage (either central cache or local state)
        if self.cache_manager:
            history = self.cache_manager.get_threshold_state(rule_id, session_key)
        else:
            if rule_id not in self.buffers:
                self.buffers[rule_id] = {}
            if session_key not in self.buffers[rule_id]:
                self.buffers[rule_id][session_key] = []
            history = self.buffers[rule_id][session_key]

        # Extract unique value if configured
        uniq_val = None
        if uniq_field:
            uniq_val = matcher.get_field_value(event, uniq_field)

        history.append((now_ts, uniq_val, event))

        # Clean expired events from sliding window
        history = [x for x in history if now_ts - x[0] <= window]

        # Save buffer state
        if self.cache_manager:
            self.cache_manager.set_threshold_state(rule_id, session_key, history)
        else:
            self.buffers[rule_id][session_key] = history

        # Evaluate threshold triggers
        if uniq_field:
            unique_set = {x[1] for x in history if x[1] is not None}
            if len(unique_set) >= count_limit:
                matched_events = [x[2] for x in history]
                # Reset buffer on trigger to prevent double alert firing
                if self.cache_manager:
                    self.cache_manager.set_threshold_state(rule_id, session_key, [])
                else:
                    self.buffers[rule_id][session_key] = []
                return True, matched_events
        else:
            if len(history) >= count_limit:
                matched_events = [x[2] for x in history]
                if self.cache_manager:
                    self.cache_manager.set_threshold_state(rule_id, session_key, [])
                else:
                    self.buffers[rule_id][session_key] = []
                return True, matched_events

        return False, []


class DistributedThresholdEngine:
    """
    Evaluates threshold correlations across multiple distributed workers using Redis.
    """
    def __init__(self, cache, tenant_id="default"):
        self.cache = cache
        self.tenant_id = tenant_id
        self.r = redis_client
        self.prefix = f"tenant:{self.tenant_id}:threshold"

    def evaluate(self, event: dict, rule: dict) -> bool:
        """
        Increments the counter in Redis. If threshold is met, returns True.
        """
        if self.r is None:
            logger.warning("Redis client is not configured. DistributedThresholdEngine bypassed.")
            return False

        rule_id = rule.get("rule_id", rule.get("metadata", {}).get("id"))
        correlation = rule.get("correlation", {})
        
        if correlation.get("type") != "threshold":
            return False
            
        threshold = correlation.get("threshold", 5)
        time_window = correlation.get("time_window_seconds", 60)
        group_by = correlation.get("group_by", ["source.ip"])

        # Extract grouping values to form a unique key
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
        counter_key = f"{self.prefix}:{rule_id}:{group_key}"

        # Atomic increment and expire
        with self.r.client.pipeline() as pipe:
            pipe.incr(counter_key)
            pipe.ttl(counter_key)
            results = pipe.execute()
            
            count = results[0]
            ttl = results[1]
            
            if ttl == -1 or ttl == -2:
                self.r.client.expire(counter_key, time_window)

        if count >= threshold:
            self.r.delete(counter_key)
            return True

        return False
