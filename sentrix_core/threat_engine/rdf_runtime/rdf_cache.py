import time
import logging
from collections import OrderedDict

try:
    from infrastructure.redis_cache import redis_client
except ImportError:
    redis_client = None
    import json  # will be needed if redis is ever dynamically loaded but we import here just in case

logger = logging.getLogger("sentrix.rdf_cache")


class LRUTTLCache:
    def __init__(self, capacity=5000, ttl_seconds=300):
        self.cache = OrderedDict()
        self.capacity = capacity
        self.ttl = ttl_seconds

    def get(self, key):
        if key not in self.cache:
            return None
        
        val, expiry = self.cache[key]
        if time.time() > expiry:
            del self.cache[key]
            return None
            
        # Move key to the end (most recently used)
        self.cache.move_to_end(key)
        return val

    def set(self, key, value):
        if key in self.cache:
            del self.cache[key]
        elif len(self.cache) >= self.capacity:
            # Pop the first element (least recently used)
            self.cache.popitem(last=False)
            
        expiry = time.time() + self.ttl
        self.cache[key] = (value, expiry)

    def delete(self, key):
        self.cache.pop(key, None)

    def clear(self):
        self.cache.clear()


class RDFRuleCache:
    def __init__(self):
        # Cache for flat rule structures
        self.rules_cache = {}
        self.behavioral_rules = []

        # Cache for threat correlation session states (Threshold and Sequence engines)
        self.threshold_state_cache = LRUTTLCache(capacity=10000, ttl_seconds=300)
        self.sequence_state_cache = LRUTTLCache(capacity=10000, ttl_seconds=300)

        # Context lookups cache
        self.context_cache = LRUTTLCache(capacity=20000, ttl_seconds=600)

    def load_rules(self, new_rules):
        """Loads and pre-compiles rule maps during load or hot reload."""
        self.rules_cache = new_rules
        
        # Categorize behavioral rules
        self.behavioral_rules = []
        for r_id, r in new_rules.items():
            if r.get("mode") == "behavioral" or "anomaly_type" in r:
                self.behavioral_rules.append(r)

    def get_rule(self, rule_id):
        return self.rules_cache.get(rule_id)

    def get_behavioral_rules(self):
        return self.behavioral_rules

    # Threshold state helpers
    def get_threshold_state(self, rule_id, session_key):
        cache_key = f"{rule_id}:{session_key}"
        res = self.threshold_state_cache.get(cache_key)
        return res if res is not None else []

    def set_threshold_state(self, rule_id, session_key, state):
        cache_key = f"{rule_id}:{session_key}"
        self.threshold_state_cache.set(cache_key, state)

    # Sequence state helpers
    def get_sequence_state(self, rule_id, session_key):
        cache_key = f"{rule_id}:{session_key}"
        return self.sequence_state_cache.get(cache_key)

    def set_sequence_state(self, rule_id, session_key, state):
        cache_key = f"{rule_id}:{session_key}"
        if state is None:
            self.sequence_state_cache.delete(cache_key)
        else:
            self.sequence_state_cache.set(cache_key, state)

    # Context cache helpers
    def get_context(self, ip_or_domain):
        return self.context_cache.get(ip_or_domain)

    def set_context(self, ip_or_domain, data):
        self.context_cache.set(ip_or_domain, data)

    def clear_correlation_states(self):
        """Clears buffers on rule hot reloading."""
        self.threshold_state_cache.clear()
        self.sequence_state_cache.clear()
        self.context_cache.clear()
        print("[Cache] Flushed all correlation and context caches due to hot reload.")


class DistributedRDFRuleCache:
    """
    Adapter that mimics RDFRuleCache but stores everything in Redis.
    Ensures horizontal scaling for all Detection and Correlation workers.
    """
    def __init__(self, tenant_id="default"):
        self.tenant_id = tenant_id
        self.r = redis_client
        self.prefix = f"tenant:{self.tenant_id}:rules"

    def load_rules(self, rules: list):
        """Replaces all rules in Redis"""
        if self.r is None:
            logger.warning("Redis client not configured. DistributedRDFRuleCache bypass.")
            return

        import json
        logger.info(f"Loading {len(rules)} rules into Redis for tenant {self.tenant_id}")
        pipe_key = f"{self.prefix}:all"
        
        rule_map = {r.get("rule_id", r.get("metadata", {}).get("id", "unknown")): json.dumps(r) for r in rules}
        
        self.r.delete(pipe_key)
        if rule_map:
            self.r.client.hset(pipe_key, mapping=rule_map)
            
        self._build_indexes(rules)

    def _build_indexes(self, rules: list):
        sig_idx = f"{self.prefix}:idx:signatures"
        beh_idx = f"{self.prefix}:idx:behavioral"
        seq_idx = f"{self.prefix}:idx:sequences"
        thr_idx = f"{self.prefix}:idx:thresholds"

        self.r.delete(sig_idx, beh_idx, seq_idx, thr_idx)
        
        for rule in rules:
            rid = rule.get("rule_id", rule.get("metadata", {}).get("id", "unknown"))
            rule_type = rule.get("rule_type", rule.get("metadata", {}).get("rule_type", "signature"))
            
            if rule_type == "signature":
                self.r.client.sadd(sig_idx, rid)
            elif rule_type == "behavioral":
                self.r.client.sadd(beh_idx, rid)
                
            correlation = rule.get("correlation", {})
            if correlation.get("type") == "sequence":
                self.r.client.sadd(seq_idx, rid)
            elif correlation.get("type") == "threshold":
                self.r.client.sadd(thr_idx, rid)

    def get_rule_by_id(self, rule_id: str):
        if self.r is None:
            return None
        import json
        val = self.r.client.hget(f"{self.prefix}:all", rule_id)
        return json.loads(val) if val else None

    def _get_by_index(self, idx_key: str):
        if self.r is None:
            return []
        import json
        rule_ids = self.r.client.smembers(idx_key)
        if not rule_ids:
            return []
        
        rules_json = self.r.client.hmget(f"{self.prefix}:all", list(rule_ids))
        return [json.loads(r) for r in rules_json if r]

    def get_signature_rules(self):
        return self._get_by_index(f"{self.prefix}:idx:signatures")

    def get_behavioral_rules(self):
        return self._get_by_index(f"{self.prefix}:idx:behavioral")

    def get_sequence_rules(self):
        return self._get_by_index(f"{self.prefix}:idx:sequences")

    def get_threshold_rules(self):
        return self._get_by_index(f"{self.prefix}:idx:thresholds")

    def get_all_rules(self):
        if self.r is None:
            return []
        all_rules = self.r.hgetall_json(f"{self.prefix}:all")
        return list(all_rules.values())

    def update_rule(self, rule: dict):
        if self.r is None:
            return
        import json
        rid = rule.get("rule_id", rule.get("metadata", {}).get("id", "unknown"))
        self.r.client.hset(f"{self.prefix}:all", rid, json.dumps(rule))
        self._build_indexes(self.get_all_rules())
