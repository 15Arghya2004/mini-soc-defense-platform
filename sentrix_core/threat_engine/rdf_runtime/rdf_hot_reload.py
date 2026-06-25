class RDFHotReloader:
    def __init__(self, registry, loader, cache_manager):
        self.registry = registry
        self.loader = loader
        self.cache = cache_manager

    def trigger_hot_reload(self):
        """
        Reloads rules from rule-repository directory, 
        updates the RDFRegistry, and flushes states and JIT caches.
        """
        print("[HotReload] Initiating rules hot swap...")
        try:
            # Load new rule catalog
            new_rules = self.loader.load_all_rules()
            
            # Atomic update in Registry
            self.registry.update_rules(new_rules)
            
            # Update Cache rule catalog
            self.cache.load_rules(new_rules)
            
            # Flush existing correlation buffers to prevent state contamination
            self.cache.clear_correlation_states()
            
            print(f"[HotReload] Hot reload successful. {len(new_rules)} rules re-compiled and swapped.")
            return True
        except Exception as e:
            print(f"[-] HotReload failed: {e}")
            return False
