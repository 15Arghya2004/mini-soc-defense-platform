"""
sentrix_core/rule_define_studio/hot_reload.py
Live Rule Reloader watching custom rules and repository.
"""
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger("sentrix.rule_studio.hot_reload")

class RuleChangeHandler(FileSystemEventHandler):
    def __init__(self, threat_engine):
        self.threat_engine = threat_engine
        self.last_reload = 0

    def on_modified(self, event):
        self._trigger_reload(event)

    def on_created(self, event):
        self._trigger_reload(event)

    def on_deleted(self, event):
        self._trigger_reload(event)

    def _trigger_reload(self, event):
        if event.is_directory or not event.src_path.endswith(".json"):
            return
        
        # Debounce reloads (watchdog can fire multiple events rapidly)
        current_time = time.time()
        if current_time - self.last_reload > 1.0:
            logger.info(f"Rule file changed: {event.src_path}. Reloading Threat Engine...")
            self.last_reload = current_time
            try:
                self.threat_engine.reload_rules()
            except Exception as e:
                logger.error(f"Failed to reload rules dynamically: {e}")

class RuleReloader:
    def __init__(self, threat_engine, rules_dirs: list):
        self.threat_engine = threat_engine
        self.rules_dirs = rules_dirs
        self.observer = Observer()
        self.handler = RuleChangeHandler(self.threat_engine)

    def start(self):
        for directory in self.rules_dirs:
            self.observer.schedule(self.handler, path=directory, recursive=False)
        self.observer.start()
        logger.info(f"Rule hot-reload watcher started on: {self.rules_dirs}")

    def stop(self):
        self.observer.stop()
        self.observer.join()
