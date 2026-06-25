"""
sentrix_core/metrics/metrics_collector.py
Observability Metrics Collector — tracks event rates, alert rates,
rule counts, incident counts, case counts, SOAR actions, and prediction counts.
Thread-safe in-memory counters backed by SQLite for persistence.
"""
import sqlite3
import logging
import threading
import time
import os
from datetime import datetime, timezone
from sentrix_core.config.settings import get_settings

logger = logging.getLogger("sentrix.metrics")


class MetricsCollector:
    """
    Central metrics registry for Sentrix V8.
    All counters are thread-safe. Snapshot is persisted to SQLite periodically.
    """

    def __init__(self, db_path: str = None):
        settings = get_settings()
        self.db_path = db_path or os.path.join(settings.DATA_DIR, "metrics", "metrics.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        self._lock = threading.Lock()
        self._start_time = time.time()

        # In-memory counters (reset on restart)
        self._counters = {
            "events_ingested":    0,
            "events_normalized":  0,
            "alerts_generated":   0,
            "alerts_suppressed":  0,
            "incidents_created":  0,
            "cases_created":      0,
            "soar_actions":       0,
            "predictions_made":   0,
            "ioc_matches":        0,
            "rules_loaded":       0,
            "enrichments_run":    0,
        }

        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        conn = self._connect()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS metric_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    snapshot    TEXT NOT NULL,
                    recorded_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS metric_events (
                    event_id    TEXT PRIMARY KEY,
                    metric_name TEXT NOT NULL,
                    value       REAL NOT NULL,
                    labels      TEXT DEFAULT '{}',
                    recorded_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_me_name ON metric_events(metric_name);
                CREATE INDEX IF NOT EXISTS idx_me_time ON metric_events(recorded_at);
            """)
            conn.commit()
        finally:
            conn.close()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ── Increment Helpers ─────────────────────────────────────────────────────

    def inc(self, metric: str, amount: int = 1):
        with self._lock:
            if metric in self._counters:
                self._counters[metric] += amount
            else:
                self._counters[metric] = amount

    def inc_events(self):           self.inc("events_ingested")
    def inc_normalized(self):       self.inc("events_normalized")
    def inc_alerts(self, n: int = 1): self.inc("alerts_generated", n)
    def inc_suppressed(self, n: int = 1): self.inc("alerts_suppressed", n)
    def inc_incidents(self):        self.inc("incidents_created")
    def inc_cases(self):            self.inc("cases_created")
    def inc_soar(self):             self.inc("soar_actions")
    def inc_predictions(self):      self.inc("predictions_made")
    def inc_ioc_matches(self, n: int = 1): self.inc("ioc_matches", n)
    def inc_enrichments(self):      self.inc("enrichments_run")
    def set_rules_loaded(self, n: int): 
        with self._lock:
            self._counters["rules_loaded"] = n

    # ── Snapshot ──────────────────────────────────────────────────────────────

    def get_snapshot(self) -> dict:
        with self._lock:
            counters = dict(self._counters)
        uptime = round(time.time() - self._start_time, 2)
        now = self._now()
        return {
            "timestamp": now,
            "uptime_seconds": uptime,
            "counters": counters,
            "rates": {
                "events_per_second": round(counters["events_ingested"] / max(uptime, 1), 4),
                "alerts_per_second": round(counters["alerts_generated"] / max(uptime, 1), 4),
            },
        }

    def persist_snapshot(self):
        """Persist current metrics to SQLite for historical tracking."""
        import json
        import uuid
        snap = self.get_snapshot()
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO metric_snapshots (snapshot_id, snapshot, recorded_at) VALUES (?,?,?)",
                (f"snap-{uuid.uuid4().hex[:8]}", json.dumps(snap), snap["timestamp"]),
            )
            conn.commit()
        except Exception as e:
            logger.error("[Metrics] Failed to persist snapshot: %s", e)
        finally:
            conn.close()

    def record_metric_event(self, metric_name: str, value: float, labels: dict = None):
        """Record a time-series metric point."""
        import json, uuid
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO metric_events (event_id, metric_name, value, labels, recorded_at) VALUES (?,?,?,?,?)",
                (
                    f"me-{uuid.uuid4().hex[:8]}",
                    metric_name, value,
                    json.dumps(labels or {}),
                    self._now(),
                ),
            )
            conn.commit()
        except Exception as e:
            logger.error("[Metrics] Failed to record metric event: %s", e)
        finally:
            conn.close()

    def get_history(self, metric_name: str, limit: int = 100) -> list:
        import json
        conn = self._connect()
        try:
            rows = conn.execute(
                """SELECT metric_name, value, labels, recorded_at
                   FROM metric_events WHERE metric_name=?
                   ORDER BY recorded_at DESC LIMIT ?""",
                (metric_name, limit),
            ).fetchall()
            result = []
            for r in rows:
                d = dict(r)
                d["labels"] = json.loads(d.get("labels", "{}"))
                result.append(d)
            return result
        finally:
            conn.close()


# Global singleton instance
_metrics_instance: MetricsCollector = None
_metrics_lock = threading.Lock()


def get_metrics() -> MetricsCollector:
    global _metrics_instance
    if _metrics_instance is None:
        with _metrics_lock:
            if _metrics_instance is None:
                _metrics_instance = MetricsCollector()
    return _metrics_instance
