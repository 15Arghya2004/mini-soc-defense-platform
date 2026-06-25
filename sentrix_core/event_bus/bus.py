"""
sentrix_core/event_bus/bus.py
Unified in-process SQLite event bus for Sentrix V7.

All three engines (Threat, Prediction, Investigation) share this single
bus instance via the module-level singleton. No external broker required.
"""
import sqlite3
import json
import os
import time
import threading
import logging

logger = logging.getLogger("sentrix.event_bus")

# ── Singleton state ────────────────────────────────────────────────────────────
_bus_lock = threading.Lock()
_db_path: str = ""
_initialized: bool = False


def init_bus(db_path: str):
    """Initialize the event bus database. Called once at app startup."""
    global _db_path, _initialized
    with _bus_lock:
        _db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                topic       TEXT    NOT NULL,
                payload     TEXT    NOT NULL,
                created_at  TEXT    DEFAULT (datetime('now', 'utc'))
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_topic ON events(topic)")
        conn.commit()
        conn.close()
        _initialized = True
        logger.info("[EventBus] Initialized at %s", db_path)


def _get_db() -> str:
    if not _initialized:
        raise RuntimeError("EventBus not initialized. Call init_bus() first.")
    return _db_path


# ── Publisher ──────────────────────────────────────────────────────────────────
class EventPublisher:
    def publish(self, topic: str, message: dict) -> bool:
        try:
            conn = sqlite3.connect(_get_db())
            conn.execute(
                "INSERT INTO events (topic, payload) VALUES (?, ?)",
                (topic, json.dumps(message))
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error("[Publisher] Error on topic %s: %s", topic, e)
            return False


# ── Subscriber ─────────────────────────────────────────────────────────────────
class EventSubscriber:
    def __init__(self):
        self.running = False
        self.last_id = self._get_max_id()

    def _get_max_id(self) -> int:
        try:
            conn = sqlite3.connect(_get_db())
            row = conn.execute("SELECT MAX(id) FROM events").fetchone()
            conn.close()
            return row[0] if row and row[0] is not None else 0
        except Exception:
            return 0

    def subscribe(self, topic: str, callback) -> threading.Thread:
        """Start a background polling thread for the given topic."""
        self.running = True

        def poll_loop():
            local_last = self.last_id
            while self.running:
                try:
                    conn = sqlite3.connect(_get_db())
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute(
                        "SELECT id, payload FROM events WHERE topic = ? AND id > ? ORDER BY id ASC",
                        (topic, local_last)
                    ).fetchall()
                    for row in rows:
                        local_last = max(local_last, row["id"])
                        try:
                            callback(json.loads(row["payload"]))
                        except Exception as cb_err:
                            logger.error("[Subscriber] Callback error: %s", cb_err)
                    conn.close()
                except Exception as poll_err:
                    logger.warning("[Subscriber] Poll error: %s", poll_err)
                time.sleep(0.2)

        t = threading.Thread(target=poll_loop, daemon=True)
        t.start()
        return t

    def stop(self):
        self.running = False


# ── Direct read helpers (used by Investigation collectors in-process) ─────────
def read_topic_events(topic: str, limit: int = 200) -> list:
    """Read most recent events from a topic directly from the database."""
    try:
        conn = sqlite3.connect(_get_db())
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT payload FROM events WHERE topic = ? ORDER BY id DESC LIMIT ?",
            (topic, limit)
        ).fetchall()
        conn.close()
        return [json.loads(r["payload"]) for r in rows]
    except Exception as e:
        logger.error("[EventBus] read_topic_events error: %s", e)
        return []


def get_topic_stats() -> dict:
    """Return per-topic event counts."""
    try:
        conn = sqlite3.connect(_get_db())
        rows = conn.execute(
            "SELECT topic, COUNT(*) as cnt FROM events GROUP BY topic"
        ).fetchall()
        conn.close()
        return {r[0]: r[1] for r in rows}
    except Exception:
        return {}
