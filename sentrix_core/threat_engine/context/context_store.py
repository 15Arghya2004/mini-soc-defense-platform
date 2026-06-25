import os
import json
import sqlite3
from .attacker_profile import AttackerContextProfile

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "context.db")

class ContextStore:
    def __init__(self, db_path=None):
        self.db_path = db_path or DB_PATH
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        conn = self._connect()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS context_memory (
                    src_ip TEXT PRIMARY KEY,
                    first_seen TEXT,
                    last_seen TEXT,
                    alert_count INTEGER,
                    categories_seen TEXT,
                    campaign_count INTEGER,
                    risk_trend TEXT,
                    prediction_count INTEGER,
                    risk_history TEXT
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def get_context(self, src_ip) -> AttackerContextProfile:
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM context_memory WHERE src_ip = ?", (src_ip,)
            ).fetchone()
            
            if row:
                try:
                    categories = json.loads(row["categories_seen"])
                except Exception:
                    categories = []
                try:
                    risk_hist = json.loads(row["risk_history"])
                except Exception:
                    risk_hist = []
                    
                return AttackerContextProfile(
                    src_ip=row["src_ip"],
                    first_seen=row["first_seen"],
                    last_seen=row["last_seen"],
                    alert_count=row["alert_count"],
                    categories_seen=categories,
                    campaign_count=row["campaign_count"],
                    risk_trend=row["risk_trend"],
                    prediction_count=row["prediction_count"],
                    risk_history=risk_hist
                )
            return None
        finally:
            conn.close()

    def save_context(self, profile: AttackerContextProfile):
        conn = self._connect()
        try:
            conn.execute("""
                INSERT INTO context_memory (
                    src_ip, first_seen, last_seen, alert_count, 
                    categories_seen, campaign_count, risk_trend, 
                    prediction_count, risk_history
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(src_ip) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    alert_count = excluded.alert_count,
                    categories_seen = excluded.categories_seen,
                    campaign_count = excluded.campaign_count,
                    risk_trend = excluded.risk_trend,
                    prediction_count = excluded.prediction_count,
                    risk_history = excluded.risk_history
            """, (
                profile.src_ip,
                profile.first_seen,
                profile.last_seen,
                profile.alert_count,
                json.dumps(profile.categories_seen),
                profile.campaign_count,
                profile.risk_trend,
                profile.prediction_count,
                json.dumps(profile.risk_history)
            ))
            conn.commit()
        finally:
            conn.close()

    def clear(self):
        conn = self._connect()
        try:
            conn.execute("DELETE FROM context_memory")
            conn.commit()
        finally:
            conn.close()
