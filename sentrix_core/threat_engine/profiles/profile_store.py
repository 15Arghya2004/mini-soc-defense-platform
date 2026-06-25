import os
import json
import sqlite3
from .attacker_profile import AttackerProfile

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles.db")

class ProfileStore:
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
                CREATE TABLE IF NOT EXISTS attacker_profiles (
                    src_ip TEXT PRIMARY KEY,
                    total_alerts INTEGER,
                    campaigns TEXT,
                    predictions TEXT,
                    highest_risk INTEGER,
                    first_seen TEXT,
                    last_seen TEXT
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def get_profile(self, src_ip) -> AttackerProfile:
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM attacker_profiles WHERE src_ip = ?", (src_ip,)
            ).fetchone()
            
            if row:
                try:
                    camps = json.loads(row["campaigns"])
                except Exception:
                    camps = []
                try:
                    preds = json.loads(row["predictions"])
                except Exception:
                    preds = []
                    
                return AttackerProfile(
                    src_ip=row["src_ip"],
                    total_alerts=row["total_alerts"],
                    campaigns=camps,
                    predictions=preds,
                    highest_risk=row["highest_risk"],
                    first_seen=row["first_seen"],
                    last_seen=row["last_seen"]
                )
            return None
        finally:
            conn.close()

    def save_profile(self, profile: AttackerProfile):
        conn = self._connect()
        try:
            conn.execute("""
                INSERT INTO attacker_profiles (
                    src_ip, total_alerts, campaigns, predictions, 
                    highest_risk, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(src_ip) DO UPDATE SET
                    total_alerts = excluded.total_alerts,
                    campaigns = excluded.campaigns,
                    predictions = excluded.predictions,
                    highest_risk = excluded.highest_risk,
                    last_seen = excluded.last_seen
            """, (
                profile.src_ip,
                profile.total_alerts,
                json.dumps(profile.campaigns),
                json.dumps(profile.predictions),
                profile.highest_risk,
                profile.first_seen,
                profile.last_seen
            ))
            conn.commit()
        finally:
            conn.close()

    def get_all_profiles(self):
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM attacker_profiles").fetchall()
            profiles = []
            for row in rows:
                try:
                    camps = json.loads(row["campaigns"])
                except Exception:
                    camps = []
                try:
                    preds = json.loads(row["predictions"])
                except Exception:
                    preds = []
                profiles.append(AttackerProfile(
                    src_ip=row["src_ip"],
                    total_alerts=row["total_alerts"],
                    campaigns=camps,
                    predictions=preds,
                    highest_risk=row["highest_risk"],
                    first_seen=row["first_seen"],
                    last_seen=row["last_seen"]
                ))
            return profiles
        finally:
            conn.close()

    def clear(self):
        conn = self._connect()
        try:
            conn.execute("DELETE FROM attacker_profiles")
            conn.commit()
        finally:
            conn.close()
