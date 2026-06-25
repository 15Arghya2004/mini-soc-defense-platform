import os
import json
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "campaigns.db")

class CampaignStore:
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
                CREATE TABLE IF NOT EXISTS campaign_memory (
                    campaign_id TEXT PRIMARY KEY,
                    src_ip TEXT,
                    current_stage TEXT,
                    historical_stages TEXT,
                    current_risk INTEGER,
                    predicted_next_stage TEXT,
                    last_updated TEXT
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def get_campaign(self, campaign_id) -> dict:
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM campaign_memory WHERE campaign_id = ?", (campaign_id,)
            ).fetchone()
            
            if row:
                try:
                    hist = json.loads(row["historical_stages"])
                except Exception:
                    hist = []
                    
                return {
                    "campaign_id": row["campaign_id"],
                    "src_ip": row["src_ip"],
                    "current_stage": row["current_stage"],
                    "historical_stages": hist,
                    "current_risk": row["current_risk"],
                    "predicted_next_stage": row["predicted_next_stage"],
                    "last_updated": row["last_updated"]
                }
            return None
        finally:
            conn.close()

    def get_active_campaign_for_ip(self, src_ip) -> dict:
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM campaign_memory WHERE src_ip = ? ORDER BY last_updated DESC LIMIT 1", (src_ip,)
            ).fetchone()
            
            if row:
                try:
                    hist = json.loads(row["historical_stages"])
                except Exception:
                    hist = []
                    
                return {
                    "campaign_id": row["campaign_id"],
                    "src_ip": row["src_ip"],
                    "current_stage": row["current_stage"],
                    "historical_stages": hist,
                    "current_risk": row["current_risk"],
                    "predicted_next_stage": row["predicted_next_stage"],
                    "last_updated": row["last_updated"]
                }
            return None
        finally:
            conn.close()

    def save_campaign(self, campaign: dict):
        now_str = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            conn.execute("""
                INSERT INTO campaign_memory (
                    campaign_id, src_ip, current_stage, historical_stages, 
                    current_risk, predicted_next_stage, last_updated
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(campaign_id) DO UPDATE SET
                    current_stage = excluded.current_stage,
                    historical_stages = excluded.historical_stages,
                    current_risk = excluded.current_risk,
                    predicted_next_stage = excluded.predicted_next_stage,
                    last_updated = excluded.last_updated
            """, (
                campaign["campaign_id"],
                campaign["src_ip"],
                campaign["current_stage"],
                json.dumps(campaign["historical_stages"]),
                campaign["current_risk"],
                campaign.get("predicted_next_stage", "Unknown"),
                now_str
            ))
            conn.commit()
        finally:
            conn.close()

    def get_all_campaigns(self) -> list:
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM campaign_memory").fetchall()
            camps = []
            for row in rows:
                try:
                    hist = json.loads(row["historical_stages"])
                except Exception:
                    hist = []
                camps.append({
                    "campaign_id": row["campaign_id"],
                    "src_ip": row["src_ip"],
                    "current_stage": row["current_stage"],
                    "historical_stages": hist,
                    "current_risk": row["current_risk"],
                    "predicted_next_stage": row["predicted_next_stage"],
                    "last_updated": row["last_updated"]
                })
            return camps
        finally:
            conn.close()

    def clear(self):
        conn = self._connect()
        try:
            conn.execute("DELETE FROM campaign_memory")
            conn.commit()
        finally:
            conn.close()
