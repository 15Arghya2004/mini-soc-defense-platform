import os
import json
import sqlite3
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("sentrix.investigation.report_store")

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "investigations.db")

class ReportStore:
    def __init__(self, db_path=None):
        self.db_path = db_path or DB_PATH
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._connect()
        try:
            # Table for incidents and case details
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id       TEXT PRIMARY KEY,
                    source_ip         TEXT NOT NULL,
                    severity          TEXT NOT NULL,
                    destination_host  TEXT,
                    attacker_origin   TEXT,
                    first_seen        TEXT,
                    last_seen         TEXT,
                    report_json       TEXT,
                    status            TEXT NOT NULL DEFAULT 'OPEN',
                    assigned_analyst  TEXT DEFAULT 'unassigned',
                    resolution_notes  TEXT,
                    created_at        TEXT DEFAULT (datetime('now','utc'))
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inc_source_ip ON incidents(source_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inc_status ON incidents(status)")
            conn.commit()
        finally:
            conn.close()

    def save_incident(self, incident_id: str, source_ip: str, severity: str, 
                      dest_host: Any = None, origin: str = None, first_seen: str = None, 
                      last_seen: str = None, report_data: dict = None, status: str = "OPEN") -> bool:
        if isinstance(dest_host, dict) and report_data is None:
            report_data = dest_host
            dest_host = report_data.get("destination_host", "unknown")
            origin = report_data.get("attacker_origin", "unknown")
            first_seen = report_data.get("first_seen", "unknown")
            last_seen = report_data.get("last_seen", "unknown")
            status = report_data.get("case_status", status)
        conn = self._connect()
        try:
            conn.execute("""
                INSERT INTO incidents (
                    incident_id, source_ip, severity, destination_host, 
                    attacker_origin, first_seen, last_seen, report_json, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    severity = excluded.severity,
                    destination_host = excluded.destination_host,
                    attacker_origin = excluded.attacker_origin,
                    last_seen = excluded.last_seen,
                    report_json = excluded.report_json
            """, (
                incident_id,
                source_ip,
                severity.upper(),
                dest_host,
                origin,
                first_seen,
                last_seen,
                json.dumps(report_data),
                status.upper()
            ))
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"[ReportStore] Save failed for incident {incident_id}: {e}")
            return False
        finally:
            conn.close()

    def get_incident(self, incident_id: str) -> dict:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
            if row:
                d = dict(row)
                try:
                    d["report_data"] = json.loads(d["report_json"])
                except Exception:
                    d["report_data"] = {}
                return d
            return None
        finally:
            conn.close()

    def get_all_incidents(self) -> list:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
            incidents = []
            for row in rows:
                d = dict(row)
                try:
                    d["report_data"] = json.loads(d["report_json"])
                except Exception:
                    d["report_data"] = {}
                incidents.append(d)
            return incidents
        finally:
            conn.close()

    def get_incidents_by_ip(self, source_ip: str) -> list:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT * FROM incidents WHERE source_ip = ? ORDER BY created_at DESC", (source_ip,)).fetchall()
            incidents = []
            for row in rows:
                d = dict(row)
                try:
                    d["report_data"] = json.loads(d["report_json"])
                except Exception:
                    d["report_data"] = {}
                incidents.append(d)
            return incidents
        finally:
            conn.close()

    def clear(self):
        conn = self._connect()
        try:
            conn.execute("DELETE FROM incidents")
            conn.commit()
        finally:
            conn.close()
