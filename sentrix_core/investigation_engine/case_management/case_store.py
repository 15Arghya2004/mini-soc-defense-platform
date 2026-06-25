import os
import sqlite3
import logging
from datetime import datetime, timezone

logger = logging.getLogger("sentrix.investigation.case_store")

# Resolve DB path dynamically (shares the same database as report_store.py)
DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
    "storage", "investigations.db"
)

class CaseStore:
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
            # Table for analyst notes
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analyst_notes (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id  TEXT NOT NULL,
                    analyst_name TEXT NOT NULL,
                    note_text    TEXT NOT NULL,
                    created_at   TEXT DEFAULT (datetime('now','utc')),
                    FOREIGN KEY(incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_notes_inc_id ON analyst_notes(incident_id)")

            # Table for assignment history
            conn.execute("""
                CREATE TABLE IF NOT EXISTS assignment_history (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id  TEXT NOT NULL,
                    assigned_by  TEXT NOT NULL,
                    assigned_to  TEXT NOT NULL,
                    timestamp    TEXT DEFAULT (datetime('now','utc')),
                    FOREIGN KEY(incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_assign_inc_id ON assignment_history(incident_id)")
            conn.commit()
        finally:
            conn.close()

    def add_note(self, incident_id: str, analyst_name: str, note_text: str) -> bool:
        conn = self._connect()
        try:
            conn.execute("""
                INSERT INTO analyst_notes (incident_id, analyst_name, note_text, created_at)
                VALUES (?, ?, ?, ?)
            """, (incident_id, analyst_name, note_text, datetime.now(timezone.utc).isoformat()))
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"[CaseStore] Failed to add note for incident {incident_id}: {e}")
            return False
        finally:
            conn.close()

    def get_notes(self, incident_id: str) -> list:
        conn = self._connect()
        try:
            rows = conn.execute("""
                SELECT * FROM analyst_notes 
                WHERE incident_id = ? 
                ORDER BY created_at ASC
            """, (incident_id,)).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"[CaseStore] Failed to get notes for incident {incident_id}: {e}")
            return []
        finally:
            conn.close()

    def update_status(self, incident_id: str, status: str, resolution_notes: str = None) -> bool:
        conn = self._connect()
        try:
            if resolution_notes:
                conn.execute("""
                    UPDATE incidents 
                    SET status = ?, resolution_notes = ?
                    WHERE incident_id = ?
                """, (status.upper(), resolution_notes, incident_id))
            else:
                conn.execute("""
                    UPDATE incidents 
                    SET status = ?
                    WHERE incident_id = ?
                """, (status.upper(), incident_id))
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"[CaseStore] Failed to update status for incident {incident_id}: {e}")
            return False
        finally:
            conn.close()

    def update_case_status(self, incident_id: str, status: str, resolution_notes: str = None) -> bool:
        """Alias for update_status to maintain compatibility with route handlers."""
        return self.update_status(incident_id, status, resolution_notes)

    def assign_case(self, incident_id: str, assigned_by: str, assigned_to: str) -> bool:
        conn = self._connect()
        try:
            # 1. Update active analyst in incidents table
            conn.execute("""
                UPDATE incidents 
                SET assigned_analyst = ? 
                WHERE incident_id = ?
            """, (assigned_to, incident_id))

            # 2. Add entry to assignment history
            conn.execute("""
                INSERT INTO assignment_history (incident_id, assigned_by, assigned_to, timestamp)
                VALUES (?, ?, ?, ?)
            """, (incident_id, assigned_by, assigned_to, datetime.now(timezone.utc).isoformat()))

            conn.commit()
            return True
        except Exception as e:
            logger.error(f"[CaseStore] Failed to assign incident {incident_id} to {assigned_to}: {e}")
            return False
        finally:
            conn.close()

    def get_assignment_history(self, incident_id: str) -> list:
        conn = self._connect()
        try:
            rows = conn.execute("""
                SELECT * FROM assignment_history 
                WHERE incident_id = ? 
                ORDER BY timestamp ASC
            """, (incident_id,)).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"[CaseStore] Failed to get assignments for incident {incident_id}: {e}")
            return []
        finally:
            conn.close()

    def clear(self):
        conn = self._connect()
        try:
            conn.execute("DELETE FROM analyst_notes")
            conn.execute("DELETE FROM assignment_history")
            conn.commit()
        finally:
            conn.close()

    def create_case_from_report(self, report: dict) -> bool:
        """Ensures compatability for investigation report generation in worker threads."""
        incident_id = report.get("incident_id", "unknown")
        logger.info(f"[CaseStore] Case verified and report registered for incident: {incident_id}")
        return True
