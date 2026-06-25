"""
sentrix_core/response_engine/soar.py
SOAR Response Engine for automated actions.
"""
import logging
import uuid
import sqlite3
import os
import json
from datetime import datetime, timezone
from sentrix_core.config.settings import get_settings

logger = logging.getLogger("sentrix.soar")

class SOAREngine:
    def __init__(self):
        self.settings = get_settings()
        self.db_path = os.path.join(self.settings.DATA_DIR, "investigations", "soar_audit.db")
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._connect()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS soar_actions (
                    action_id TEXT PRIMARY KEY,
                    incident_id TEXT,
                    action_type TEXT,
                    target TEXT,
                    status TEXT,
                    simulation_mode BOOLEAN,
                    payload TEXT,
                    timestamp TEXT
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def _log_action(self, action_id, incident_id, action_type, target, status, simulation, payload):
        conn = self._connect()
        try:
            conn.execute("""
                INSERT INTO soar_actions (action_id, incident_id, action_type, target, status, simulation_mode, payload, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                action_id, incident_id, action_type, target, status,
                1 if simulation else 0, json.dumps(payload),
                datetime.now(timezone.utc).isoformat()
            ))
            conn.commit()
        except Exception as e:
            logger.error(f"Failed to log SOAR action: {e}")
        finally:
            conn.close()

    def execute_action(self, action_type: str, target: str, incident_id: str = None, payload: dict = None) -> dict:
        """
        Executes a SOAR action in simulation mode.
        Supported actions: isolate_host, block_ip, disable_account, create_ticket, notify_soc, trigger_webhook
        """
        if not payload:
            payload = {}
            
        action_id = f"act-{uuid.uuid4().hex[:8]}"
        
        valid_actions = ["isolate_host", "block_ip", "disable_account", "create_ticket", "notify_soc", "trigger_webhook"]
        if action_type not in valid_actions:
            logger.warning(f"SOAR: Unknown action type requested: {action_type}")
            status = "failed_invalid_action"
        else:
            logger.info(f"[SOAR] [SIMULATION] Executing {action_type} against {target}")
            status = "success_simulated"

        self._log_action(action_id, incident_id, action_type, target, status, True, payload)

        return {
            "action_id": action_id,
            "incident_id": incident_id,
            "action": action_type,
            "target": target,
            "status": status,
            "simulation": True,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def get_audit_log(self, limit: int = 100) -> list:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT * FROM soar_actions ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
