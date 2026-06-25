"""
sentrix_core/suppression/suppression_engine.py
Alert Suppression Engine — prevents alert fatigue via whitelisting,
maintenance windows, host suppression, and noise reduction rules.
"""
import sqlite3
import uuid
import json
import logging
import re
from datetime import datetime, timezone
from typing import Optional, List, Any
from sentrix_core.config.settings import get_settings

logger = logging.getLogger("sentrix.suppression")


class SuppressionEngine:
    """
    Alert suppression engine. Checks alerts against:
    - IP/CIDR whitelist
    - Known-good hosts
    - Rule-specific suppressions
    - Active maintenance windows
    - Noise reduction (min severity threshold)
    """

    def __init__(self, db_path: str = None):
        settings = get_settings()
        import os
        self.db_path = db_path or os.path.join(settings.DATA_DIR, "suppression", "suppression.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
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
                CREATE TABLE IF NOT EXISTS suppressions (
                    suppression_id  TEXT PRIMARY KEY,
                    suppression_type TEXT NOT NULL,
                    value           TEXT NOT NULL,
                    rule_id         TEXT,
                    reason          TEXT DEFAULT '',
                    created_by      TEXT DEFAULT 'system',
                    created_at      TEXT NOT NULL,
                    expires_at      TEXT,
                    active          INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS maintenance_windows (
                    window_id   TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    scope       TEXT DEFAULT 'global',
                    scope_value TEXT,
                    start_time  TEXT NOT NULL,
                    end_time    TEXT NOT NULL,
                    created_by  TEXT DEFAULT 'system',
                    active      INTEGER DEFAULT 1
                );

                CREATE INDEX IF NOT EXISTS idx_supp_type_val ON suppressions(suppression_type, value);
                CREATE INDEX IF NOT EXISTS idx_supp_active   ON suppressions(active);
                CREATE INDEX IF NOT EXISTS idx_mw_active     ON maintenance_windows(active);
            """)
            conn.commit()
        finally:
            conn.close()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _row_to_dict(self, row) -> dict:
        d = dict(row)
        if "active" in d:
            d["active"] = bool(d["active"])
        return d

    # ── Suppression Rules CRUD ────────────────────────────────────────────────

    def add_suppression(
        self,
        suppression_type: str,
        value: str,
        rule_id: str = None,
        reason: str = "",
        created_by: str = "system",
        expires_at: str = None,
    ) -> dict:
        """
        Add a suppression entry.
        Types: 'ip_whitelist', 'hostname_whitelist', 'rule_suppression', 'known_good'
        """
        valid_types = {"ip_whitelist", "hostname_whitelist", "rule_suppression", "known_good"}
        if suppression_type not in valid_types:
            raise ValueError(f"Invalid type. Must be one of: {valid_types}")

        supp_id = f"supp-{uuid.uuid4().hex[:8]}"
        conn = self._connect()
        try:
            conn.execute(
                """INSERT INTO suppressions
                   (suppression_id, suppression_type, value, rule_id, reason,
                    created_by, created_at, expires_at, active)
                   VALUES (?,?,?,?,?,?,?,?,1)""",
                (supp_id, suppression_type, value.strip().lower(), rule_id, reason,
                 created_by, self._now(), expires_at),
            )
            conn.commit()
            logger.info("[Suppression] Added %s: %s", suppression_type, value)
        finally:
            conn.close()
        return self.get_suppression(supp_id)

    def get_suppression(self, suppression_id: str) -> Optional[dict]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM suppressions WHERE suppression_id=?", (suppression_id,)
            ).fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def list_suppressions(self, suppression_type: str = None, active_only: bool = True) -> List[dict]:
        conditions, params = [], []
        if active_only:
            conditions.append("active=1")
        if suppression_type:
            conditions.append("suppression_type=?"); params.append(suppression_type)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        conn = self._connect()
        try:
            rows = conn.execute(
                f"SELECT * FROM suppressions {where} ORDER BY created_at DESC", params
            ).fetchall()
            return [self._row_to_dict(r) for r in rows]
        finally:
            conn.close()

    def remove_suppression(self, suppression_id: str) -> bool:
        conn = self._connect()
        try:
            cur = conn.execute(
                "UPDATE suppressions SET active=0 WHERE suppression_id=?", (suppression_id,)
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    # ── Maintenance Windows ───────────────────────────────────────────────────

    def add_maintenance_window(
        self, name: str, start_time: str, end_time: str,
        scope: str = "global", scope_value: str = None, created_by: str = "system"
    ) -> dict:
        window_id = f"mw-{uuid.uuid4().hex[:8]}"
        conn = self._connect()
        try:
            conn.execute(
                """INSERT INTO maintenance_windows
                   (window_id, name, scope, scope_value, start_time, end_time, created_by, active)
                   VALUES (?,?,?,?,?,?,?,1)""",
                (window_id, name, scope, scope_value, start_time, end_time, created_by),
            )
            conn.commit()
        finally:
            conn.close()
        return {"window_id": window_id, "name": name, "scope": scope,
                "start_time": start_time, "end_time": end_time}

    def list_maintenance_windows(self, active_only: bool = True) -> List[dict]:
        where = "WHERE active=1" if active_only else ""
        conn = self._connect()
        try:
            rows = conn.execute(
                f"SELECT * FROM maintenance_windows {where} ORDER BY start_time DESC"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def _in_maintenance_window(self, alert: dict) -> bool:
        """Returns True if the alert falls within any active maintenance window."""
        now_str = self._now()
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM maintenance_windows WHERE active=1 AND start_time<=? AND end_time>=?",
                (now_str, now_str),
            ).fetchall()
        finally:
            conn.close()

        for mw in rows:
            scope = mw["scope"]
            if scope == "global":
                return True
            scope_value = (mw["scope_value"] or "").lower()
            if scope == "host":
                host = (alert.get("affected_host") or "").lower()
                if host == scope_value or host.startswith(scope_value):
                    return True
            elif scope == "ip":
                src_ip = (alert.get("source_ip") or "").lower()
                if src_ip == scope_value:
                    return True
        return False

    # ── Core Suppression Check ────────────────────────────────────────────────

    def should_suppress(self, alert: dict) -> tuple:
        """
        Returns (True, reason) if the alert should be suppressed, else (False, None).
        Checks in order: maintenance windows → IP whitelist → host whitelist →
                         rule-level suppression → known-good hosts
        """
        # 1. Maintenance window
        if self._in_maintenance_window(alert):
            return True, "maintenance_window"

        src_ip = (alert.get("source_ip") or "").strip().lower()
        host   = (alert.get("affected_host") or "").strip().lower()
        rule_id = alert.get("rule_id", "")

        conn = self._connect()
        try:
            active_suppresions = conn.execute(
                """SELECT * FROM suppressions
                   WHERE active=1 AND (expires_at IS NULL OR expires_at > ?)""",
                (self._now(),),
            ).fetchall()
        finally:
            conn.close()

        for s in active_suppresions:
            stype = s["suppression_type"]
            val   = (s["value"] or "").lower()

            if stype == "ip_whitelist" and src_ip and src_ip == val:
                return True, f"ip_whitelist:{val}"
            if stype == "hostname_whitelist" and host and host == val:
                return True, f"hostname_whitelist:{val}"
            if stype == "known_good" and (src_ip == val or host == val):
                return True, f"known_good:{val}"
            if stype == "rule_suppression" and val == rule_id.lower():
                return True, f"rule_suppression:{val}"

        return False, None

    def filter_alerts(self, alerts: list) -> tuple:
        """
        Filter a list of alerts. Returns (allowed_alerts, suppressed_alerts).
        """
        allowed, suppressed = [], []
        for alert in alerts:
            is_suppressed, reason = self.should_suppress(alert)
            if is_suppressed:
                alert["_suppressed"] = True
                alert["_suppression_reason"] = reason
                suppressed.append(alert)
                logger.info("[Suppression] Alert %s suppressed: %s", alert.get("alert_id"), reason)
            else:
                allowed.append(alert)
        return allowed, suppressed
