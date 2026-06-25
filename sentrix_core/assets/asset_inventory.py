"""
sentrix_core/assets/asset_inventory.py
Asset Inventory — Registry of all known hosts, their criticality, ownership, and tags.
Risk scoring engine consumes asset criticality to amplify/dampen risk scores.
"""
import sqlite3
import uuid
import json
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sentrix_core.config.settings import get_settings

logger = logging.getLogger("sentrix.asset_inventory")


class AssetInventory:
    """
    Enterprise Asset Registry backed by SQLite.
    Provides asset CRUD, criticality scoring, and ownership tracking.
    """

    CRITICALITY_LEVELS = {"critical": 1.5, "high": 1.3, "medium": 1.0, "low": 0.7, "info": 0.5}

    def __init__(self, db_path: str = None):
        settings = get_settings()
        import os
        self.db_path = db_path or os.path.join(settings.DATA_DIR, "assets", "inventory.db")
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
                CREATE TABLE IF NOT EXISTS assets (
                    asset_id        TEXT PRIMARY KEY,
                    hostname        TEXT,
                    ip_address      TEXT,
                    mac_address     TEXT,
                    asset_type      TEXT DEFAULT 'workstation',
                    os              TEXT,
                    owner           TEXT,
                    department      TEXT,
                    criticality     TEXT DEFAULT 'medium',
                    tags            TEXT DEFAULT '[]',
                    location        TEXT,
                    description     TEXT DEFAULT '',
                    first_seen      TEXT NOT NULL,
                    last_seen       TEXT NOT NULL,
                    active          INTEGER DEFAULT 1
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_ip ON assets(ip_address) WHERE ip_address IS NOT NULL;
                CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_hostname ON assets(hostname) WHERE hostname IS NOT NULL;
                CREATE INDEX IF NOT EXISTS idx_asset_criticality ON assets(criticality);
            """)
            conn.commit()
        finally:
            conn.close()

    def _row_to_dict(self, row) -> dict:
        d = dict(row)
        d["tags"] = json.loads(d.get("tags", "[]"))
        d["active"] = bool(d["active"])
        d["criticality_multiplier"] = self.CRITICALITY_LEVELS.get(d.get("criticality", "medium"), 1.0)
        return d

    # ── CRUD ─────────────────────────────────────────────────────────────────

    def register_asset(self, hostname: str = None, ip_address: str = None, **kwargs) -> dict:
        """Register a new asset. At least hostname or ip_address is required."""
        if not hostname and not ip_address:
            raise ValueError("At least one of hostname or ip_address is required.")

        now = datetime.now(timezone.utc).isoformat()
        asset_id = f"ast-{uuid.uuid4().hex[:12]}"
        criticality = kwargs.get("criticality", "medium")
        if criticality not in self.CRITICALITY_LEVELS:
            raise ValueError(f"Invalid criticality. Must be one of: {list(self.CRITICALITY_LEVELS.keys())}")

        conn = self._connect()
        try:
            conn.execute(
                """INSERT INTO assets
                    (asset_id, hostname, ip_address, mac_address, asset_type, os,
                     owner, department, criticality, tags, location, description,
                     first_seen, last_seen, active)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                (
                    asset_id,
                    hostname,
                    ip_address,
                    kwargs.get("mac_address"),
                    kwargs.get("asset_type", "workstation"),
                    kwargs.get("os"),
                    kwargs.get("owner"),
                    kwargs.get("department"),
                    criticality,
                    json.dumps(kwargs.get("tags", [])),
                    kwargs.get("location"),
                    kwargs.get("description", ""),
                    now,
                    now,
                ),
            )
            conn.commit()
            logger.info("[Asset] Registered asset: %s / %s", hostname, ip_address)
        except sqlite3.IntegrityError as e:
            raise ValueError(f"Asset already registered (duplicate IP or hostname): {e}")
        finally:
            conn.close()

        return self.get_asset(asset_id)

    def get_asset(self, asset_id: str) -> Optional[dict]:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM assets WHERE asset_id=?", (asset_id,)).fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def get_asset_by_ip(self, ip: str) -> Optional[dict]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM assets WHERE ip_address=? AND active=1", (ip,)
            ).fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def get_asset_by_hostname(self, hostname: str) -> Optional[dict]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM assets WHERE hostname=? AND active=1", (hostname,)
            ).fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def update_asset(self, asset_id: str, updates: dict) -> Optional[dict]:
        allowed = {
            "hostname", "ip_address", "mac_address", "asset_type", "os",
            "owner", "department", "criticality", "tags", "location", "description", "active"
        }
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            raise ValueError("No updatable fields provided.")
        if "criticality" in fields and fields["criticality"] not in self.CRITICALITY_LEVELS:
            raise ValueError(f"Invalid criticality. Must be one of: {list(self.CRITICALITY_LEVELS.keys())}")
        if "tags" in fields:
            fields["tags"] = json.dumps(fields["tags"])
        if "active" in fields:
            fields["active"] = 1 if fields["active"] else 0
        fields["last_seen"] = datetime.now(timezone.utc).isoformat()

        set_clause = ", ".join(f"{k}=?" for k in fields)
        values = list(fields.values()) + [asset_id]
        conn = self._connect()
        try:
            conn.execute(f"UPDATE assets SET {set_clause} WHERE asset_id=?", values)
            conn.commit()
        finally:
            conn.close()
        return self.get_asset(asset_id)

    def decommission_asset(self, asset_id: str) -> bool:
        conn = self._connect()
        try:
            cur = conn.execute(
                "UPDATE assets SET active=0, last_seen=? WHERE asset_id=?",
                (datetime.now(timezone.utc).isoformat(), asset_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    # ── Search ───────────────────────────────────────────────────────────────

    def list_assets(
        self, criticality: str = None, active_only: bool = True, limit: int = 200, offset: int = 0
    ) -> List[dict]:
        conditions = []
        params: List[Any] = []
        if active_only:
            conditions.append("active=1")
        if criticality:
            conditions.append("criticality=?")
            params.append(criticality)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.extend([limit, offset])
        conn = self._connect()
        try:
            rows = conn.execute(
                f"SELECT * FROM assets {where} ORDER BY criticality ASC, hostname LIMIT ? OFFSET ?",
                params,
            ).fetchall()
            return [self._row_to_dict(r) for r in rows]
        finally:
            conn.close()

    # ── Risk Integration ─────────────────────────────────────────────────────

    def get_criticality_multiplier(self, ip: str = None, hostname: str = None) -> float:
        """
        Returns the risk multiplier for an asset based on its criticality.
        Returns 1.0 (medium) if asset is unknown — fail-safe default.
        """
        asset = None
        if ip:
            asset = self.get_asset_by_ip(ip)
        if not asset and hostname:
            asset = self.get_asset_by_hostname(hostname)
        if not asset:
            return 1.0  # unknown asset = medium criticality
        return self.CRITICALITY_LEVELS.get(asset.get("criticality", "medium"), 1.0)

    def touch_asset(self, ip: str = None, hostname: str = None):
        """Update last_seen for a known asset when it appears in an event."""
        asset = None
        if ip:
            asset = self.get_asset_by_ip(ip)
        if not asset and hostname:
            asset = self.get_asset_by_hostname(hostname)
        if asset:
            conn = self._connect()
            try:
                conn.execute(
                    "UPDATE assets SET last_seen=? WHERE asset_id=?",
                    (datetime.now(timezone.utc).isoformat(), asset["asset_id"]),
                )
                conn.commit()
            finally:
                conn.close()

    def get_stats(self) -> dict:
        conn = self._connect()
        try:
            total = conn.execute("SELECT COUNT(*) FROM assets WHERE active=1").fetchone()[0]
            by_crit = conn.execute(
                "SELECT criticality, COUNT(*) as cnt FROM assets WHERE active=1 GROUP BY criticality"
            ).fetchall()
            return {
                "total_active": total,
                "by_criticality": {r["criticality"]: r["cnt"] for r in by_crit},
            }
        finally:
            conn.close()
