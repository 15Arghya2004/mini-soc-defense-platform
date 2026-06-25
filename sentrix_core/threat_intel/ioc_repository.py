"""
sentrix_core/threat_intel/ioc_repository.py
IOC Repository — stores and queries Indicators of Compromise.
Supports: IPs, domains, URLs, file hashes, and generic threat indicators.
"""
import sqlite3
import uuid
import json
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sentrix_core.config.settings import get_settings

logger = logging.getLogger("sentrix.ioc_repository")


class IOCRepository:
    """
    Production-grade IOC repository backed by SQLite.
    Provides CRUD, search, and match APIs for all IOC types.
    """

    IOC_TYPES = {"ip", "domain", "url", "file_hash", "indicator"}

    def __init__(self, db_path: str = None):
        settings = get_settings()
        import os
        self.db_path = db_path or os.path.join(settings.DATA_DIR, "threat_intel", "ioc.db")
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
                CREATE TABLE IF NOT EXISTS iocs (
                    ioc_id      TEXT PRIMARY KEY,
                    ioc_type    TEXT NOT NULL,
                    value       TEXT NOT NULL,
                    threat_actor TEXT,
                    campaign    TEXT,
                    confidence  INTEGER DEFAULT 70,
                    severity    TEXT DEFAULT 'medium',
                    tags        TEXT DEFAULT '[]',
                    source      TEXT DEFAULT 'manual',
                    description TEXT DEFAULT '',
                    created_at  TEXT NOT NULL,
                    updated_at  TEXT NOT NULL,
                    expires_at  TEXT,
                    active      INTEGER DEFAULT 1
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_ioc_type_value ON iocs(ioc_type, value);
                CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type);
                CREATE INDEX IF NOT EXISTS idx_ioc_active ON iocs(active);
            """)
            conn.commit()
        finally:
            conn.close()

    def _row_to_dict(self, row) -> dict:
        d = dict(row)
        d["tags"] = json.loads(d.get("tags", "[]"))
        d["active"] = bool(d["active"])
        return d

    # ── CRUD ─────────────────────────────────────────────────────────────────

    def add_ioc(self, ioc_type: str, value: str, **kwargs) -> dict:
        """Add a new IOC. Raises ValueError on invalid type or duplicate."""
        if ioc_type not in self.IOC_TYPES:
            raise ValueError(f"Invalid IOC type '{ioc_type}'. Must be one of {self.IOC_TYPES}")

        now = datetime.now(timezone.utc).isoformat()
        ioc_id = f"ioc-{uuid.uuid4().hex[:12]}"
        tags = json.dumps(kwargs.get("tags", []))

        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO iocs
                    (ioc_id, ioc_type, value, threat_actor, campaign, confidence,
                     severity, tags, source, description, created_at, updated_at,
                     expires_at, active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    ioc_id,
                    ioc_type,
                    value.strip().lower(),
                    kwargs.get("threat_actor"),
                    kwargs.get("campaign"),
                    int(kwargs.get("confidence", 70)),
                    kwargs.get("severity", "medium"),
                    tags,
                    kwargs.get("source", "manual"),
                    kwargs.get("description", ""),
                    now,
                    now,
                    kwargs.get("expires_at"),
                ),
            )
            conn.commit()
            logger.info("[IOC] Added %s IOC: %s", ioc_type, value)
        except sqlite3.IntegrityError:
            raise ValueError(f"IOC already exists: type={ioc_type} value={value}")
        finally:
            conn.close()

        return self.get_ioc(ioc_id)

    def get_ioc(self, ioc_id: str) -> Optional[dict]:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM iocs WHERE ioc_id=?", (ioc_id,)).fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def update_ioc(self, ioc_id: str, updates: dict) -> Optional[dict]:
        allowed = {"threat_actor", "campaign", "confidence", "severity", "tags", "source", "description", "expires_at", "active"}
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            raise ValueError("No updatable fields provided.")

        if "tags" in fields:
            fields["tags"] = json.dumps(fields["tags"])
        if "active" in fields:
            fields["active"] = 1 if fields["active"] else 0

        fields["updated_at"] = datetime.now(timezone.utc).isoformat()
        set_clause = ", ".join(f"{k}=?" for k in fields)
        values = list(fields.values()) + [ioc_id]

        conn = self._connect()
        try:
            conn.execute(f"UPDATE iocs SET {set_clause} WHERE ioc_id=?", values)
            conn.commit()
        finally:
            conn.close()

        return self.get_ioc(ioc_id)

    def delete_ioc(self, ioc_id: str) -> bool:
        """Soft-delete by marking inactive."""
        conn = self._connect()
        try:
            cur = conn.execute(
                "UPDATE iocs SET active=0, updated_at=? WHERE ioc_id=?",
                (datetime.now(timezone.utc).isoformat(), ioc_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    # ── Search ───────────────────────────────────────────────────────────────

    def list_iocs(
        self,
        ioc_type: str = None,
        active_only: bool = True,
        limit: int = 200,
        offset: int = 0,
    ) -> List[dict]:
        conditions = []
        params: List[Any] = []

        if active_only:
            conditions.append("active=1")
        if ioc_type:
            conditions.append("ioc_type=?")
            params.append(ioc_type)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.extend([limit, offset])

        conn = self._connect()
        try:
            rows = conn.execute(
                f"SELECT * FROM iocs {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
            return [self._row_to_dict(r) for r in rows]
        finally:
            conn.close()

    def search_iocs(self, query: str, ioc_type: str = None, limit: int = 50) -> List[dict]:
        """Full-text search over IOC values and descriptions."""
        q = f"%{query.strip().lower()}%"
        params: List[Any] = [q, q]
        type_clause = ""
        if ioc_type:
            type_clause = " AND ioc_type=?"
            params.append(ioc_type)
        params.append(limit)

        conn = self._connect()
        try:
            rows = conn.execute(
                f"""SELECT * FROM iocs
                    WHERE (value LIKE ? OR description LIKE ?){type_clause}
                    AND active=1
                    ORDER BY confidence DESC
                    LIMIT ?""",
                params,
            ).fetchall()
            return [self._row_to_dict(r) for r in rows]
        finally:
            conn.close()

    # ── Match ────────────────────────────────────────────────────────────────

    def match_value(self, value: str, ioc_type: str = None) -> Optional[dict]:
        """
        Check if a value matches an active IOC.
        Returns the matched IOC dict or None.
        """
        normalized = value.strip().lower()
        params: List[Any] = [normalized]
        type_clause = ""
        if ioc_type:
            type_clause = " AND ioc_type=?"
            params.append(ioc_type)

        conn = self._connect()
        try:
            row = conn.execute(
                f"SELECT * FROM iocs WHERE value=? {type_clause} AND active=1 LIMIT 1",
                params,
            ).fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def match_event(self, event: dict) -> List[dict]:
        """
        Match all IOC-relevant fields in a normalized event dict.
        Returns list of matched IOC records.
        """
        matches = []
        candidates = [
            (event.get("source", {}).get("ip"), "ip"),
            (event.get("destination", {}).get("ip"), "ip"),
            (event.get("process", {}).get("hash_md5"), "file_hash"),
            (event.get("process", {}).get("hash_sha256"), "file_hash"),
            (event.get("file", {}).get("hash_md5"), "file_hash"),
            (event.get("file", {}).get("hash_sha256"), "file_hash"),
            (event.get("network", {}).get("dns_query"), "domain"),
        ]
        seen_ids = set()
        for value, ioc_type in candidates:
            if not value:
                continue
            match = self.match_value(str(value), ioc_type)
            if match and match["ioc_id"] not in seen_ids:
                matches.append(match)
                seen_ids.add(match["ioc_id"])
        return matches

    def get_stats(self) -> dict:
        conn = self._connect()
        try:
            total = conn.execute("SELECT COUNT(*) FROM iocs WHERE active=1").fetchone()[0]
            by_type = conn.execute(
                "SELECT ioc_type, COUNT(*) as cnt FROM iocs WHERE active=1 GROUP BY ioc_type"
            ).fetchall()
            return {
                "total_active": total,
                "by_type": {r["ioc_type"]: r["cnt"] for r in by_type},
            }
        finally:
            conn.close()
