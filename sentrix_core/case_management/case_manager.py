"""
sentrix_core/case_management/case_manager.py
Enterprise Case Management — create, assign, update, add notes/evidence,
escalate, and close security cases. Cases may contain multiple incidents.
"""
import sqlite3
import uuid
import json
import logging
from datetime import datetime, timezone
from typing import Optional, List, Any
from sentrix_core.config.settings import get_settings

logger = logging.getLogger("sentrix.case_management")


class CaseManager:
    """
    Production Case Management engine backed by SQLite.
    Each case can aggregate multiple incident IDs, notes, and evidence records.
    """

    VALID_STATUSES  = {"open", "in_progress", "pending", "escalated", "resolved", "closed", "investigating"}
    VALID_PRIORITIES = {"critical", "high", "medium", "low"}

    def __init__(self, db_path: str = None):
        settings = get_settings()
        import os
        self.db_path = db_path or os.path.join(settings.DATA_DIR, "cases", "cases.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        conn = self._connect()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS cases (
                    case_id         TEXT PRIMARY KEY,
                    title           TEXT NOT NULL,
                    description     TEXT DEFAULT '',
                    status          TEXT DEFAULT 'open',
                    priority        TEXT DEFAULT 'medium',
                    assignee        TEXT,
                    reporter        TEXT DEFAULT 'system',
                    tags            TEXT DEFAULT '[]',
                    incident_ids    TEXT DEFAULT '[]',
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL,
                    resolved_at     TEXT,
                    sla_deadline    TEXT
                );

                CREATE TABLE IF NOT EXISTS case_notes (
                    note_id     TEXT PRIMARY KEY,
                    case_id     TEXT NOT NULL,
                    author      TEXT DEFAULT 'system',
                    content     TEXT NOT NULL,
                    created_at  TEXT NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES cases(case_id)
                );

                CREATE TABLE IF NOT EXISTS case_evidence (
                    evidence_id TEXT PRIMARY KEY,
                    case_id     TEXT NOT NULL,
                    evidence_type TEXT DEFAULT 'artifact',
                    label       TEXT NOT NULL,
                    value       TEXT NOT NULL,
                    added_by    TEXT DEFAULT 'system',
                    created_at  TEXT NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES cases(case_id)
                );

                CREATE TABLE IF NOT EXISTS case_audit (
                    audit_id    TEXT PRIMARY KEY,
                    case_id     TEXT NOT NULL,
                    actor       TEXT DEFAULT 'system',
                    action      TEXT NOT NULL,
                    detail      TEXT DEFAULT '',
                    created_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cases_status   ON cases(status);
                CREATE INDEX IF NOT EXISTS idx_cases_assignee ON cases(assignee);
                CREATE INDEX IF NOT EXISTS idx_notes_case     ON case_notes(case_id);
                CREATE INDEX IF NOT EXISTS idx_evidence_case  ON case_evidence(case_id);
                CREATE INDEX IF NOT EXISTS idx_audit_case     ON case_audit(case_id);
            """)
            conn.commit()
        finally:
            conn.close()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _audit(self, conn, case_id: str, action: str, detail: str = "", actor: str = "system"):
        conn.execute(
            "INSERT INTO case_audit (audit_id, case_id, actor, action, detail, created_at) VALUES (?,?,?,?,?,?)",
            (f"aud-{uuid.uuid4().hex[:8]}", case_id, actor, action, detail, self._now()),
        )

    def _row_to_dict(self, row) -> dict:
        d = dict(row)
        for field in ("tags", "incident_ids"):
            if field in d:
                d[field] = json.loads(d[field] or "[]")
        # For compatibility with tests
        d["analyst"] = d.get("assignee")
        return d

    # ── Case CRUD ────────────────────────────────────────────────────────────

    def create_case(
        self,
        title: str,
        description: str = "",
        priority: str = "medium",
        assignee: str = None,
        reporter: str = "system",
        tags: list = None,
        incident_ids: list = None,
        sla_deadline: str = None,
        source_ip: str = None,
        severity: str = None,
        rule_name: str = None,
        summary: str = None,
        **kwargs,
    ) -> dict:
        # Map severity to priority if needed
        if severity and not priority:
            priority = severity
        if priority.lower() == "medium":
            priority = "medium"
        elif priority.lower() == "high":
            priority = "high"
        elif priority.lower() == "critical":
            priority = "critical"
        elif priority.lower() == "low":
            priority = "low"

        if priority not in self.VALID_PRIORITIES:
            priority = "medium"

        # Combine extra info into description if present
        details = []
        if rule_name:
            details.append(f"Rule: {rule_name}")
        if source_ip:
            details.append(f"Source IP: {source_ip}")
        if summary:
            details.append(f"Summary: {summary}")
        if description:
            details.append(description)
        final_description = "\n".join(details)

        case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
        now = self._now()

        conn = self._connect()
        try:
            conn.execute(
                """INSERT INTO cases
                    (case_id, title, description, status, priority, assignee, reporter,
                     tags, incident_ids, created_at, updated_at, sla_deadline)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    case_id, title, final_description, "open", priority,
                    assignee, reporter,
                    json.dumps(tags or []),
                    json.dumps(incident_ids or []),
                    now, now, sla_deadline,
                ),
            )
            self._audit(conn, case_id, "CASE_CREATED", f"Priority={priority}")
            conn.commit()
            logger.info("[CaseManager] Created case %s: %s", case_id, title)
        finally:
            conn.close()

        return self.get_case(case_id)

    def get_case(self, case_id: str) -> Optional[dict]:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
            if not row:
                return None
            case = self._row_to_dict(row)
            case["notes"] = self.get_notes(case_id)
            case["evidence"] = self.get_evidence(case_id)
            case["audit_trail"] = self.get_audit_trail(case_id)
            return case
        finally:
            conn.close()

    def list_cases(
        self,
        status: str = None,
        assignee: str = None,
        priority: str = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[dict]:
        conditions, params = [], []
        if status:
            conditions.append("status=?"); params.append(status)
        if assignee:
            conditions.append("assignee=?"); params.append(assignee)
        if priority:
            conditions.append("priority=?"); params.append(priority)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.extend([limit, offset])

        conn = self._connect()
        try:
            rows = conn.execute(
                f"SELECT * FROM cases {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
            return [self._row_to_dict(r) for r in rows]
        finally:
            conn.close()

    def update_case(self, case_id: str, updates: dict, actor: str = "system") -> Optional[dict]:
        allowed = {"title", "description", "priority", "assignee", "tags", "sla_deadline"}
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            raise ValueError("No updatable fields provided.")
        if "priority" in fields and fields["priority"] not in self.VALID_PRIORITIES:
            raise ValueError(f"Invalid priority.")
        if "tags" in fields:
            fields["tags"] = json.dumps(fields["tags"])
        fields["updated_at"] = self._now()
        set_clause = ", ".join(f"{k}=?" for k in fields)
        values = list(fields.values()) + [case_id]

        conn = self._connect()
        try:
            conn.execute(f"UPDATE cases SET {set_clause} WHERE case_id=?", values)
            self._audit(conn, case_id, "CASE_UPDATED", str(list(fields.keys())), actor)
            conn.commit()
        finally:
            conn.close()
        return self.get_case(case_id)

    def update_status(self, case_id: str, status: str, actor: str = "system") -> Optional[dict]:
        if status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid status. Must be one of: {self.VALID_STATUSES}")
        now = self._now()
        resolved_at = now if status in ("resolved", "closed") else None

        conn = self._connect()
        try:
            if resolved_at:
                conn.execute(
                    "UPDATE cases SET status=?, updated_at=?, resolved_at=? WHERE case_id=?",
                    (status, now, resolved_at, case_id),
                )
            else:
                conn.execute(
                    "UPDATE cases SET status=?, updated_at=? WHERE case_id=?",
                    (status, now, case_id),
                )
            self._audit(conn, case_id, "STATUS_CHANGED", f"New status={status}", actor)
            conn.commit()
        finally:
            conn.close()
        return self.get_case(case_id)

    def update_case_status(self, case_id: str, status: str, notes: str = None, analyst: str = None, actor: str = "system") -> Optional[dict]:
        """Updates case status, sets assignee (analyst), and optionally appends notes."""
        if status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid status. Must be one of: {self.VALID_STATUSES}")
        now = self._now()
        resolved_at = now if status in ("resolved", "closed") else None

        conn = self._connect()
        try:
            if resolved_at:
                if analyst:
                    conn.execute(
                        "UPDATE cases SET status=?, assignee=?, updated_at=?, resolved_at=? WHERE case_id=?",
                        (status, analyst, now, resolved_at, case_id),
                    )
                else:
                    conn.execute(
                        "UPDATE cases SET status=?, updated_at=?, resolved_at=? WHERE case_id=?",
                        (status, now, resolved_at, case_id),
                    )
            else:
                if analyst:
                    conn.execute(
                        "UPDATE cases SET status=?, assignee=?, updated_at=? WHERE case_id=?",
                        (status, analyst, now, case_id),
                    )
                else:
                    conn.execute(
                        "UPDATE cases SET status=?, updated_at=? WHERE case_id=?",
                        (status, now, case_id),
                    )
            self._audit(conn, case_id, "STATUS_CHANGED", f"New status={status}, Assignee={analyst or 'no change'}", actor)
            conn.commit()
        finally:
            conn.close()

        if notes:
            self.add_note(case_id, notes, author=analyst or actor)

        return self.get_case(case_id)

    def assign_case(self, case_id: str, assignee: str, actor: str = "system") -> Optional[dict]:
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE cases SET assignee=?, updated_at=? WHERE case_id=?",
                (assignee, self._now(), case_id),
            )
            self._audit(conn, case_id, "CASE_ASSIGNED", f"Assignee={assignee}", actor)
            conn.commit()
        finally:
            conn.close()
        return self.get_case(case_id)

    def escalate_case(self, case_id: str, reason: str = "", actor: str = "system") -> Optional[dict]:
        return self.update_status(case_id, "escalated", actor)

    def link_incident(self, case_id: str, incident_id: str, actor: str = "system") -> Optional[dict]:
        """Link an incident ID to an existing case."""
        conn = self._connect()
        try:
            row = conn.execute("SELECT incident_ids FROM cases WHERE case_id=?", (case_id,)).fetchone()
            if not row:
                return None
            existing = json.loads(row["incident_ids"])
            if incident_id not in existing:
                existing.append(incident_id)
            conn.execute(
                "UPDATE cases SET incident_ids=?, updated_at=? WHERE case_id=?",
                (json.dumps(existing), self._now(), case_id),
            )
            self._audit(conn, case_id, "INCIDENT_LINKED", f"IncidentID={incident_id}", actor)
            conn.commit()
        finally:
            conn.close()
        return self.get_case(case_id)

    # ── Notes ────────────────────────────────────────────────────────────────

    def add_note(self, case_id: str, content: str, author: str = "system") -> dict:
        note_id = f"note-{uuid.uuid4().hex[:8]}"
        now = self._now()
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO case_notes (note_id, case_id, author, content, created_at) VALUES (?,?,?,?,?)",
                (note_id, case_id, author, content, now),
            )
            conn.execute("UPDATE cases SET updated_at=? WHERE case_id=?", (now, case_id))
            self._audit(conn, case_id, "NOTE_ADDED", f"Author={author}", author)
            conn.commit()
        finally:
            conn.close()
        return {"note_id": note_id, "case_id": case_id, "author": author, "content": content, "created_at": now}

    def get_notes(self, case_id: str) -> List[dict]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM case_notes WHERE case_id=? ORDER BY created_at ASC", (case_id,)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # ── Evidence ─────────────────────────────────────────────────────────────

    def add_evidence(
        self, case_id: str, label: str, value: str,
        evidence_type: str = "artifact", added_by: str = "system"
    ) -> dict:
        evidence_id = f"ev-{uuid.uuid4().hex[:8]}"
        now = self._now()
        conn = self._connect()
        try:
            conn.execute(
                """INSERT INTO case_evidence
                   (evidence_id, case_id, evidence_type, label, value, added_by, created_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (evidence_id, case_id, evidence_type, label, value, added_by, now),
            )
            conn.execute("UPDATE cases SET updated_at=? WHERE case_id=?", (now, case_id))
            self._audit(conn, case_id, "EVIDENCE_ADDED", f"Label={label}", added_by)
            conn.commit()
        finally:
            conn.close()
        return {
            "evidence_id": evidence_id, "case_id": case_id, "evidence_type": evidence_type,
            "label": label, "value": value, "added_by": added_by, "created_at": now,
        }

    def get_evidence(self, case_id: str) -> List[dict]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM case_evidence WHERE case_id=? ORDER BY created_at ASC", (case_id,)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # ── Audit Trail ──────────────────────────────────────────────────────────

    def get_audit_trail(self, case_id: str) -> List[dict]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM case_audit WHERE case_id=? ORDER BY created_at ASC", (case_id,)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # ── Stats ────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        conn = self._connect()
        try:
            total = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
            by_status = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM cases GROUP BY status"
            ).fetchall()
            by_priority = conn.execute(
                "SELECT priority, COUNT(*) as cnt FROM cases GROUP BY priority"
            ).fetchall()
            return {
                "total": total,
                "by_status": {r["status"]: r["cnt"] for r in by_status},
                "by_priority": {r["priority"]: r["cnt"] for r in by_priority},
            }
        finally:
            conn.close()
