"""
prediction_store.py
────────────────────
SQLite-backed persistence layer for prediction results.
Uses Python built-in sqlite3 — no external dependencies.

Database: predictions.db (located in prediction-engine/storage/)
Table   : prediction_results
"""
import os
import json
import sqlite3
import logging
from datetime import datetime, timezone

logger = logging.getLogger("sentrix.prediction.store")

_DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "predictions.db"
)


class PredictionStore:
    """
    Manages persistence of prediction results to a local SQLite database.

    Schema
    ------
    id              : auto-increment primary key
    source_ip       : attacker source IP
    current_stage   : last observed MITRE stage
    predicted_stage : forecasted next stage
    probability     : 0-100
    confidence      : 0-100
    risk_level      : LOW / MEDIUM / HIGH / CRITICAL
    campaign        : predicted campaign type
    campaign_conf   : campaign classification confidence 0-99
    alert_count     : number of alerts ingested for this attacker
    forecast_json   : full forecast JSON blob
    created_at      : ISO timestamp
    """

    def __init__(self, db_path: str = None):
        self.db_path = db_path or _DEFAULT_DB_PATH
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Creates the predictions table if it doesn't exist."""
        conn = self._connect()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS prediction_results (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip       TEXT    NOT NULL,
                    current_stage   TEXT,
                    predicted_stage TEXT,
                    probability     INTEGER,
                    confidence      INTEGER,
                    risk_level      TEXT,
                    campaign        TEXT,
                    campaign_conf   INTEGER,
                    alert_count     INTEGER DEFAULT 1,
                    forecast_json   TEXT,
                    created_at      TEXT DEFAULT (datetime('now','utc'))
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_source_ip ON prediction_results(source_ip)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_created_at ON prediction_results(created_at)"
            )
            conn.commit()
        finally:
            conn.close()

    def save(self, forecast: dict) -> int:
        """
        Persists a forecast result to the database.
        Returns the new row ID.
        """
        conn = self._connect()
        try:
            cursor = conn.execute(
                """
                INSERT INTO prediction_results
                    (source_ip, current_stage, predicted_stage, probability,
                     confidence, risk_level, campaign, campaign_conf,
                     alert_count, forecast_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    forecast.get("source_ip", "unknown"),
                    forecast.get("current_stage", ""),
                    forecast.get("next_attack", ""),
                    int(forecast.get("probability", 0)),
                    int(forecast.get("confidence", 0)),
                    forecast.get("risk_level", "LOW"),
                    forecast.get("campaign", {}).get("likely_campaign", "Unknown"),
                    int(forecast.get("campaign", {}).get("confidence", 0)),
                    int(forecast.get("alert_count", 1)),
                    json.dumps(forecast),
                )
            )
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            logger.error("[PredictionStore] Save failed: %s", e)
            return -1
        finally:
            conn.close()

    def get_all(self, limit: int = 100) -> list:
        """Returns the most recent `limit` prediction results."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM prediction_results ORDER BY id DESC LIMIT ?",
                (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error("[PredictionStore] get_all failed: %s", e)
            return []
        finally:
            conn.close()

    def get_live(self) -> list:
        """Returns the latest prediction per source_ip (active tracked attackers)."""
        conn = self._connect()
        try:
            rows = conn.execute("""
                SELECT * FROM prediction_results
                WHERE id IN (
                    SELECT MAX(id) FROM prediction_results GROUP BY source_ip
                )
                ORDER BY id DESC
            """).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error("[PredictionStore] get_live failed: %s", e)
            return []
        finally:
            conn.close()

    def get_stats(self) -> dict:
        """Returns aggregate statistics across all stored predictions."""
        conn = self._connect()
        try:
            total          = conn.execute("SELECT COUNT(*) FROM prediction_results").fetchone()[0]
            attackers      = conn.execute("SELECT COUNT(DISTINCT source_ip) FROM prediction_results").fetchone()[0]
            avg_prob       = conn.execute("SELECT AVG(probability) FROM prediction_results").fetchone()[0] or 0
            avg_conf       = conn.execute("SELECT AVG(confidence) FROM prediction_results").fetchone()[0] or 0
            critical_count = conn.execute("SELECT COUNT(*) FROM prediction_results WHERE risk_level='CRITICAL'").fetchone()[0]
            high_count     = conn.execute("SELECT COUNT(*) FROM prediction_results WHERE risk_level='HIGH'").fetchone()[0]
            top_campaigns  = conn.execute("""
                SELECT campaign, COUNT(*) as cnt
                FROM prediction_results
                WHERE campaign IS NOT NULL AND campaign != 'Unknown'
                GROUP BY campaign ORDER BY cnt DESC LIMIT 5
            """).fetchall()

            return {
                "total_predictions":   total,
                "tracked_attackers":   attackers,
                "avg_probability":     round(avg_prob, 1),
                "avg_confidence":      round(avg_conf, 1),
                "critical_forecasts":  critical_count,
                "high_risk_forecasts": high_count,
                "top_campaigns":       [{"campaign": r[0], "count": r[1]} for r in top_campaigns],
            }
        except Exception as e:
            logger.error("[PredictionStore] get_stats failed: %s", e)
            return {}
        finally:
            conn.close()

    def clear(self):
        """Clears all records (for testing)."""
        conn = self._connect()
        try:
            conn.execute("DELETE FROM prediction_results")
            conn.commit()
        finally:
            conn.close()
