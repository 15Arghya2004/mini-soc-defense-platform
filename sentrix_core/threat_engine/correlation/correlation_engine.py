"""
sentrix_core/threat_engine/correlation/correlation_engine.py

Cross-Source Correlation Engine for Sentrix V10.

Purpose: Correlate alerts from BOTH Suricata and Wazuh into unified incidents.
- Groups alerts by source IP within a configurable time window
- Elevates severity when both sources confirm the same attacker
- Writes correlated incidents to the EventStore for dashboard consumption
- Does NOT replace existing sequence_engine / threshold_engine / attack_chain_engine
"""
import logging
import threading
import time
import json
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

logger = logging.getLogger("sentrix.correlation")

# Correlation window: alerts from the same IP within this window → one incident
CORRELATION_WINDOW_SECONDS = 300  # 5 minutes

# Minimum alerts from different sources to create a correlated incident
MIN_SOURCES_FOR_CORRELATION = 2


class CorrelationBucket:
    """Holds alerts for a single source IP within a time window."""

    def __init__(self, source_ip: str):
        self.source_ip = source_ip
        self.alerts: List[dict] = []
        self.sources_seen: set = set()
        self.max_risk: float = 0.0
        self.first_seen: str = datetime.now(timezone.utc).isoformat()
        self.last_seen: str = self.first_seen
        self.lock = threading.Lock()

    def add_alert(self, alert: dict, source_type: str):
        with self.lock:
            self.alerts.append({**alert, "_source_type": source_type})
            self.sources_seen.add(source_type)
            self.max_risk = max(self.max_risk, float(alert.get("risk_score", 0)))
            self.last_seen = datetime.now(timezone.utc).isoformat()

    def is_correlated(self) -> bool:
        """True when alerts from >= 2 distinct sources confirm this attacker."""
        with self.lock:
            return len(self.sources_seen) >= MIN_SOURCES_FOR_CORRELATION

    def is_expired(self) -> bool:
        """True when this bucket is older than CORRELATION_WINDOW_SECONDS."""
        try:
            last = datetime.fromisoformat(self.last_seen.replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - last).total_seconds()
            return age > CORRELATION_WINDOW_SECONDS
        except Exception:
            return True

    def build_incident(self) -> dict:
        """Build a correlated incident from collected alerts."""
        with self.lock:
            severities = [a.get("severity", "low") for a in self.alerts]
            sev_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
            top_sev = max(severities, key=lambda s: sev_rank.get(s, 0), default="medium")

            rule_names = list({a.get("rule_name", "Unknown") for a in self.alerts})
            mitre_techniques = []
            for a in self.alerts:
                for m in a.get("mitre_enrichment", []):
                    tid = m.get("id") or m.get("technique_id")
                    if tid and tid not in [x.get("id") for x in mitre_techniques]:
                        mitre_techniques.append(m)

            return {
                "incident_type":   "correlated",
                "source_ip":       self.source_ip,
                "severity":        top_sev,
                "risk_score":      round(self.max_risk, 1),
                "sources":         sorted(self.sources_seen),
                "alert_count":     len(self.alerts),
                "rule_names":      rule_names,
                "mitre_techniques": mitre_techniques,
                "first_seen":      self.first_seen,
                "last_seen":       self.last_seen,
                "alerts":          self.alerts,
                "correlated_at":   datetime.now(timezone.utc).isoformat(),
            }


class CorrelationEngine:
    """
    Correlates alerts across Suricata and Wazuh data sources.

    Usage:
        engine = CorrelationEngine()
        engine.ingest_alert(alert, source_type="suricata")
        engine.ingest_alert(alert, source_type="wazuh")
    """

    def __init__(self):
        self._buckets: Dict[str, CorrelationBucket] = {}
        self._bucket_lock = threading.Lock()
        self._correlated_incidents: List[dict] = []
        self._max_stored_incidents = 500

        # Start background cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="correlation-cleanup"
        )
        self._cleanup_thread.start()
        logger.info("[CorrelationEngine] Started (window=%ds)", CORRELATION_WINDOW_SECONDS)

    def ingest_alert(self, alert: dict, source_type: str = "suricata"):
        """
        Feed an alert into the correlation engine.
        Called by the threat route after every alert is generated.
        """
        source_ip = alert.get("source_ip", "unknown")
        if source_ip in ("unknown", "", None):
            return

        with self._bucket_lock:
            if source_ip not in self._buckets:
                self._buckets[source_ip] = CorrelationBucket(source_ip)
            bucket = self._buckets[source_ip]

        bucket.add_alert(alert, source_type)

        # Immediately emit correlated incident if threshold met
        if bucket.is_correlated():
            self._emit_incident(bucket, source_ip)

    def _emit_incident(self, bucket: CorrelationBucket, source_ip: str):
        """Build and store a correlated incident from a bucket."""
        incident = bucket.build_incident()

        # Deduplicate: don't re-emit the same incident within 60s
        now = datetime.now(timezone.utc)
        for existing in self._correlated_incidents[-20:]:
            if (
                existing.get("source_ip") == source_ip
                and existing.get("alert_count") == incident.get("alert_count")
            ):
                return

        self._correlated_incidents.append(incident)
        if len(self._correlated_incidents) > self._max_stored_incidents:
            self._correlated_incidents = self._correlated_incidents[-self._max_stored_incidents:]

        logger.info(
            "[CorrelationEngine] Correlated incident: %s | sources=%s | risk=%.1f | alerts=%d",
            source_ip, incident["sources"], incident["risk_score"], incident["alert_count"]
        )
        
        # Publish to event bus
        from sentrix_core.event_bus.bus import EventPublisher
        EventPublisher().publish("incidents.correlated", {"incident": incident})

    def _cleanup_loop(self):
        """Periodically evict expired buckets."""
        while True:
            try:
                time.sleep(60)
                with self._bucket_lock:
                    expired = [ip for ip, b in self._buckets.items() if b.is_expired()]
                    for ip in expired:
                        del self._buckets[ip]
                if expired:
                    logger.debug("[CorrelationEngine] Evicted %d expired buckets", len(expired))
            except Exception as e:
                logger.warning("[CorrelationEngine] Cleanup error: %s", e)

    # ── Read methods ───────────────────────────────────────────────────────────

    def get_correlated_incidents(self, limit: int = 100) -> List[dict]:
        """Returns the most recent correlated incidents."""
        return list(reversed(self._correlated_incidents[-limit:]))

    def get_active_buckets(self) -> List[dict]:
        """Returns currently active (non-expired) attacker buckets summary."""
        with self._bucket_lock:
            result = []
            for ip, bucket in self._buckets.items():
                if not bucket.is_expired():
                    with bucket.lock:
                        result.append({
                            "source_ip":    ip,
                            "sources":      sorted(bucket.sources_seen),
                            "alert_count":  len(bucket.alerts),
                            "max_risk":     bucket.max_risk,
                            "first_seen":   bucket.first_seen,
                            "last_seen":    bucket.last_seen,
                            "correlated":   bucket.is_correlated(),
                        })
            return sorted(result, key=lambda x: x["max_risk"], reverse=True)

    def get_status(self) -> dict:
        return {
            "status":               "healthy",
            "active_buckets":       len(self._buckets),
            "correlated_incidents": len(self._correlated_incidents),
            "window_seconds":       CORRELATION_WINDOW_SECONDS,
        }


# ── Singleton ──────────────────────────────────────────────────────────────────

_correlation_instance: Optional[CorrelationEngine] = None
_corr_lock = threading.Lock()


def get_correlation_engine() -> CorrelationEngine:
    global _correlation_instance
    if _correlation_instance is None:
        with _corr_lock:
            if _correlation_instance is None:
                _correlation_instance = CorrelationEngine()
    return _correlation_instance
