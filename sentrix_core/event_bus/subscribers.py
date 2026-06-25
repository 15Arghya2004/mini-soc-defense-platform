"""
sentrix_core/event_bus/subscribers.py

Wires up all the pub/sub event handlers.
Engines do not call each other directly; they react to events on the bus.
"""
import logging
from sentrix_core.event_bus.bus import EventSubscriber, EventPublisher

logger = logging.getLogger("sentrix.subscribers")


def init_subscribers(engines):
    sub_raw = EventSubscriber()
    sub_alerts = EventSubscriber()
    sub_incidents = EventSubscriber()

    # ── 1. Raw Events Ingested ──────────────────────────────────────
    def handle_raw_event(msg):

        # Threat Engine performs normalization internally.
        if engines.threat:
            alerts = engines.threat.process_scef_event(msg)

            pub = EventPublisher()

            for alert in alerts:

                if "rule" in msg and isinstance(msg.get("rule"), dict):
                    source_type = "wazuh"
                elif "event_type" in msg and "src_ip" in msg:
                    source_type = "suricata"
                else:
                    source_type = "generic"

                if engines.event_store:
                    engines.event_store.store_alert(
                        alert,
                        source_type=source_type
                    )

                if not alert.get("_suppressed"):
                    pub.publish(
                        "alerts.generated",
                        {
                            "alert": alert,
                            "source_type": source_type
                        }
                    )

        # 1b. Automatic asset discovery & Timeline
        if engines.event_store:
            src_ip = (
                msg.get("src_ip")
                or msg.get("source", {}).get("ip")
                or msg.get("agent", {}).get("ip")
            )

            if src_ip:
                engines.event_store.store_asset(src_ip)

            engines.event_store.store_timeline_event(
                event_type="raw_event",
                ref_id=msg.get("event_hash", "unknown"),
                description=f"Ingested event from {msg.get('source', 'unknown')}",
                source_ip=src_ip,
                severity=msg.get("severity", "informational")
            )

    sub_raw.subscribe("events.ingested", handle_raw_event)

    # ── 2. Alerts Generated ──────────────────────────────────────────
    def handle_alert(msg):
        alert = msg.get("alert")
        source_type = msg.get("source_type")

        if engines.correlation:
            engines.correlation.ingest_alert(
                alert,
                source_type=source_type
            )

        if engines.prediction:
            engines.prediction.analyze_alert(alert)

        if (
            engines.investigation
            and alert.get("severity") in ["high", "critical"]
        ):
            engines.investigation.trigger_investigation(
                source_ip=alert.get("source_ip"),
                incident_id=None,
                severity=alert.get("severity")
            )

        if engines.event_store:
            engines.event_store.store_timeline_event(
                event_type="alert",
                ref_id=alert.get("alert_id", "unknown"),
                description=f"Generated alert: {alert.get('rule_name', 'Unknown')}",
                source_ip=alert.get("source_ip"),
                severity=alert.get("severity", "medium")
            )

    sub_alerts.subscribe("alerts.generated", handle_alert)

    # ── 3. Incidents Correlated ──────────────────────────────────────
    def handle_incident(msg):
        incident = msg.get("incident")

        if engines.event_store:
            engines.event_store.store_incident(incident)

        pub = EventPublisher()
        pub.publish(
            "soar.trigger",
            {
                "incident": incident
            }
        )

    sub_incidents.subscribe("incidents.correlated", handle_incident)

    logger.info("[EventBus] Subscribers initialized.")

    # Prevent garbage collection
    engines.subscribers = [
        sub_raw,
        sub_alerts,
        sub_incidents,
    ]