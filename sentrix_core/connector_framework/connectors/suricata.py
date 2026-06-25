"""connectors/suricata.py — Suricata ingestion connector."""
import logging
from sentrix_core.connector_framework.base_connector import BaseConnector

logger = logging.getLogger("sentrix.connector.suricata")

class SuricataConnector(BaseConnector):
    name = "suricata"
    enabled = False

    def enrich(self, ip: str) -> dict:
        return {}

    def ingest(self, payload: dict) -> dict:
        """Normalize a Suricata EVE JSON event to Sentrix SCEF format."""
        return {
            "source": {"ip": payload.get("src_ip", "")},
            "destination": {"ip": payload.get("dest_ip", "")},
            "timestamp": payload.get("timestamp", ""),
            "event_type": payload.get("event_type", "suricata_alert"),
            "raw": payload
        }
