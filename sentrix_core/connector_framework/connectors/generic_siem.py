"""connectors/generic_siem.py — Generic SIEM ingestion connector."""
import logging
from sentrix_core.connector_framework.base_connector import BaseConnector

logger = logging.getLogger("sentrix.connector.generic_siem")

class GenericSIEMConnector(BaseConnector):
    name = "generic_siem"
    enabled = False

    def enrich(self, ip: str) -> dict:
        return {}

    def ingest(self, payload: dict) -> dict:
        """Fallback normalization for generic SIEM alerts."""
        return {
            "source": {"ip": payload.get("source_ip", payload.get("src_ip", ""))},
            "destination": {"ip": payload.get("destination_ip", payload.get("dst_ip", ""))},
            "timestamp": payload.get("timestamp", payload.get("time", "")),
            "event_type": payload.get("event_type", payload.get("type", "generic_alert")),
            "raw": payload
        }
