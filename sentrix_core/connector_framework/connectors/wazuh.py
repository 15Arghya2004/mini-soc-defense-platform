"""connectors/wazuh.py — Wazuh ingestion and enrichment connector."""
import logging
from sentrix_core.connector_framework.base_connector import BaseConnector

logger = logging.getLogger("sentrix.connector.wazuh")

class WazuhConnector(BaseConnector):
    name = "wazuh"
    enabled = False

    def enrich(self, ip: str) -> dict:
        # Wazuh is primarily for ingestion, but could query active agents by IP
        return {}

    def ingest(self, payload: dict) -> dict:
        """Normalize a Wazuh alert to Sentrix SCEF format."""
        data = payload.get("data", {})
        return {
            "source": {"ip": data.get("srcip", payload.get("agent", {}).get("ip", ""))},
            "destination": {"ip": data.get("dstip", "")},
            "timestamp": payload.get("timestamp", ""),
            "event_type": payload.get("rule", {}).get("groups", ["unknown"])[0],
            "raw": payload
        }
