"""connectors/sysmon.py — Sysmon ingestion connector."""
import logging
from sentrix_core.connector_framework.base_connector import BaseConnector

logger = logging.getLogger("sentrix.connector.sysmon")

class SysmonConnector(BaseConnector):
    name = "sysmon"
    enabled = False

    def enrich(self, ip: str) -> dict:
        return {}

    def ingest(self, payload: dict) -> dict:
        """Normalize a Sysmon Event to Sentrix SCEF format."""
        event_data = payload.get("EventData", {})
        return {
            "source": {"ip": event_data.get("SourceIp", "")},
            "destination": {"ip": event_data.get("DestinationIp", "")},
            "timestamp": payload.get("System", {}).get("TimeCreated", {}).get("SystemTime", ""),
            "event_type": "process_creation" if payload.get("System", {}).get("EventID") == 1 else "sysmon_event",
            "raw": payload
        }
