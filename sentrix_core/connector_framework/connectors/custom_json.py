"""connectors/custom_json.py — Custom JSON Feed ingestion connector."""
import logging
from sentrix_core.connector_framework.base_connector import BaseConnector
from sentrix_core.config.settings import get_settings

logger = logging.getLogger("sentrix.connector.custom_json")

class CustomJSONConnector(BaseConnector):
    name = "custom_json"
    enabled = False

    def enrich(self, ip: str) -> dict:
        settings = get_settings()
        feed_url = getattr(settings, "CUSTOM_FEED_URL", None)
        if not feed_url:
            return {}
        try:
            import requests
            resp = requests.get(feed_url, timeout=5)
            if resp.status_code == 200:
                feed_data = resp.json()
                if isinstance(feed_data, list):
                    for entry in feed_data:
                        if entry.get("ip") == ip:
                            return {"match": entry, "source": "custom_json"}
        except Exception as e:
            logger.error(f"Custom JSON feed error for {ip}: {e}")
        return {}

    def ingest(self, payload: dict) -> dict:
        """Normalize a custom JSON payload to Sentrix SCEF format."""
        return {
            "source": {"ip": payload.get("src_ip", payload.get("source_ip", ""))},
            "destination": {"ip": payload.get("dst_ip", payload.get("dest_ip", ""))},
            "timestamp": payload.get("timestamp", ""),
            "event_type": payload.get("type", "custom"),
            "raw": payload
        }
