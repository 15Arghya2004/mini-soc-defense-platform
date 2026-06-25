"""connectors/shodan.py — Shodan IP intelligence connector."""
import logging
from sentrix_core.connector_framework.base_connector import BaseConnector
from sentrix_core.config.settings import get_settings

logger = logging.getLogger("sentrix.connector.shodan")

class ShodanConnector(BaseConnector):
    name = "shodan"
    enabled = False

    def enrich(self, ip: str) -> dict:
        settings = get_settings()
        if not getattr(settings, "SHODAN_API_KEY", None):
            return {}
        try:
            import requests
            resp = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": settings.SHODAN_API_KEY},
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "open_ports": data.get("ports", []),
                    "os": data.get("os", ""),
                    "org": data.get("org", ""),
                    "vulns": list(data.get("vulns", {}).keys()),
                    "source": "shodan"
                }
        except Exception as e:
            logger.error(f"Shodan enrichment error for {ip}: {e}")
        return {}

    def ingest(self, payload: dict) -> dict:
        return payload
