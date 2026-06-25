"""connectors/virustotal.py — VirusTotal IP enrichment connector."""
import logging
from sentrix_core.connector_framework.base_connector import BaseConnector
from sentrix_core.config.settings import get_settings

logger = logging.getLogger("sentrix.connector.virustotal")

class VirusTotalConnector(BaseConnector):
    name = "virustotal"
    enabled = False

    def enrich(self, ip: str) -> dict:
        settings = get_settings()
        if not getattr(settings, "VIRUSTOTAL_API_KEY", None):
            logger.debug("VirusTotal API key not configured")
            return {}
        try:
            import requests
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                return {
                    "malicious_votes": data.get("last_analysis_stats", {}).get("malicious", 0),
                    "reputation": data.get("reputation", 0),
                    "country": data.get("country", ""),
                    "source": "virustotal"
                }
        except Exception as e:
            logger.error(f"VirusTotal enrichment error for {ip}: {e}")
        return {}

    def ingest(self, payload: dict) -> dict:
        return payload
