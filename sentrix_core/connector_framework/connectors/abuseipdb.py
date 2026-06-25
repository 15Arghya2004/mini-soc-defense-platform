"""connectors/abuseipdb.py — AbuseIPDB IP reputation connector."""
import logging
from sentrix_core.connector_framework.base_connector import BaseConnector
from sentrix_core.config.settings import get_settings

logger = logging.getLogger("sentrix.connector.abuseipdb")

class AbuseIPDBConnector(BaseConnector):
    name = "abuseipdb"
    enabled = False

    def enrich(self, ip: str) -> dict:
        settings = get_settings()
        if not getattr(settings, "ABUSEIPDB_API_KEY", None):
            return {}
        try:
            import requests
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                    "source": "abuseipdb"
                }
        except Exception as e:
            logger.error(f"AbuseIPDB enrichment error for {ip}: {e}")
        return {}

    def ingest(self, payload: dict) -> dict:
        return payload
