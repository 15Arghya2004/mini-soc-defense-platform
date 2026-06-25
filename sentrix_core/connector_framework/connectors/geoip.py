"""connectors/geoip.py — GeoIP location enrichment connector."""
import logging
from sentrix_core.connector_framework.base_connector import BaseConnector

logger = logging.getLogger("sentrix.connector.geoip")

class GeoIPConnector(BaseConnector):
    name = "geoip"
    enabled = False

    def enrich(self, ip: str) -> dict:
        try:
            import requests
            # Uses free ip-api.com (no key needed)
            resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,lat,lon", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("country", ""),
                        "region": data.get("regionName", ""),
                        "city": data.get("city", ""),
                        "isp": data.get("isp", ""),
                        "org": data.get("org", ""),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon"),
                        "source": "geoip"
                    }
        except Exception as e:
            logger.error(f"GeoIP enrichment error for {ip}: {e}")
        return {}

    def ingest(self, payload: dict) -> dict:
        return payload
