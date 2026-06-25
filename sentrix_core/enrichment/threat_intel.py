"""
sentrix_core/enrichment/threat_intel.py
Threat Intelligence Enrichment Pipeline.
"""
import logging
from sentrix_core.connector_framework.registry import ConnectorRegistry

logger = logging.getLogger("sentrix.enrichment.ti")

class ThreatIntelEnricher:
    def __init__(self):
        self.registry = ConnectorRegistry()

    def enrich_ip(self, ip: str) -> dict:
        """Enrich a single IP using the Connector Registry."""
        if not ip or ip in ["127.0.0.1", "localhost", "0.0.0.0", "unknown"]:
            return {}
        
        enrichment_data = self.registry.enrich_ip(ip)
        return enrichment_data

    def enrich_event(self, event_dict: dict) -> dict:
        """
        Enrich an entire normalized event dictionary.
        This runs pre-detection.
        """
        src_ip = event_dict.get("source", {}).get("ip")
        ti = {}
        if src_ip:
            ti = self.enrich_ip(src_ip)
            if not ti or "reputation" not in ti:
                ti = {"reputation": "clean", "source": "threat_intel"}
            event_dict["source"]["ti_enrichment"] = ti
            
        dst_ip = event_dict.get("destination", {}).get("ip")
        if dst_ip:
            ti_dst = self.enrich_ip(dst_ip)
            if not ti_dst or "reputation" not in ti_dst:
                ti_dst = {"reputation": "clean", "source": "threat_intel"}
            event_dict["destination"]["ti_enrichment"] = ti_dst
            
        # Put on root level as well for compatibility / tests
        if ti:
            event_dict["ti_enrichment"] = ti
        else:
            event_dict["ti_enrichment"] = {"reputation": "clean", "source": "threat_intel"}
            
        return event_dict
