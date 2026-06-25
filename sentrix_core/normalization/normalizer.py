"""
sentrix_core/normalization/normalizer.py

Universal Event Normalizer for Sentrix V10.
Produces EXACTLY the identical schema required for the Threat Engine
regardless of whether the source is Wazuh or Suricata.
"""
import logging
import json
from typing import Dict, Any

logger = logging.getLogger("sentrix.normalizer")

class EventNormalizer:
    def __init__(self):
        pass

    def detect_source(self, raw: dict) -> str:
        """Heuristics to detect the source format of a raw event."""
        if "rule" in raw and isinstance(raw["rule"], dict) and ("agent" in raw or "data" in raw or "decoder" in raw):
            return "wazuh"
        if "event_type" in raw and "src_ip" in raw:
            return "suricata"
        return "generic"

    def normalize(self, raw: dict, source: str = None) -> Dict[str, Any]:
        """
        Normalize a raw event payload into the required flat schema.
        {
            source, timestamp, severity, event_type, protocol, 
            src_ip, dst_ip, src_port, dst_port, mitre, ioc, raw
        }
        """
        if not source:
            source = self.detect_source(raw)

        # 1. Defaults
        norm_event = {
            "source": {"ip": "unknown"},
            "destination": {"ip": "unknown"},
            "timestamp": "",
            "severity": "informational",
            "event_type": "unknown",
            "protocol": "unknown",
            "src_ip": "unknown",
            "dst_ip": "unknown",
            "src_port": 0,
            "dst_port": 0,
            "mitre": [],
            "ioc": [],
            "raw": raw
        }

        try:
            if source == "wazuh":
                rule = raw.get("rule", {})
                data = raw.get("data", {})
                agent = raw.get("agent", {})
                
                norm_event["timestamp"] = raw.get("timestamp", "")
                
                # Severity
                lvl = int(rule.get("level", 0))
                if lvl >= 15: norm_event["severity"] = "critical"
                elif lvl >= 12: norm_event["severity"] = "high"
                elif lvl >= 8: norm_event["severity"] = "medium"
                elif lvl >= 4: norm_event["severity"] = "low"
                
                norm_event["event_type"] = "wazuh_alert"
                norm_event["protocol"] = data.get("protocol", "unknown")
                
                # IPs
                src_ip = data.get("srcip") or data.get("src_ip") or agent.get("ip") or "unknown"
                dst_ip = data.get("dstip") or data.get("dst_ip") or "unknown"
                norm_event["src_ip"] = src_ip
                norm_event["dst_ip"] = dst_ip
                norm_event["source"]["ip"] = src_ip
                norm_event["destination"]["ip"] = dst_ip
                
                # Ports
                norm_event["src_port"] = int(data.get("srcport") or data.get("src_port") or 0)
                norm_event["dst_port"] = int(data.get("dstport") or data.get("dst_port") or 0)
                
                # Mitre
                mitre_list = []
                waz_mitre = rule.get("mitre", {})
                if isinstance(waz_mitre, dict):
                    tids = waz_mitre.get("id", [])
                    tacts = waz_mitre.get("tactic", [])
                    if not isinstance(tids, list): tids = [tids]
                    if not isinstance(tacts, list): tacts = [tacts]
                    for idx, tid in enumerate(tids):
                        tac = tacts[idx] if idx < len(tacts) else "unknown"
                        mitre_list.append({"id": tid, "tactic": tac})
                norm_event["mitre"] = mitre_list

            elif source == "suricata":
                norm_event["timestamp"] = raw.get("timestamp", "")
                
                alert = raw.get("alert", {})
                sev_num = alert.get("severity", 3)
                if sev_num == 1: norm_event["severity"] = "critical"
                elif sev_num == 2: norm_event["severity"] = "high"
                elif sev_num == 3: norm_event["severity"] = "medium"
                else: norm_event["severity"] = "low"
                
                norm_event["event_type"] = raw.get("event_type", "unknown")
                norm_event["protocol"] = raw.get("proto", "unknown")
                
                src_ip = raw.get("src_ip", "unknown")
                dst_ip = raw.get("dest_ip", "unknown")
                norm_event["src_ip"] = src_ip
                norm_event["dst_ip"] = dst_ip
                norm_event["source"]["ip"] = src_ip
                norm_event["destination"]["ip"] = dst_ip
                norm_event["src_port"] = int(raw.get("src_port", 0))
                norm_event["dst_port"] = int(raw.get("dest_port", 0))
                
                norm_event["mitre"] = [] # Extracted later by Threat Engine via rule mapping

            else:
                # Generic fallback extraction
                norm_event["timestamp"] = raw.get("timestamp", "")
                norm_event["event_type"] = raw.get("event_type", "unknown")
                norm_event["severity"] = raw.get("severity", "informational")
                src_ip = raw.get("src_ip") or raw.get("source", {}).get("ip") or "unknown"
                dst_ip = raw.get("dst_ip") or raw.get("destination", {}).get("ip") or "unknown"
                norm_event["src_ip"] = src_ip
                norm_event["dst_ip"] = dst_ip
                norm_event["source"]["ip"] = src_ip
                norm_event["destination"]["ip"] = dst_ip

            # IOC Extraction (basic hash extraction to fulfill ioc field)
            iocs = []
            payload_str = json.dumps(raw)
            import re
            hashes = set(re.findall(r'\b[a-fA-F0-9]{64}\b', payload_str)) # SHA256
            for h in hashes: iocs.append({"type": "sha256", "value": h})
            norm_event["ioc"] = iocs

        except Exception as e:
            logger.error(f"[Normalizer] Error normalizing {source} event: {e}")

        return {"event": norm_event}
