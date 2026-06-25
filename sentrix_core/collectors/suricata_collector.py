"""
sentrix_core/collectors/suricata_collector.py

Suricata Alerts Collector for Sentrix V10.
Tails eve.json and forwards all event types to Sentrix Threat Engine.
"""
import json
import os
import sys
import time
import requests
import logging
from datetime import datetime, timezone

# ── Configuration ──────────────────────────────────────────────────────────────
SURICATA_LOG = os.getenv(
    "SURICATA_LOG",
    r"C:\hackathon\suricata\eve.json"
)
SENTRIX_API_URL = os.getenv(
    "SENTRIX_API_URL",
    "http://localhost:8000"
)
SENTRIX_INGEST_URL = f"{SENTRIX_API_URL}/api/v1/threat/events/ingest"

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [SURI-COLLECTOR] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("suricata_collector")

def _wait_for_sentrix():
    health_url = f"{SENTRIX_API_URL}/api/v1/admin/health"
    attempt = 0
    while True:
        attempt += 1
        try:
            r = requests.get(health_url, timeout=5)
            if r.status_code == 200:
                logger.info("[INIT] Sentrix is ready.")
                return
        except Exception:
            pass
        wait = min(attempt * 2, 30)
        logger.info("[INIT] Waiting for Sentrix (attempt %d)...", attempt)
        time.sleep(wait)

def _build_payload(raw_event: dict) -> dict:
    event_type = raw_event.get("event_type", "unknown")
    
    # Extract severity
    severity = "informational"
    if event_type == "alert":
        sev_num = raw_event.get("alert", {}).get("severity", 3)
        if sev_num == 1: severity = "critical"
        elif sev_num == 2: severity = "high"
        elif sev_num == 3: severity = "medium"
        else: severity = "low"
    elif event_type == "anomaly":
        severity = "medium"

    return {
        "event": {
            "source": {"ip": raw_event.get("src_ip", "unknown")},
            "destination": {"ip": raw_event.get("dest_ip", "unknown")},
            "timestamp": raw_event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "event_type": event_type,
            "severity": severity,
            "protocol": raw_event.get("proto", "unknown"),
            
            # Additional Suricata fields
            "signature": raw_event.get("alert", {}).get("signature", ""),
            "signature_id": raw_event.get("alert", {}).get("signature_id", ""),
            "category": raw_event.get("alert", {}).get("category", ""),
            
            # Pass everything down for normalizer
            "raw": raw_event
        }
    }

def send_to_sentrix(payload: dict, backoff: list):
    try:
        r = requests.post(SENTRIX_INGEST_URL, json=payload, timeout=10)
        if r.status_code in (200, 201, 202):
            backoff[0] = 0
            return True
        else:
            logger.warning("[POST] HTTP %d: %s", r.status_code, r.text[:200])
            return False
    except requests.exceptions.ConnectionError:
        logger.warning("[POST] Connection refused.")
        return False
    except Exception as e:
        logger.error("[POST] Error: %s", e)
        return False

def follow_log():
    logger.info("=" * 70)
    logger.info("[*] Suricata Collector Started")
    logger.info("[*] Watching: %s", SURICATA_LOG)
    logger.info("=" * 70)

    first = True
    while not os.path.exists(SURICATA_LOG):
        if first:
            logger.info("[WAIT] eve.json not found... waiting")
            first = False
        time.sleep(3)

    backoff = [0]
    last_inode = None
    last_size = 0

    while True:
        try:
            current_inode = os.stat(SURICATA_LOG).st_ino
            current_size = os.path.getsize(SURICATA_LOG)
            
            if last_inode is not None and current_inode != last_inode:
                logger.info("[ROTATE] Log rotation detected.")
                last_size = 0
                
            last_inode = current_inode

            with open(SURICATA_LOG, "r", encoding="utf-8", errors="replace") as f:
                if last_size > 0 and current_size >= last_size:
                    f.seek(last_size)
                else:
                    f.seek(0, os.SEEK_END)
                    last_size = f.tell()

                while True:
                    line = f.readline()
                    if not line:
                        try:
                            if os.stat(SURICATA_LOG).st_ino != last_inode: break
                            if os.path.getsize(SURICATA_LOG) < last_size: break
                            last_size = f.tell()
                        except FileNotFoundError: break
                        time.sleep(0.5)
                        continue

                    line = line.strip()
                    if not line: continue

                    try:
                        raw = json.loads(line)
                        event_type = raw.get("event_type", "unknown")
                        
                        # Only skip stats if it's too noisy, but requirement says forward everything.
                        payload = _build_payload(raw)
                        
                        if backoff[0] > 0: time.sleep(min(backoff[0], 60))
                        
                        if send_to_sentrix(payload, backoff):
                            if event_type == 'alert':
                                logger.info("[EVENT] %s | %s", event_type.upper(), payload['event']['signature'])
                        else:
                            backoff[0] = min(backoff[0] + 2, 60)
                            
                    except json.JSONDecodeError:
                        continue
                        
                    last_size = f.tell()

        except FileNotFoundError:
            time.sleep(2)
        except Exception as e:
            logger.error("[ERROR] Tail loop: %s", e)
            time.sleep(5)

if __name__ == "__main__":
    _wait_for_sentrix()
    follow_log()