"""
sentrix_core/collectors/wazuh_collector.py

Wazuh Alerts Collector for Sentrix V10.

Continuously monitors /var/ossec/logs/alerts/alerts.json,
deduplicates alerts, and forwards them to the Sentrix Threat Engine.

Features:
- Tails alerts.json in real-time (handles log rotation)
- Deduplicates by Wazuh alert ID (falls back to SHA256 hash)
- Auto-reconnects if file disappears or connection to Sentrix fails
- Exponential backoff on repeated POST failures
- Configurable via environment variables

Environment Variables:
    WAZUH_ALERTS_PATH   Path to Wazuh alerts.json (default: /var/ossec/logs/alerts/alerts.json)
    SENTRIX_API_URL     Sentrix API base URL (default: http://sentrix-core:8000)
    SENTRIX_API_KEY     API key for authentication (optional if auth disabled)
    LOG_LEVEL           Logging verbosity (default: INFO)
"""

import json
import os
import sys
import time
import hashlib
import logging
import requests
from datetime import datetime, timezone

# ── Configuration ──────────────────────────────────────────────────────────────

WAZUH_ALERTS_PATH = os.getenv(
    "WAZUH_ALERTS_PATH",
    "/var/ossec/logs/alerts/alerts.json"
)
SENTRIX_API_URL = os.getenv("SENTRIX_API_URL", "http://sentrix-core:8000")
SENTRIX_INGEST_URL = f"{SENTRIX_API_URL}/api/v1/threat/events/ingest"
SENTRIX_API_KEY = os.getenv("SENTRIX_API_KEY", "")

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# ── Logging ────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [WAZUH-COLLECTOR] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("wazuh_collector")

# ── Deduplication ──────────────────────────────────────────────────────────────

_seen_ids: set = set()
_MAX_SEEN = 100_000  # cap memory usage

def _get_alert_id(raw: dict, raw_line: str) -> str:
    """Extract or compute a unique identifier for this alert."""
    # Wazuh native alert ID
    native_id = raw.get("id")
    if native_id:
        return str(native_id)

    # Wazuh agent timestamp combo (also unique per manager)
    agent_id = raw.get("agent", {}).get("id", "")
    timestamp = raw.get("timestamp", "")
    rule_id = raw.get("rule", {}).get("id", "")
    if agent_id and timestamp and rule_id:
        return f"{agent_id}-{timestamp}-{rule_id}"

    # Fallback: SHA256 of raw line
    return hashlib.sha256(raw_line.encode("utf-8", errors="replace")).hexdigest()[:32]


def _is_duplicate(alert_id: str) -> bool:
    global _seen_ids
    if alert_id in _seen_ids:
        return True
    _seen_ids.add(alert_id)
    # Trim if over limit (keep most recent)
    if len(_seen_ids) > _MAX_SEEN:
        _seen_ids = set(list(_seen_ids)[-(_MAX_SEEN // 2):])
    return False

# ── Event Transformation ───────────────────────────────────────────────────────

def _build_payload(raw: dict) -> dict:
    """
    Transform a Wazuh alert dict into the Sentrix ingest payload format.
    Preserves all raw fields under event.raw for the normalizer.
    """
    rule = raw.get("rule", {})
    agent = raw.get("agent", {})
    data = raw.get("data", {})
    manager = raw.get("manager", {})

    # Attempt to extract source/destination IPs from various Wazuh data fields
    src_ip = (
        data.get("srcip")
        or data.get("src_ip")
        or data.get("source_ip")
        or data.get("attacker")
        or agent.get("ip")
        or raw.get("srcip")
        or "unknown"
    )
    dest_ip = (
        data.get("dstip")
        or data.get("dst_ip")
        or data.get("dest_ip")
        or manager.get("ip")
        or "unknown"
    )

    # Wazuh rule level → severity mapping
    level = int(rule.get("level", 0))
    if level >= 15:
        severity = "critical"
    elif level >= 12:
        severity = "high"
    elif level >= 8:
        severity = "medium"
    elif level >= 4:
        severity = "low"
    else:
        severity = "informational"

    return {
        "event": {
            # Standard Sentrix SCEF fields
            "source": {"ip": src_ip},
            "destination": {"ip": dest_ip},
            "timestamp": raw.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "event_type": "wazuh_alert",
            "severity": severity,

            # Wazuh-specific fields
            "rule": rule,
            "agent": agent,
            "agent_name": agent.get("name", "unknown"),
            "agent_ip": agent.get("ip", "unknown"),
            "rule_id": str(rule.get("id", "")),
            "rule_description": rule.get("description", ""),
            "rule_level": level,
            "rule_groups": rule.get("groups", []),
            "rule_mitre": rule.get("mitre", {}),
            "manager": manager.get("name", ""),
            "decoder": raw.get("decoder", {}).get("name", ""),
            "location": raw.get("location", ""),
            "full_log": raw.get("full_log", ""),
            "data": data,

            # Keep full raw for the normalizer
            "raw": raw,
        }
    }

# ── POST to Sentrix ────────────────────────────────────────────────────────────

_headers = {
    "Content-Type": "application/json",
    **({"X-API-Key": SENTRIX_API_KEY} if SENTRIX_API_KEY else {}),
}

def _post_to_sentrix(payload: dict, backoff: list) -> bool:
    """
    POST an event to Sentrix. Returns True on success.
    Updates backoff[0] on repeated failures (exponential backoff, cap 60s).
    """
    try:
        r = requests.post(
            SENTRIX_INGEST_URL,
            json=payload,
            headers=_headers,
            timeout=10,
        )
        if r.status_code in (200, 201, 202):
            backoff[0] = 0  # reset on success
            return True
        else:
            logger.warning("[POST] HTTP %d — %s", r.status_code, r.text[:200])
            return False
    except requests.exceptions.ConnectionError:
        logger.warning("[POST] Connection refused — Sentrix not ready yet")
        return False
    except Exception as e:
        logger.error("[POST] Error: %s", e)
        return False


def _wait_for_sentrix():
    """Block until Sentrix health endpoint responds."""
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
        logger.info("[INIT] Waiting for Sentrix (attempt %d, next retry in %ds)...", attempt, wait)
        time.sleep(wait)

# ── Main Tail Loop ─────────────────────────────────────────────────────────────

def _wait_for_file():
    """Block until alerts.json exists."""
    first = True
    while not os.path.exists(WAZUH_ALERTS_PATH):
        if first:
            logger.info("[WAIT] alerts.json not found at %s — waiting...", WAZUH_ALERTS_PATH)
            first = False
        time.sleep(3)
    logger.info("[READY] Found alerts.json at %s", WAZUH_ALERTS_PATH)


def _tail_alerts():
    """
    Main tail loop. Reads new lines from alerts.json continuously.
    Handles:
    - File growth (normal operation)
    - File truncation / log rotation (re-seeks to start)
    - File disappearance (waits for it to reappear)
    """
    backoff = [0]  # mutable for inner function
    last_inode = None
    last_size = 0
    consecutive_failures = 0

    while True:
        _wait_for_file()

        try:
            current_inode = os.stat(WAZUH_ALERTS_PATH).st_ino
            current_size = os.path.getsize(WAZUH_ALERTS_PATH)
        except FileNotFoundError:
            time.sleep(2)
            continue

        # Detect log rotation (inode change)
        if last_inode is not None and current_inode != last_inode:
            logger.info("[ROTATE] Log rotation detected — re-opening from start")
            last_size = 0

        last_inode = current_inode

        try:
            with open(WAZUH_ALERTS_PATH, "r", encoding="utf-8", errors="replace") as f:
                # Seek to where we left off
                if last_size > 0 and current_size >= last_size:
                    f.seek(last_size)
                else:
                    # File was truncated or first open — go to end
                    f.seek(0, os.SEEK_END)
                    last_size = f.tell()

                logger.info("[RUN] Tailing %s from offset %d", WAZUH_ALERTS_PATH, f.tell())

                while True:
                    line = f.readline()

                    if not line:
                        # No new data — check for rotation
                        try:
                            if os.stat(WAZUH_ALERTS_PATH).st_ino != last_inode:
                                break  # re-open
                            new_size = os.path.getsize(WAZUH_ALERTS_PATH)
                            if new_size < last_size:
                                break  # truncated — re-open from start
                            last_size = f.tell()
                        except FileNotFoundError:
                            break
                        time.sleep(0.5)
                        continue

                    line = line.strip()
                    if not line:
                        continue

                    # Parse JSON
                    try:
                        raw = json.loads(line)
                    except json.JSONDecodeError:
                        logger.debug("[PARSE] Skipped non-JSON line: %s", line[:80])
                        continue

                    # Deduplicate
                    alert_id = _get_alert_id(raw, line)
                    if _is_duplicate(alert_id):
                        continue

                    # Build and POST payload
                    payload = _build_payload(raw)
                    rule_desc = raw.get("rule", {}).get("description", "—")
                    agent_name = raw.get("agent", {}).get("name", "—")

                    logger.info(
                        "[EVENT] agent=%-20s rule=%s | %s",
                        agent_name,
                        raw.get("rule", {}).get("id", "?"),
                        rule_desc[:60],
                    )

                    # Apply backoff if previous failures
                    if backoff[0] > 0:
                        time.sleep(min(backoff[0], 60))

                    success = _post_to_sentrix(payload, backoff)
                    if success:
                        consecutive_failures = 0
                    else:
                        consecutive_failures += 1
                        backoff[0] = min(backoff[0] + 2, 60)
                        if consecutive_failures >= 10:
                            logger.warning(
                                "[BACKOFF] %d consecutive failures — backing off %ds",
                                consecutive_failures, backoff[0]
                            )

                    last_size = f.tell()

        except FileNotFoundError:
            logger.warning("[MISSING] alerts.json disappeared — will wait")
            last_size = 0
            time.sleep(2)
        except Exception as e:
            logger.error("[ERROR] Unexpected error in tail loop: %s", e)
            time.sleep(5)


# ── Entrypoint ─────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  SENTRIX WAZUH COLLECTOR — V10")
    print(f"  Alerts File : {WAZUH_ALERTS_PATH}")
    print(f"  Sentrix URL : {SENTRIX_INGEST_URL}")
    print(f"  Auth Key    : {'SET' if SENTRIX_API_KEY else 'NONE (auth disabled)'}")
    print("=" * 70)

    logger.info("[INIT] Waiting for Sentrix API to be ready...")
    _wait_for_sentrix()

    logger.info("[INIT] Starting tail loop...")
    _tail_alerts()


if __name__ == "__main__":
    main()
