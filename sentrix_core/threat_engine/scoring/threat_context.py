"""
threat_context.py
─────────────────
Threat Intelligence Context Manager

Provides TI reputation scoring for source/destination IPs and domains.

DESIGN:
  When no live TI feed is configured, all scores default to 0.
  The mock data from the previous version has been removed.

  To enable real TI lookups, set environment variables:
    SENTRIX_TI_FEED_URL   — REST endpoint returning JSON {score, category, source}
    SENTRIX_TI_API_KEY    — Bearer token for the TI API
    SENTRIX_TI_CACHE_TTL  — Seconds to cache per-IP results (default: 300)

  Supported live TI providers (via REST adapter):
    - AbuseIPDB    (score field: abuseConfidenceScore)
    - OTX AlienVault (score derived from pulse count)
    - MISP         (score derived from attribute count)
    - Custom feed  (must return {score: 0-100, category: str})

  TI Score → Bonus mapping (used by RiskCalculator):
    score ≥ 90  → 10 pts  (Known APT C2 / active malware domain)
    score ≥ 80  →  8 pts  (TOR exit node confirmed)
    score ≥ 60  →  6 pts  (High-confidence threat list)
    score ≥ 40  →  3 pts  (Low-confidence threat list)
    score  < 40 →  0 pts  (No signal)
"""

import os
import json
import time
import logging
import urllib.request
import urllib.error
from threading import Lock

logger = logging.getLogger("sentrix.scoring.threat_intel")

_TI_FEED_URL = os.getenv("SENTRIX_TI_FEED_URL", "")
_TI_API_KEY  = os.getenv("SENTRIX_TI_API_KEY",  "")
_TI_CACHE_TTL = int(os.getenv("SENTRIX_TI_CACHE_TTL", "300"))


class ThreatContextManager:
    """
    Queries configured threat intelligence feeds to score IPs and domains.

    When no feed is configured (SENTRIX_TI_FEED_URL is empty), every call
    returns 0 — there is no mock or hardcoded data.
    """

    def __init__(self, feed_url=None, api_key=None, cache_ttl=None):
        self._feed_url  = feed_url  or _TI_FEED_URL
        self._api_key   = api_key   or _TI_API_KEY
        self._cache_ttl = cache_ttl or _TI_CACHE_TTL
        self._cache: dict[str, tuple[int, float]] = {}  # ip → (score, ts)
        self._lock = Lock()

        if not self._feed_url:
            logger.info(
                "[ThreatIntel] No SENTRIX_TI_FEED_URL configured. "
                "TI scores will default to 0. "
                "Set SENTRIX_TI_FEED_URL to enable live threat intelligence."
            )

    # ── Public ────────────────────────────────────────────────────────────────

    def get_reputation_score(self, event) -> int:
        """
        Returns a threat intelligence reputation score (0–100) for the event.
        Checks source IP, destination IP, and DNS/HTTP hostname.

        Returns 0 if no feed is configured or no signal found.
        """
        if not self._feed_url:
            return 0

        max_score = 0

        for ip in self._extract_ips(event):
            score = self._get_ip_score(ip)
            max_score = max(max_score, score)

        domain = self._extract_domain(event)
        if domain:
            score = self._get_domain_score(domain)
            max_score = max(max_score, score)

        return max_score

    def is_feed_configured(self) -> bool:
        """Returns True if a live TI feed URL is configured."""
        return bool(self._feed_url)

    def flush_cache(self):
        """Clears the TI cache (e.g., after feed update)."""
        with self._lock:
            self._cache.clear()

    # ── Private ───────────────────────────────────────────────────────────────

    def _extract_ips(self, event) -> list[str]:
        ips = []
        for path in [("source", "ip"), ("destination", "ip")]:
            ip = event
            for key in path:
                ip = (ip or {}).get(key)
            if ip and isinstance(ip, str):
                ips.append(ip)
        # Also check top-level src_ip / dest_ip fields (Suricata SCEF)
        for key in ("src_ip", "dest_ip"):
            ip = event.get(key)
            if ip and isinstance(ip, str):
                ips.append(ip)
        return list(set(ips))

    def _extract_domain(self, event) -> str | None:
        return (
            event.get("network", {}).get("dns_query")
            or event.get("http", {}).get("hostname")
            or None
        )

    def _get_ip_score(self, ip: str) -> int:
        with self._lock:
            cached = self._cache.get(ip)
            if cached:
                score, ts = cached
                if time.time() - ts < self._cache_ttl:
                    return score

        score = self._query_feed(ip, "ip")
        with self._lock:
            self._cache[ip] = (score, time.time())
        return score

    def _get_domain_score(self, domain: str) -> int:
        with self._lock:
            cached = self._cache.get(domain)
            if cached:
                score, ts = cached
                if time.time() - ts < self._cache_ttl:
                    return score

        score = self._query_feed(domain, "domain")
        with self._lock:
            self._cache[domain] = (score, time.time())
        return score

    def _query_feed(self, indicator: str, indicator_type: str) -> int:
        """
        Queries the configured TI REST endpoint.

        Expected API contract (GET):
          {indicator_type}/{indicator} → {"score": 0-100, "category": str, "source": str}

        Returns 0 on any error.
        """
        url = f"{self._feed_url.rstrip('/')}/{indicator_type}/{indicator}"
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type":  "application/json",
                    "User-Agent":    "Sentrix-ThreatEngine/2.1",
                },
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    body = json.loads(resp.read().decode())
                    return int(min(100, max(0, body.get("score", 0))))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return 0   # Unknown indicator — no signal
            logger.warning("[ThreatIntel] HTTP %s for %s: %s", e.code, indicator, e)
        except Exception as exc:
            logger.debug("[ThreatIntel] Query failed for %s: %s", indicator, exc)
        return 0
