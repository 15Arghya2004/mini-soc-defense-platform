"""
asset_context.py
────────────────
Asset Context Manager — loads asset metadata from assets.yaml.

Replaces the previous hardcoded 4-IP dict with a YAML-configurable register.
The file is read once at startup; call reload() to pick up changes without
restarting the engine.

Unknown assets receive the `default_asset` values defined in assets.yaml
(criticality=0.3 by default — not inflated).
"""

import os
import logging

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

logger = logging.getLogger("sentrix.scoring.asset")

_DEFAULT_ASSET_FALLBACK = {
    "hostname":         "unknown",
    "criticality":      0.3,
    "network_exposure": 0.3,
    "data_sensitivity": 0.3,
    "environment":      "unknown",
    "owner":            "unassigned",
    "tags":             [],
}

_DEFAULT_ASSETS_YAML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets.yaml")


class AssetContextManager:
    """
    Loads asset metadata from assets.yaml and provides context enrichment
    for the Risk Calculator.

    Priority for asset lookup:
      1. Destination IP (primary target)
      2. Source IP (fallback)
      3. Hostname from event (string match against loaded register)
      4. Default asset values
    """

    def __init__(self, assets_path=None, asset_register=None, user_register=None):
        self._assets_path = assets_path or _DEFAULT_ASSETS_YAML
        self._asset_register = {}
        self._default_asset  = _DEFAULT_ASSET_FALLBACK.copy()

        # Allow constructor injection (unit tests, legacy compatibility)
        if asset_register is not None:
            # Legacy format: plain dict of IP→{criticality, ...}
            self._asset_register = {
                ip: {**_DEFAULT_ASSET_FALLBACK, **details}
                for ip, details in asset_register.items()
            }
        else:
            self._load_from_yaml()

        self._user_register = user_register or {
            "root":          "system",
            "administrator": "system",
            "domain_admin":  "admin",
            "db_admin":      "admin",
        }

    # ── Public ────────────────────────────────────────────────────────────────

    def reload(self):
        """Hot-reload assets.yaml without engine restart."""
        self._load_from_yaml()
        logger.info("[AssetContext] Asset register reloaded from %s (%d entries)",
                    self._assets_path, len(self._asset_register))

    def build_context(self, event, crisis_state=None):
        """Returns enrichment context dict for the Risk Calculator."""
        dest_ip  = event.get("destination", {}).get("ip") or event.get("dest_ip")
        src_ip   = event.get("source", {}).get("ip") or event.get("src_ip")
        hostname = (event.get("host", {}) or {}).get("hostname", "")
        user_name = (event.get("user", {}) or {}).get("name", "guest")

        asset_details = (
            self._asset_register.get(dest_ip)
            or self._asset_register.get(src_ip)
            or self._lookup_by_hostname(hostname)
            or self._default_asset.copy()
        )

        user_priv = self._user_register.get(user_name.lower(), "user")

        return {
            "crisis_mode":  crisis_state or {"enabled": False, "scope": None},
            "asset_context": asset_details,
            "user_context":  {
                "username":       user_name,
                "privilege_level": user_priv,
            },
        }

    def get_asset(self, ip_or_hostname):
        """Direct lookup by IP or hostname. Returns None if not found."""
        if ip_or_hostname in self._asset_register:
            return self._asset_register[ip_or_hostname]
        return self._lookup_by_hostname(ip_or_hostname)

    # ── Private ───────────────────────────────────────────────────────────────

    def _load_from_yaml(self):
        if not _HAS_YAML:
            logger.warning("[AssetContext] PyYAML not available — using empty register")
            return
        if not os.path.exists(self._assets_path):
            logger.warning("[AssetContext] assets.yaml not found at %s — using defaults",
                           self._assets_path)
            return
        try:
            with open(self._assets_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            self._default_asset = {
                **_DEFAULT_ASSET_FALLBACK,
                **(data.get("default_asset") or {}),
            }

            raw_assets = data.get("assets") or {}
            self._asset_register = {}
            for ip, details in raw_assets.items():
                self._asset_register[str(ip)] = {
                    **self._default_asset,
                    **(details or {}),
                }

            logger.info("[AssetContext] Loaded %d assets from %s",
                        len(self._asset_register), self._assets_path)
        except Exception as exc:
            logger.error("[AssetContext] Failed to load assets.yaml: %s", exc)

    def _lookup_by_hostname(self, hostname):
        """Secondary lookup by hostname field (case-insensitive)."""
        if not hostname:
            return None
        hostname_lower = hostname.lower()
        for asset in self._asset_register.values():
            if asset.get("hostname", "").lower() == hostname_lower:
                return asset
        return None


# Alias for backward compatibility with SentrixThreatEngine import
ContextBuilder = AssetContextManager
