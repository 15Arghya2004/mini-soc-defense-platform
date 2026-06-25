"""
sentrix_core/config/settings.py
Centralized environment-driven configuration for Sentrix V7.
All secrets are sourced exclusively from environment variables.
"""
import os
from functools import lru_cache


class Settings:
    # ── Platform Security ──────────────────────────────────────
    SENTRIX_API_KEY: str = os.getenv("SENTRIX_API_KEY", "")
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))
    AUTH_ENABLED: bool = os.getenv("SENTRIX_AUTH_ENABLED", "true").lower() == "true"

    # ── AI Integration ─────────────────────────────────────────
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")

    # ── Threat Intelligence Connectors ────────────────────────
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
    GEOIP_API_KEY: str = os.getenv("GEOIP_API_KEY", "")
    CUSTOM_FEED_URL: str = os.getenv("CUSTOM_FEED_URL", "")

    # ── SIEM / EDR Connectors ──────────────────────────────────────
    WAZUH_URL: str = os.getenv("WAZUH_URL", "")
    WAZUH_API_KEY: str = os.getenv("WAZUH_API_KEY", "")
    WAZUH_USERNAME: str = os.getenv("WAZUH_USERNAME", "")
    WAZUH_PASSWORD: str = os.getenv("WAZUH_PASSWORD", "")
    SIEM_WEBHOOK_URL: str = os.getenv("SIEM_WEBHOOK_URL", "")

    # ── Collector Configuration ────────────────────────────────────
    # Path inside the Wazuh container (shared volume)
    WAZUH_ALERTS_PATH: str = os.getenv("WAZUH_ALERTS_PATH", "/var/ossec/logs/alerts/alerts.json")
    # Suricata eve.json path inside suricata collector container
    SURICATA_EVE_PATH: str = os.getenv("SURICATA_EVE_PATH", "/var/log/suricata/eve.json")
    # Internal API URL (used by collector containers to reach sentrix-core)
    SENTRIX_API_URL: str = os.getenv("SENTRIX_API_URL", "http://sentrix-core:8000")

    # ── Storage ────────────────────────────────────────────────
    DATA_DIR: str = os.getenv("DATA_DIR", "/data")

    # ── Logging ────────────────────────────────────────────────
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # ── Server ─────────────────────────────────────────────────
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))

    # ── Derived Paths ──────────────────────────────────────────
    @property
    def rules_dir(self) -> str:
        return os.path.join(self.DATA_DIR, "rule-repository")

    @property
    def custom_rules_dir(self) -> str:
        return os.path.join(self.DATA_DIR, "custom-rules", "active")

    @property
    def event_bus_db(self) -> str:
        return os.path.join(self.DATA_DIR, "event_bus", "events.db")

    @property
    def predictions_db(self) -> str:
        return os.path.join(self.DATA_DIR, "predictions", "predictions.db")

    @property
    def investigations_db(self) -> str:
        return os.path.join(self.DATA_DIR, "investigations", "investigations.db")

    @property
    def exports_dir(self) -> str:
        return os.path.join(self.DATA_DIR, "exports")

    @property
    def connectors_config(self) -> str:
        return os.path.join(self.DATA_DIR, "connectors", "config.json")

    @property
    def events_db(self) -> str:
        """Persistent event store for dashboard consumption."""
        return os.path.join(self.DATA_DIR, "events", "events.db")

    def ensure_dirs(self):
        """Create all required data directories on startup."""
        dirs = [
            self.rules_dir,
            self.custom_rules_dir,
            os.path.dirname(self.event_bus_db),
            os.path.dirname(self.predictions_db),
            os.path.dirname(self.investigations_db),
            self.exports_dir,
            os.path.dirname(self.connectors_config),
            os.path.dirname(self.events_db),
        ]
        for d in dirs:
            os.makedirs(d, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
