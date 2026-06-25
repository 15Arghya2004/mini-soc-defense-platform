"""
sentrix_core/connector_framework/registry.py
Connector registry.
"""
import os
import json
import logging
from typing import Dict, List
from sentrix_core.config.settings import get_settings
from sentrix_core.connector_framework.base_connector import BaseConnector
import importlib
import pkgutil
import sentrix_core.connector_framework.connectors as connectors_pkg

logger = logging.getLogger("sentrix.connector_registry")

class ConnectorRegistry:
    def __init__(self):
        self.settings = get_settings()
        self.connectors: Dict[str, BaseConnector] = {}
        self._load_config()
        self._discover_connectors()

    def _load_config(self):
        self.config_path = self.settings.connectors_config
        if os.path.exists(self.config_path):
            with open(self.config_path, "r") as f:
                try:
                    self.config_data = json.load(f)
                except json.JSONDecodeError:
                    self.config_data = {}
        else:
            self.config_data = {}

    def _save_config(self):
        with open(self.config_path, "w") as f:
            json.dump(self.config_data, f, indent=4)

    def _discover_connectors(self):
        """Dynamically load all connector classes from the connectors package."""
        prefix = connectors_pkg.__name__ + "."
        for _, modname, _ in pkgutil.iter_modules(connectors_pkg.__path__, prefix):
            try:
                module = importlib.import_module(modname)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if isinstance(attr, type) and issubclass(attr, BaseConnector) and attr is not BaseConnector:
                        instance = attr()
                        
                        # Set enabled status from config or default to False
                        is_enabled = self.config_data.get(instance.name, {}).get("enabled", False)
                        instance.enabled = is_enabled
                        
                        self.connectors[instance.name] = instance
                        logger.info(f"Loaded connector: {instance.name} (Enabled: {is_enabled})")
            except Exception as e:
                logger.error(f"Error loading connector {modname}: {e}")

    def get_connector(self, name: str) -> BaseConnector:
        return self.connectors.get(name)

    def get_all_connectors(self) -> List[dict]:
        return [{"name": name, "enabled": conn.enabled} for name, conn in self.connectors.items()]

    def enable_connector(self, name: str):
        if name in self.connectors:
            self.connectors[name].enabled = True
            if name not in self.config_data:
                self.config_data[name] = {}
            self.config_data[name]["enabled"] = True
            self._save_config()
            logger.info(f"Enabled connector: {name}")

    def disable_connector(self, name: str):
        if name in self.connectors:
            self.connectors[name].enabled = False
            if name not in self.config_data:
                self.config_data[name] = {}
            self.config_data[name]["enabled"] = False
            self._save_config()
            logger.info(f"Disabled connector: {name}")

    def enrich_ip(self, ip: str) -> dict:
        """Runs enrichment across all enabled connectors."""
        results = {}
        for name, connector in self.connectors.items():
            if connector.enabled:
                try:
                    res = connector.enrich(ip)
                    if res:
                        results[name] = res
                except Exception as e:
                    logger.error(f"Enrichment error for {name} on {ip}: {e}")
        return results
