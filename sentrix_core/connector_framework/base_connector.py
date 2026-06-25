"""
sentrix_core/connector_framework/base_connector.py
Base connector interface.
"""
from abc import ABC, abstractmethod

class BaseConnector(ABC):
    name: str = "base"
    enabled: bool = False

    @abstractmethod
    def enrich(self, ip: str) -> dict:
        """Enrich an IP address. Returns dict of findings."""
        pass

    @abstractmethod
    def ingest(self, payload: dict) -> dict:
        """Ingest raw payload and normalize it to Sentrix format."""
        pass
