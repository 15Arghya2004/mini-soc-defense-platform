"""
sentrix_core/normalization/schema.py
Canonical Event Schema for Sentrix V8.
"""
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
import uuid
from datetime import datetime, timezone

class CanonicalEntity(BaseModel):
    ip: Optional[str] = None
    port: Optional[int] = None
    mac: Optional[str] = None
    hostname: Optional[str] = None

class CanonicalUser(BaseModel):
    name: Optional[str] = None
    id: Optional[str] = None
    domain: Optional[str] = None

class CanonicalProcess(BaseModel):
    name: Optional[str] = None
    pid: Optional[int] = None
    path: Optional[str] = None
    command_line: Optional[str] = None
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None

class CanonicalFile(BaseModel):
    name: Optional[str] = None
    path: Optional[str] = None
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    size: Optional[int] = None

class CanonicalThreat(BaseModel):
    category: Optional[str] = None
    signature: Optional[str] = None
    severity: Optional[str] = None
    mitre_tactics: Optional[List[str]] = Field(default_factory=list)
    mitre_techniques: Optional[List[str]] = Field(default_factory=list)

class CanonicalEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: f"EVT-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str = "unknown"
    severity: str = "info"
    source: CanonicalEntity = Field(default_factory=CanonicalEntity)
    destination: CanonicalEntity = Field(default_factory=CanonicalEntity)
    user: CanonicalUser = Field(default_factory=CanonicalUser)
    network: Dict[str, Any] = Field(default_factory=dict)
    process: CanonicalProcess = Field(default_factory=CanonicalProcess)
    file: CanonicalFile = Field(default_factory=CanonicalFile)
    threat: CanonicalThreat = Field(default_factory=CanonicalThreat)
    raw_event: Dict[str, Any] = Field(default_factory=dict)
    
    def dict_exclude_none(self) -> dict:
        return self.model_dump(exclude_none=True)
