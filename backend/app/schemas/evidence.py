"""
Evidence Pydantic schemas.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import IdentifiableSchema

EvidenceSourceType = Literal[
    "SYSMON",
    "WINDOWS_EVENT_LOG",
    "LINUX_AUTH_LOG",
    "NETWORK_TELEMETRY",
    "EDR",
    "STRUCTURED_JSON",
    "CSV",
    "OTHER",
]


class EvidenceCreate(BaseModel):
    investigation_id: UUID
    source_type: str = Field(..., max_length=100)
    source_identifier: str = Field(..., max_length=1000)
    original_content: str | None = None
    storage_reference: str | None = Field(default=None, max_length=2000)
    content_hash: str = Field(..., max_length=128)
    hash_algorithm: str = Field(default="SHA-256", max_length=20)
    source_metadata: dict | None = None


class EvidenceRead(IdentifiableSchema):
    investigation_id: UUID
    source_type: str
    source_identifier: str
    original_content: str | None
    storage_reference: str | None
    content_hash: str
    hash_algorithm: str
    source_metadata: dict | None
    imported_at: datetime
    is_immutable: bool
