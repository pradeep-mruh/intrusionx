"""
NormalizedEvent Pydantic schemas.
"""

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import IdentifiableSchema

EventCategory = Literal["PROCESS", "NETWORK", "FILE", "AUTH", "REGISTRY", "SERVICE", "OTHER"]
ActionResult = Literal["SUCCESS", "FAILURE", "UNKNOWN"]


class NormalizedEventCreate(BaseModel):
    investigation_id: UUID
    evidence_id: UUID
    occurred_at: datetime
    event_type: str = Field(..., max_length=100)
    event_category: str = Field(..., max_length=50)

    # Host & user
    source_host: str | None = Field(default=None, max_length=255)
    source_user: str | None = Field(default=None, max_length=255)
    source_account: str | None = Field(default=None, max_length=255)

    # Process
    process_name: str | None = Field(default=None, max_length=500)
    process_id: str | None = Field(default=None, max_length=20)
    parent_process_name: str | None = Field(default=None, max_length=500)
    parent_process_id: str | None = Field(default=None, max_length=20)

    # Network
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)

    # File & domain
    file_path: str | None = None
    domain: str | None = Field(default=None, max_length=255)

    # Action
    action: str | None = Field(default=None, max_length=100)
    action_result: ActionResult | None = None

    # Extended attributes
    extended_attributes: dict | None = None


class NormalizedEventRead(IdentifiableSchema):
    investigation_id: UUID
    evidence_id: UUID
    occurred_at: datetime
    normalized_at: datetime
    event_type: str
    event_category: str

    source_host: str | None
    source_user: str | None
    source_account: str | None

    process_name: str | None
    process_id: str | None
    parent_process_name: str | None
    parent_process_id: str | None

    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None

    file_path: str | None
    domain: str | None

    action: str | None
    action_result: str | None

    extended_attributes: dict | None
