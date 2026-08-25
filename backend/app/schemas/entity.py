"""
Entity and EventEntityRef Pydantic schemas.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import IdentifiableSchema

EntityType = Literal["HOST", "USER", "PROCESS", "IP_ADDRESS", "DOMAIN", "FILE", "ACCOUNT"]
EntityRole = Literal[
    "SOURCE_HOST",
    "TARGET_HOST",
    "ACTING_USER",
    "ACTING_PROCESS",
    "PARENT_PROCESS",
    "SOURCE_IP",
    "DESTINATION_IP",
    "TARGET_FILE",
    "TARGET_DOMAIN",
]


class EntityCreate(BaseModel):
    investigation_id: UUID
    entity_type: EntityType
    canonical_value: str = Field(..., max_length=1000)
    attributes: dict | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None


class EntityRead(IdentifiableSchema):
    investigation_id: UUID
    entity_type: str
    canonical_value: str
    attributes: dict | None
    first_seen_at: datetime | None
    last_seen_at: datetime | None


class EventEntityRefCreate(BaseModel):
    event_id: UUID
    entity_id: UUID
    role: EntityRole


class EventEntityRefRead(IdentifiableSchema):
    event_id: UUID
    entity_id: UUID
    role: str
