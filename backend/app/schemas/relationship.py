"""
Relationship and RelationshipSupport Pydantic schemas.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from app.schemas.common import IdentifiableSchema

RelationshipStatus = Literal["SYSTEM_PROPOSED", "ANALYST_CONFIRMED", "ANALYST_REJECTED"]


class RelationshipCreate(BaseModel):
    investigation_id: UUID
    relationship_type: str = Field(..., max_length=100)
    source_event_id: UUID | None = None
    source_entity_id: UUID | None = None
    target_event_id: UUID | None = None
    target_entity_id: UUID | None = None
    creation_method: str = Field(..., max_length=100)
    status: RelationshipStatus = "SYSTEM_PROPOSED"
    explanation: str = Field(..., description="Explainable reason for this relationship")

    @model_validator(mode="after")
    def validate_endpoints(self) -> "RelationshipCreate":
        source_count = sum(1 for x in (self.source_event_id, self.source_entity_id) if x is not None)
        if source_count != 1:
            raise ValueError("Exactly one of source_event_id or source_entity_id must be provided")

        target_count = sum(1 for x in (self.target_event_id, self.target_entity_id) if x is not None)
        if target_count != 1:
            raise ValueError("Exactly one of target_event_id or target_entity_id must be provided")

        if self.source_event_id and self.target_event_id and self.source_event_id == self.target_event_id:
            raise ValueError("Self-reference on identical source and target event is not allowed")

        if self.source_entity_id and self.target_entity_id and self.source_entity_id == self.target_entity_id:
            raise ValueError("Self-reference on identical source and target entity is not allowed")

        return self


class RelationshipUpdateStatus(BaseModel):
    status: RelationshipStatus
    reason: str | None = Field(default=None, description="Analyst reason for status change")


class RelationshipRead(IdentifiableSchema):
    investigation_id: UUID
    relationship_type: str
    source_event_id: UUID | None
    source_entity_id: UUID | None
    target_event_id: UUID | None
    target_entity_id: UUID | None
    creation_method: str
    status: RelationshipStatus
    explanation: str
    created_at: datetime
    status_changed_at: datetime | None


class RelationshipSupportCreate(BaseModel):
    relationship_id: UUID
    event_id: UUID
    support_reason: str = Field(..., max_length=200)


class RelationshipSupportRead(IdentifiableSchema):
    relationship_id: UUID
    event_id: UUID
    support_reason: str
