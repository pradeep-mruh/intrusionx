"""
Reconstruction and ReconstructionStep Pydantic schemas.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from app.schemas.common import IdentifiableSchema

ReconstructionStatus = Literal["DRAFT", "UNDER_REVIEW", "ACCEPTED", "REJECTED"]
StepType = Literal["EVENT", "RELATIONSHIP", "GAP", "NOTE"]


class ReconstructionCreate(BaseModel):
    investigation_id: UUID
    title: str = Field(..., max_length=500)
    description: str | None = None
    status: ReconstructionStatus = "DRAFT"


class ReconstructionUpdate(BaseModel):
    title: str | None = Field(default=None, max_length=500)
    description: str | None = None
    status: ReconstructionStatus | None = None


class ReconstructionRead(IdentifiableSchema):
    investigation_id: UUID
    title: str
    description: str | None
    status: ReconstructionStatus
    created_at: datetime
    updated_at: datetime


class ReconstructionStepCreate(BaseModel):
    reconstruction_id: UUID
    step_order: int = Field(..., description="Sequence ordering index (e.g., 10, 20, 30)")
    step_type: StepType
    event_id: UUID | None = None
    relationship_id: UUID | None = None
    gap_id: UUID | None = None
    analyst_note: str | None = None

    @model_validator(mode="after")
    def validate_step_fk(self) -> "ReconstructionStepCreate":
        if self.step_type == "EVENT" and not self.event_id:
            raise ValueError("event_id must be provided when step_type is EVENT")
        if self.step_type == "RELATIONSHIP" and not self.relationship_id:
            raise ValueError("relationship_id must be provided when step_type is RELATIONSHIP")
        if self.step_type == "GAP" and not self.gap_id:
            raise ValueError("gap_id must be provided when step_type is GAP")
        if self.step_type == "NOTE" and any((self.event_id, self.relationship_id, self.gap_id)):
            raise ValueError("FKs must not be provided when step_type is NOTE")
        return self


class ReconstructionStepRead(IdentifiableSchema):
    reconstruction_id: UUID
    step_order: int
    step_type: StepType
    event_id: UUID | None
    relationship_id: UUID | None
    gap_id: UUID | None
    analyst_note: str | None
