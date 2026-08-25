"""
Hypothesis and HypothesisElement Pydantic schemas.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from app.schemas.common import IdentifiableSchema

HypothesisStatus = Literal["SUPPORTED", "REJECTED", "UNRESOLVED"]


class HypothesisCreate(BaseModel):
    investigation_id: UUID
    reconstruction_id: UUID | None = None
    title: str = Field(..., max_length=500)
    description: str | None = None
    status: HypothesisStatus = "UNRESOLVED"


class HypothesisUpdate(BaseModel):
    reconstruction_id: UUID | None = None
    title: str | None = Field(default=None, max_length=500)
    description: str | None = None
    status: HypothesisStatus | None = None


class HypothesisRead(IdentifiableSchema):
    investigation_id: UUID
    reconstruction_id: UUID | None
    title: str
    description: str | None
    status: HypothesisStatus
    created_at: datetime
    updated_at: datetime


class HypothesisElementCreate(BaseModel):
    hypothesis_id: UUID
    event_id: UUID | None = None
    relationship_id: UUID | None = None
    reconstruction_step_id: UUID | None = None
    evidence_id: UUID | None = None
    gap_id: UUID | None = None
    analyst_note: str | None = None

    @model_validator(mode="after")
    def validate_single_target(self) -> "HypothesisElementCreate":
        targets = [
            self.event_id,
            self.relationship_id,
            self.reconstruction_step_id,
            self.evidence_id,
            self.gap_id,
        ]
        count = sum(1 for t in targets if t is not None)
        if count != 1:
            raise ValueError("Exactly one target FK (event, relationship, step, evidence, or gap) must be set")
        return self


class HypothesisElementRead(IdentifiableSchema):
    hypothesis_id: UUID
    event_id: UUID | None
    relationship_id: UUID | None
    reconstruction_step_id: UUID | None
    evidence_id: UUID | None
    gap_id: UUID | None
    analyst_note: str | None
