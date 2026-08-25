"""
EvidenceConflict and ConflictEvidence Pydantic schemas.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from app.schemas.common import IdentifiableSchema

ConflictStatus = Literal["OPEN", "RESOLVED", "DISMISSED"]


class EvidenceConflictCreate(BaseModel):
    investigation_id: UUID
    conflict_type: str = Field(..., max_length=100)
    status: ConflictStatus = "OPEN"
    description: str = Field(..., description="Detailed description of the contradiction")
    analyst_notes: str | None = None


class EvidenceConflictResolve(BaseModel):
    status: Literal["RESOLVED", "DISMISSED"]
    analyst_resolution: str = Field(..., description="Explanation of how the conflict was resolved or dismissed")
    resolved_by: UUID


class EvidenceConflictRead(IdentifiableSchema):
    investigation_id: UUID
    conflict_type: str
    status: ConflictStatus
    description: str
    analyst_resolution: str | None
    analyst_notes: str | None
    resolved_by: UUID | None
    resolved_at: datetime | None
    created_at: datetime


class ConflictEvidenceCreate(BaseModel):
    conflict_id: UUID
    evidence_id: UUID | None = None
    event_id: UUID | None = None

    @model_validator(mode="after")
    def validate_reference(self) -> "ConflictEvidenceCreate":
        if not self.evidence_id and not self.event_id:
            raise ValueError("At least one of evidence_id or event_id must be provided")
        return self


class ConflictEvidenceRead(IdentifiableSchema):
    conflict_id: UUID
    evidence_id: UUID | None
    event_id: UUID | None
