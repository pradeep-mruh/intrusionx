"""
EvidenceGap and GapEvent Pydantic schemas.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import IdentifiableSchema

GapStatus = Literal["OPEN", "EXPLAINED", "UNRESOLVABLE"]
GapEventRole = Literal["PRECEDING", "FOLLOWING"]


class EvidenceGapCreate(BaseModel):
    investigation_id: UUID
    gap_start: datetime | None = None
    gap_end: datetime | None = None
    description: str = Field(..., description="Description of missing telemetry context")
    status: GapStatus = "OPEN"
    analyst_notes: str | None = None


class EvidenceGapUpdate(BaseModel):
    gap_start: datetime | None = None
    gap_end: datetime | None = None
    description: str | None = None
    status: GapStatus | None = None
    analyst_notes: str | None = None


class EvidenceGapRead(IdentifiableSchema):
    investigation_id: UUID
    gap_start: datetime | None
    gap_end: datetime | None
    description: str
    status: GapStatus
    analyst_notes: str | None
    created_at: datetime


class GapEventCreate(BaseModel):
    gap_id: UUID
    event_id: UUID
    role: GapEventRole


class GapEventRead(IdentifiableSchema):
    gap_id: UUID
    event_id: UUID
    role: GapEventRole
