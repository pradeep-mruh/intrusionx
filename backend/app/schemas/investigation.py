"""
Investigation Pydantic schemas.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import IdentifiableSchema, ORMBase

InvestigationStatus = Literal["OPEN", "IN_PROGRESS", "CLOSED", "ARCHIVED"]


class InvestigationCreate(BaseModel):
    title: str = Field(..., max_length=500, description="Title of the investigation case")
    description: str | None = Field(default=None, description="Detailed case description")
    created_by: UUID = Field(..., description="UUID of the investigator creating the case")


class InvestigationUpdate(BaseModel):
    title: str | None = Field(default=None, max_length=500)
    description: str | None = None
    status: InvestigationStatus | None = None


class InvestigationRead(IdentifiableSchema):
    title: str
    description: str | None
    status: InvestigationStatus
    created_by: UUID
    created_at: datetime
    updated_at: datetime
