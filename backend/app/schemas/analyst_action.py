"""
AnalystAction Pydantic schemas.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import IdentifiableSchema

ActionType = Literal[
    "CONFIRM_RELATIONSHIP",
    "REJECT_RELATIONSHIP",
    "CONNECT_EVENTS",
    "DISCONNECT_EVENTS",
    "CONFIRM_RECONSTRUCTION_STEP",
    "REJECT_RECONSTRUCTION_STEP",
    "ADD_INVESTIGATION_NOTE",
    "MARK_EVIDENCE_RELEVANT",
    "RESOLVE_CONFLICT",
    "DISMISS_CONFLICT",
    "CONFIRM_HYPOTHESIS",
    "REJECT_HYPOTHESIS",
    "CLOSE_INVESTIGATION",
]

TargetObjectType = Literal[
    "RELATIONSHIP",
    "EVENT",
    "RECONSTRUCTION",
    "RECONSTRUCTION_STEP",
    "HYPOTHESIS",
    "EVIDENCE",
    "CONFLICT",
    "GAP",
    "INVESTIGATION",
]


class AnalystActionCreate(BaseModel):
    investigation_id: UUID
    analyst_id: UUID
    action_type: ActionType
    target_object_type: TargetObjectType
    target_object_id: UUID
    previous_state: dict | None = None
    new_state: dict
    reason: str | None = Field(default=None, description="Analyst reason for decision")


class AnalystActionRead(IdentifiableSchema):
    investigation_id: UUID
    analyst_id: UUID
    action_type: ActionType
    target_object_type: TargetObjectType
    target_object_id: UUID
    previous_state: dict | None
    new_state: dict
    reason: str | None
    acted_at: datetime
