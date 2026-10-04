from datetime import datetime
from typing import Any
import uuid

from pydantic import BaseModel, ConfigDict, Field


class InvestigationCreate(BaseModel):
    title: str = Field(..., max_length=500)
    description: str | None = None
    created_by: uuid.UUID


class WorkspaceInvestigation(BaseModel):
    id: uuid.UUID
    title: str
    status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class WorkspaceEvidence(BaseModel):
    id: uuid.UUID
    source_identifier: str
    content_hash: str
    imported_at: datetime
    normalized_event_count: int

    model_config = ConfigDict(from_attributes=True)


class WorkspaceEvent(BaseModel):
    id: uuid.UUID
    occurred_at: datetime
    event_type: str
    event_category: str
    source_host: str | None = None
    source_user: str | None = None
    process_name: str | None = None
    process_id: int | None = None
    parent_process_id: int | None = None
    file_path: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    action: str | None = None

    from pydantic import field_validator
    @field_validator("source_ip", "destination_ip", mode="before")
    @classmethod
    def serialize_ip(cls, v):
        return str(v) if v is not None else v

    model_config = ConfigDict(from_attributes=True)


class WorkspaceRelationship(BaseModel):
    id: uuid.UUID
    relationship_type: str
    status: str
    creation_method: str
    explanation: str | None = None
    source_event_id: uuid.UUID
    target_event_id: uuid.UUID
    status_changed_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class WorkspaceReconstructionStep(BaseModel):
    step_order: int
    step_type: str
    event_id: uuid.UUID | None = None
    relationship_id: uuid.UUID | None = None

    model_config = ConfigDict(from_attributes=True)


class WorkspaceReconstruction(BaseModel):
    id: uuid.UUID
    title: str
    status: str
    created_at: datetime
    steps: list[WorkspaceReconstructionStep]

    model_config = ConfigDict(from_attributes=True)


class WorkspaceAnalystAction(BaseModel):
    id: uuid.UUID
    action_type: str
    target_object_type: str
    target_object_id: uuid.UUID
    analyst_id: uuid.UUID
    previous_state: dict[str, Any]
    new_state: dict[str, Any]
    reason: str | None = None
    acted_at: datetime

    model_config = ConfigDict(from_attributes=True)


class WorkspaceResponse(BaseModel):
    investigation: WorkspaceInvestigation
    evidence: list[WorkspaceEvidence]
    events: list[WorkspaceEvent]
    relationships: list[WorkspaceRelationship]
    reconstruction: WorkspaceReconstruction | None
    unresolved_event_ids: list[uuid.UUID]
    analyst_actions: list[WorkspaceAnalystAction]


class CorrelationResponse(BaseModel):
    relationships_created: int
    relationships_skipped_duplicate: int


class ReconstructionResponse(BaseModel):
    reconstructions_created: int
    steps_created: int
    components_skipped_unsupported: int
    components_skipped_cycle: int


class RelationshipValidationRequest(BaseModel):
    analyst_id: uuid.UUID
    reason: str | None = None


class RelationshipValidationResponse(BaseModel):
    relationship_id: uuid.UUID
    status: str
    status_changed_at: datetime
