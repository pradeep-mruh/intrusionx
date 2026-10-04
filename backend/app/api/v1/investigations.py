import uuid
from typing import Sequence

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
import logging

from app.core.database import get_session
from app.models.investigation import Investigation
from app.models.evidence import Evidence
from app.models.normalized_event import NormalizedEvent
from app.models.relationship import Relationship
from app.models.reconstruction import Reconstruction, ReconstructionStep
from app.models.analyst_action import AnalystAction

from app.schemas.workspace import (
    InvestigationCreate,
    WorkspaceResponse,
    CorrelationResponse,
    ReconstructionResponse,
    RelationshipValidationRequest,
    RelationshipValidationResponse,
)

from app.correlation.service import (
    correlate_process_parent_child,
    correlate_process_file_activity,
)
from app.reconstruction.service import build_reconstruction
from app.investigation.service import (
    confirm_relationship,
    reject_relationship,
    RelationshipNotFoundError,
    InvalidRelationshipTransitionError,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/investigations", tags=["investigations"])


@router.post("", response_model=dict, status_code=status.HTTP_201_CREATED)
async def create_investigation(
    req: InvestigationCreate, session: AsyncSession = Depends(get_session)
):
    investigation = Investigation(
        title=req.title,
        description=req.description,
        created_by=req.created_by,
    )
    session.add(investigation)
    try:
        await session.commit()
        await session.refresh(investigation)
    except SQLAlchemyError as e:
        await session.rollback()
        logger.error(f"Failed to create investigation: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

    return {
        "id": investigation.id,
        "title": investigation.title,
        "description": investigation.description,
        "status": investigation.status,
        "created_by": investigation.created_by,
        "created_at": investigation.created_at,
    }


@router.get("/{investigation_id}/workspace", response_model=WorkspaceResponse)
async def get_workspace(
    investigation_id: uuid.UUID, session: AsyncSession = Depends(get_session)
):
    # Retrieve investigation with eagerly loaded related entities
    stmt = (
        select(Investigation)
        .where(Investigation.id == investigation_id)
        .options(
            selectinload(Investigation.evidence).selectinload(Evidence.normalized_events),
            selectinload(Investigation.events),
            selectinload(Investigation.relationships),
            selectinload(Investigation.reconstructions).selectinload(Reconstruction.steps),
            selectinload(Investigation.analyst_actions),
        )
    )
    result = await session.execute(stmt)
    investigation = result.scalar_one_or_none()

    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    # Order collections manually since we did selectinload
    # Note: ORM relationship order_by might exist, but safer to sort here if not guaranteed.
    # From models, reconstruction steps are ordered by step_order, events by occurred_at
    events = sorted(investigation.events, key=lambda e: e.occurred_at)
    analyst_actions = sorted(investigation.analyst_actions, key=lambda a: a.acted_at)

    # Take the first reconstruction (assuming only 1 for demo purposes)
    reconstruction = None
    if investigation.reconstructions:
        # Get the newest reconstruction
        reconstruction = sorted(investigation.reconstructions, key=lambda r: r.created_at, reverse=True)[0]
        reconstruction.steps = sorted(reconstruction.steps, key=lambda s: s.step_order)

    # Compute unresolved events
    involved_event_ids = set()
    for rel in investigation.relationships:
        involved_event_ids.add(rel.source_event_id)
        involved_event_ids.add(rel.target_event_id)

    unresolved_event_ids = [e.id for e in events if e.id not in involved_event_ids]

    # Compute normalized event count for evidence
    evidence_list = []
    for ev in investigation.evidence:
        ev_dict = {
            "id": ev.id,
            "source_identifier": ev.source_identifier,
            "content_hash": ev.content_hash,
            "imported_at": ev.imported_at,
            "normalized_event_count": len(ev.normalized_events),
        }
        evidence_list.append(ev_dict)

    return WorkspaceResponse(
        investigation=investigation,
        evidence=evidence_list,
        events=events,
        relationships=investigation.relationships,
        reconstruction=reconstruction,
        unresolved_event_ids=unresolved_event_ids,
        analyst_actions=analyst_actions,
    )


@router.post("/{investigation_id}/correlate", response_model=CorrelationResponse)
async def correlate_investigation(
    investigation_id: uuid.UUID, session: AsyncSession = Depends(get_session)
):
    try:
        parent_child_result = await correlate_process_parent_child(
            session=session, investigation_id=investigation_id
        )
        file_activity_result = await correlate_process_file_activity(
            session=session, investigation_id=investigation_id
        )
        await session.commit()
    except SQLAlchemyError as e:
        await session.rollback()
        logger.error(f"Failed to correlate investigation: {e}")
        raise HTTPException(status_code=500, detail="Database error during correlation")

    # Combine results
    created = (
        parent_child_result.relationships_created
        + file_activity_result.relationships_created
    )
    skipped = (
        parent_child_result.relationships_skipped_duplicate
        + file_activity_result.relationships_skipped_duplicate
    )
    return CorrelationResponse(
        relationships_created=created,
        relationships_skipped_duplicate=skipped,
    )


@router.post("/{investigation_id}/reconstruct", response_model=ReconstructionResponse)
async def reconstruct_investigation(
    investigation_id: uuid.UUID, session: AsyncSession = Depends(get_session)
):
    try:
        result = await build_reconstruction(
            session=session, investigation_id=investigation_id
        )
        await session.commit()
    except SQLAlchemyError as e:
        await session.rollback()
        logger.error(f"Failed to reconstruct investigation: {e}")
        raise HTTPException(status_code=500, detail="Database error during reconstruction")

    return ReconstructionResponse(
        reconstructions_created=result.reconstructions_created,
        steps_created=result.steps_created,
        components_skipped_unsupported=result.components_skipped_unsupported,
        components_skipped_cycle=result.components_skipped_cycle,
    )


@router.post(
    "/{investigation_id}/relationships/{relationship_id}/confirm",
    response_model=RelationshipValidationResponse,
)
async def confirm_investigation_relationship(
    investigation_id: uuid.UUID,
    relationship_id: uuid.UUID,
    req: RelationshipValidationRequest,
    session: AsyncSession = Depends(get_session),
):
    try:
        relationship = await confirm_relationship(
            session=session,
            investigation_id=investigation_id,
            relationship_id=relationship_id,
            analyst_id=req.analyst_id,
            reason=req.reason,
        )
        await session.commit()
        return RelationshipValidationResponse(
            relationship_id=relationship.id,
            status=relationship.status,
            status_changed_at=relationship.status_changed_at,
        )
    except RelationshipNotFoundError:
        await session.rollback()
        raise HTTPException(status_code=404, detail="Relationship not found")
    except InvalidRelationshipTransitionError as e:
        await session.rollback()
        raise HTTPException(status_code=409, detail=str(e))
    except SQLAlchemyError as e:
        await session.rollback()
        logger.error(f"DB error during confirm_relationship: {e}")
        raise HTTPException(status_code=500, detail="Internal database error")


@router.post(
    "/{investigation_id}/relationships/{relationship_id}/reject",
    response_model=RelationshipValidationResponse,
)
async def reject_investigation_relationship(
    investigation_id: uuid.UUID,
    relationship_id: uuid.UUID,
    req: RelationshipValidationRequest,
    session: AsyncSession = Depends(get_session),
):
    try:
        relationship = await reject_relationship(
            session=session,
            investigation_id=investigation_id,
            relationship_id=relationship_id,
            analyst_id=req.analyst_id,
            reason=req.reason,
        )
        await session.commit()
        return RelationshipValidationResponse(
            relationship_id=relationship.id,
            status=relationship.status,
            status_changed_at=relationship.status_changed_at,
        )
    except RelationshipNotFoundError:
        await session.rollback()
        raise HTTPException(status_code=404, detail="Relationship not found")
    except InvalidRelationshipTransitionError as e:
        await session.rollback()
        raise HTTPException(status_code=409, detail=str(e))
    except SQLAlchemyError as e:
        await session.rollback()
        logger.error(f"DB error during reject_relationship: {e}")
        raise HTTPException(status_code=500, detail="Internal database error")
