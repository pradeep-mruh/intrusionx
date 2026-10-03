"""
Investigation service — Phase 6A.

PUBLIC API
----------
confirm_relationship(*, session, investigation_id, relationship_id, analyst_id, reason=None)
    -> Relationship

reject_relationship(*, session, investigation_id, relationship_id, analyst_id, reason=None)
    -> Relationship

    Record an analyst's decision on a Relationship.  Each function loads the
    Relationship using a pessimistic row lock (SELECT … FOR UPDATE), validates
    the current status against the allowed source states, mutates the
    Relationship row, and appends exactly one AnalystAction audit record.

    Both functions raise:
      RelationshipNotFoundError          — no row matching (relationship_id,
                                           investigation_id) exists.
      InvalidRelationshipTransitionError — the relationship's current status
                                           does not permit the requested
                                           transition.

    Does NOT commit the session.  The caller is responsible for
    commit/rollback.

──────────────────────────────────────────────────────────────────────────────
ALLOWED TRANSITIONS (Phase 6A)
──────────────────────────────────────────────────────────────────────────────

  SYSTEM_PROPOSED   →[confirm]→  ANALYST_CONFIRMED
  SYSTEM_PROPOSED   →[reject]→   ANALYST_REJECTED
  ANALYST_CONFIRMED →[reject]→   ANALYST_REJECTED   ← analyst reversal

ANALYST_REJECTED is terminal: no further transitions are allowed.

Rejected transitions (all raise InvalidRelationshipTransitionError):

  ANALYST_CONFIRMED + confirm   (already decided, re-confirm is a no-op error)
  ANALYST_REJECTED  + confirm   (terminal state — forbidden)
  ANALYST_REJECTED  + reject    (terminal state — forbidden)
  any status        → SYSTEM_PROPOSED  (revert to machine state forbidden)

Confirm/reject sequence (confirm locks first):

  SYSTEM_PROPOSED → ANALYST_CONFIRMED → ANALYST_REJECTED

Both succeed sequentially and each produces its own audit record.

Confirm/reject sequence (reject locks first):

  SYSTEM_PROPOSED → ANALYST_REJECTED

Subsequent confirm raises InvalidRelationshipTransitionError because
ANALYST_REJECTED is terminal.

──────────────────────────────────────────────────────────────────────────────
CONCURRENCY
──────────────────────────────────────────────────────────────────────────────
Both functions use SELECT … FOR UPDATE to acquire a row-level exclusive lock
before reading the current status.  This serializes competing analyst
decisions on the same Relationship row at the database layer.

If Transaction A holds the lock on row R, Transaction B blocks at its own
SELECT … FOR UPDATE until A commits or rolls back.  After A commits, B
re-reads the row and observes the updated status.  If that status no longer
permits B's transition, B raises InvalidRelationshipTransitionError without
mutating the row or creating an AnalystAction.

No schema migration or optimistic-lock column is required.

──────────────────────────────────────────────────────────────────────────────
AUDIT RECORDS
──────────────────────────────────────────────────────────────────────────────
Every successful transition creates exactly one AnalystAction row.

  CONFIRM:  action_type = 'CONFIRM_RELATIONSHIP'
  REJECT:   action_type = 'REJECT_RELATIONSHIP'

Both use:
  target_object_type = 'RELATIONSHIP'
  target_object_id   = relationship.id
  investigation_id   = relationship.investigation_id
  analyst_id         = supplied analyst_id
  previous_state     = {'status': <status before mutation>}
  new_state          = {'status': <status after mutation>}
  reason             = supplied reason (nullable)
  acted_at           = server-side now() — not set by this service

Earlier audit records are never modified.  A confirm-then-reject sequence
leaves two separate AnalystAction rows in chronological order.

──────────────────────────────────────────────────────────────────────────────
ANALYST IDENTITY TRUST BOUNDARY
──────────────────────────────────────────────────────────────────────────────
AnalystAction.analyst_id is a bare UUID with no FK to any user or
authentication table.  Phase 6A records the supplied analyst_id verbatim.
It cannot verify that the UUID belongs to a real authenticated analyst.
Authentication and authorisation are out of scope for Phase 6A.

──────────────────────────────────────────────────────────────────────────────
INVESTIGATION BOUNDARY
──────────────────────────────────────────────────────────────────────────────
Lookup is scoped to BOTH relationship.id AND relationship.investigation_id.
A relationship belonging to another investigation raises
RelationshipNotFoundError — the same error as a genuinely missing row.
This prevents callers from inferring cross-investigation object existence
via error type.

──────────────────────────────────────────────────────────────────────────────
TRANSACTION SEMANTICS
──────────────────────────────────────────────────────────────────────────────
This service:
  - mutates ORM objects in-place
  - calls session.add() for new AnalystAction rows
  - calls session.flush() once after all mutations
  - never calls session.commit() or session.rollback()

Caller owns the transaction.  A flush failure propagates as an
IntegrityError and must be handled by the caller.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analyst_action import AnalystAction
from app.models.relationship import Relationship


# ──────────────────────────────────────────────────────────────────────────────
# Domain exceptions
# ──────────────────────────────────────────────────────────────────────────────


class RelationshipNotFoundError(Exception):
    """
    Raised when no Relationship matching (relationship_id, investigation_id)
    exists.  Also raised for cross-investigation mismatches to avoid leaking
    object existence across investigation boundaries.
    """


class InvalidRelationshipTransitionError(Exception):
    """
    Raised when the requested status transition is not permitted for the
    relationship's current status.

    Phase 6A allowed source states:
      confirm_relationship: SYSTEM_PROPOSED
      reject_relationship:  SYSTEM_PROPOSED, ANALYST_CONFIRMED

    ANALYST_REJECTED is terminal — no further transitions are permitted.
    """


# ──────────────────────────────────────────────────────────────────────────────
# Transition guards
# ──────────────────────────────────────────────────────────────────────────────

_CONFIRM_VALID_SOURCES: frozenset[str] = frozenset({"SYSTEM_PROPOSED"})
_REJECT_VALID_SOURCES: frozenset[str] = frozenset({"SYSTEM_PROPOSED", "ANALYST_CONFIRMED"})


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────


async def _load_for_update(
    session: AsyncSession,
    *,
    investigation_id: uuid.UUID,
    relationship_id: uuid.UUID,
) -> Relationship:
    """
    Load a Relationship with a pessimistic exclusive row lock.

    Both a missing row and a row that belongs to a different investigation
    raise RelationshipNotFoundError.  Using the same error for both cases
    prevents cross-investigation object-existence disclosure.
    """
    stmt = (
        select(Relationship)
        .where(
            Relationship.id == relationship_id,
            Relationship.investigation_id == investigation_id,
        )
        .with_for_update()
    )
    result = await session.execute(stmt)
    rel = result.scalar_one_or_none()
    if rel is None:
        raise RelationshipNotFoundError(
            f"Relationship {relationship_id!s} not found in investigation "
            f"{investigation_id!s}."
        )
    return rel


def _append_action(
    session: AsyncSession,
    *,
    relationship: Relationship,
    analyst_id: uuid.UUID,
    action_type: str,
    previous_status: str,
    new_status: str,
    reason: str | None,
) -> AnalystAction:
    """Construct and register an AnalystAction audit record."""
    action = AnalystAction(
        investigation_id=relationship.investigation_id,
        analyst_id=analyst_id,
        action_type=action_type,
        target_object_type="RELATIONSHIP",
        target_object_id=relationship.id,
        previous_state={"status": previous_status},
        new_state={"status": new_status},
        reason=reason,
    )
    session.add(action)
    return action


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────


async def confirm_relationship(
    *,
    session: AsyncSession,
    investigation_id: uuid.UUID,
    relationship_id: uuid.UUID,
    analyst_id: uuid.UUID,
    reason: str | None = None,
) -> Relationship:
    """
    Confirm a SYSTEM_PROPOSED relationship as ANALYST_CONFIRMED.

    Allowed source states: SYSTEM_PROPOSED.

    Parameters
    ----------
    session:
        Active async SQLAlchemy session.  Caller owns commit/rollback.
    investigation_id:
        Must match the relationship's investigation_id.  Enforces the
        investigation boundary — a relationship in another investigation
        raises RelationshipNotFoundError.
    relationship_id:
        The relationship to confirm.
    analyst_id:
        Bare UUID identifying the acting analyst.  Recorded verbatim.
        Not authenticated by this service.
    reason:
        Optional justification.  Stored in AnalystAction.reason.

    Returns
    -------
    Relationship
        The mutated ORM object (status=ANALYST_CONFIRMED).

    Raises
    ------
    RelationshipNotFoundError
        No row matches (relationship_id, investigation_id).
    InvalidRelationshipTransitionError
        Current status is not SYSTEM_PROPOSED.
    """
    rel = await _load_for_update(
        session,
        investigation_id=investigation_id,
        relationship_id=relationship_id,
    )

    if rel.status not in _CONFIRM_VALID_SOURCES:
        raise InvalidRelationshipTransitionError(
            f"confirm_relationship: relationship {relationship_id!s} has status "
            f"'{rel.status}'; only {sorted(_CONFIRM_VALID_SOURCES)} may be confirmed."
        )

    previous_status = rel.status
    rel.status = "ANALYST_CONFIRMED"
    rel.status_changed_at = datetime.now(timezone.utc)

    _append_action(
        session,
        relationship=rel,
        analyst_id=analyst_id,
        action_type="CONFIRM_RELATIONSHIP",
        previous_status=previous_status,
        new_status="ANALYST_CONFIRMED",
        reason=reason,
    )

    await session.flush()
    return rel


async def reject_relationship(
    *,
    session: AsyncSession,
    investigation_id: uuid.UUID,
    relationship_id: uuid.UUID,
    analyst_id: uuid.UUID,
    reason: str | None = None,
) -> Relationship:
    """
    Reject a relationship as ANALYST_REJECTED.

    Allowed source states: SYSTEM_PROPOSED, ANALYST_CONFIRMED.

    ANALYST_CONFIRMED → ANALYST_REJECTED is an intentional analyst reversal
    and is explicitly supported by the Relationship domain lifecycle.

    ANALYST_REJECTED is terminal — calling reject on an already-rejected
    relationship raises InvalidRelationshipTransitionError.

    Parameters
    ----------
    session:
        Active async SQLAlchemy session.  Caller owns commit/rollback.
    investigation_id:
        Must match the relationship's investigation_id.
    relationship_id:
        The relationship to reject.
    analyst_id:
        Bare UUID identifying the acting analyst.  Recorded verbatim.
        Not authenticated by this service.
    reason:
        Optional justification.  Stored in AnalystAction.reason.

    Returns
    -------
    Relationship
        The mutated ORM object (status=ANALYST_REJECTED).

    Raises
    ------
    RelationshipNotFoundError
        No row matches (relationship_id, investigation_id).
    InvalidRelationshipTransitionError
        Current status is not SYSTEM_PROPOSED or ANALYST_CONFIRMED.
    """
    rel = await _load_for_update(
        session,
        investigation_id=investigation_id,
        relationship_id=relationship_id,
    )

    if rel.status not in _REJECT_VALID_SOURCES:
        raise InvalidRelationshipTransitionError(
            f"reject_relationship: relationship {relationship_id!s} has status "
            f"'{rel.status}'; only {sorted(_REJECT_VALID_SOURCES)} may be rejected."
        )

    previous_status = rel.status
    rel.status = "ANALYST_REJECTED"
    rel.status_changed_at = datetime.now(timezone.utc)

    _append_action(
        session,
        relationship=rel,
        analyst_id=analyst_id,
        action_type="REJECT_RELATIONSHIP",
        previous_status=previous_status,
        new_status="ANALYST_REJECTED",
        reason=reason,
    )

    await session.flush()
    return rel
