"""
Correlation service — Phase 4B.

PUBLIC API
----------
correlate_process_parent_child(session, investigation_id) -> CorrelationResult

    Discovers SPAWNED relationships between NormalizedEvents in one
    investigation by matching host + process_id (parent) to
    host + parent_process_id (child).

    Does NOT commit the session.  The caller is responsible for commit/rollback.

RULE: PROCESS_PARENT_CHILD (Phase 4B — host-aware)
---------------------------------------------------
For two NormalizedEvents parent and child belonging to the same investigation:

    MATCH(parent, child) iff:
        parent.investigation_id == child.investigation_id
        AND parent.process_id IS NOT NULL
        AND child.parent_process_id IS NOT NULL
        AND parent.process_id == child.parent_process_id   # exact string equality
        AND parent.id != child.id                          # no self-reference
        AND parent.source_host IS NOT NULL                 # host required
        AND child.source_host IS NOT NULL                  # host required
        AND parent.source_host == child.source_host        # exact string equality

When matched, one Relationship is created:
    relationship_type = "SPAWNED"
    creation_method   = "PROCESS_PARENT_CHILD"
    status            = "SYSTEM_PROPOSED"
    source_event_id   = parent.id
    target_event_id   = child.id
    source_entity_id  = None
    target_entity_id  = None

And two RelationshipSupport rows are created:
    parent  ->  support_reason = "PARENT_PID_MATCH"
    child   ->  support_reason = "CHILD_PID_MATCH"

IMPORTANT SEMANTIC CONSTRAINTS
-------------------------------
- Both events MUST belong to the same investigation.  Candidate pairs are
  produced by a scoped self-join; cross-investigation correlation is
  impossible by construction.
- The self-reference guard (parent.id != child.id) prevents a single event
  from being its own parent.
- Matching is on process_id and parent_process_id columns only.
  process_name / parent_process_name are never used for matching.
- No temporal window is applied.  The rule is purely structural.
- No event_type filter is applied.  Any NormalizedEvent with the
  appropriate PID and host fields is a candidate.

HOST MATCHING
--------------
- Both events must have a non-null source_host.  Events without a host value
  are excluded; there is no fallback to PID-only matching.
- host comparison is exact string equality (VARCHAR =) on the value already
  stored in NormalizedEvent.source_host.
- No additional host canonicalization is performed in the correlation layer.
  Phase 3B already strips whitespace and lowercases host values via
  canonicalize_host().  The correlation layer trusts those stored values.
- FQDN vs short hostname ("laptop-07" vs "laptop-07.corp.example.com") will
  correctly NOT match because normalization does not resolve FQDN differences.
  This is intentional conservative behavior.

PID MATCHING
------------
- PID comparison is exact string equality at the database level (VARCHAR =).
  PIDs are stored as strings by Phase 3B (str(raw_value)).
- No coercion, normalization, or parsing of PID representations.
  "4812" and "04812" are distinct values and will correctly not match.
  "4812" and "0x12CC" are distinct values and will correctly not match.

MULTIPLE-PARENT EDGE CASE
--------------------------
If two events on the same host share the same process_id value and a third
event on the same host has a matching parent_process_id, the rule will
create two relationships:
    event_1 -> event_3 (SPAWNED)
    event_2 -> event_3 (SPAWNED)
This is correct deterministic behaviour: the rule cannot arbitrate which
event is "the real" parent without additional context.

IDEMPOTENCY
-----------
Repeated sequential execution over the same events MUST NOT create
duplicate rows.

Strategy: application-layer pre-insert SELECT before each INSERT.
Before creating a Relationship, the service queries for an existing row
matching (source_event_id, target_event_id, relationship_type,
creation_method).  If found, the pair is skipped and counted as
relationships_skipped_duplicate.

IMPORTANT: this application-level check prevents duplicate creation during
repeated sequential execution.  It does NOT provide a database-level
concurrency guarantee.  If two callers execute this service concurrently
for the same investigation, duplicate rows may be created because the
pre-insert SELECT and the subsequent INSERT are not atomic at the database
level.  The relationship table has no DB-level unique constraint on
(source_event_id, target_event_id, relationship_type, creation_method).

CALLER RESPONSIBILITY
---------------------
The caller owns the transaction.  This service:
    - calls session.flush() after each INSERT to surface DB errors early
    - never calls session.commit() or session.rollback()

QUERY DESIGN
------------
Candidate pairs are produced by a single SQLAlchemy self-join on
NormalizedEvent.  All predicate conditions are evaluated at the database
level using the existing ix_normalized_event_source_host index.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.models.normalized_event import NormalizedEvent
from app.models.relationship import Relationship, RelationshipSupport

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

_RELATIONSHIP_TYPE = "SPAWNED"
_CREATION_METHOD = "PROCESS_PARENT_CHILD"
_STATUS = "SYSTEM_PROPOSED"
_SUPPORT_REASON_PARENT = "PARENT_PID_MATCH"
_SUPPORT_REASON_CHILD = "CHILD_PID_MATCH"


# ──────────────────────────────────────────────────────────────────────────────
# Result dataclass
# ──────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CorrelationResult:
    """
    Returned by the correlation service after processing one investigation.

    ``relationships_created`` is the number of new Relationship rows inserted.
    ``relationships_skipped_duplicate`` is the number of pairs that already
    had a matching Relationship row and were therefore skipped.
    """

    investigation_id: uuid.UUID
    relationships_created: int
    relationships_skipped_duplicate: int


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────


def _build_explanation(
    parent: NormalizedEvent,
    child: NormalizedEvent,
    matched_pid: str,
    matched_host: str,
) -> str:
    """
    Return a deterministic, auditable, human-readable explanation string.

    The explanation embeds both event UUIDs, the matched PID value, and the
    matched host value so that it can be verified independently without
    querying the database.
    """
    return (
        f'Event {parent.id} (host="{matched_host}", process_id="{parent.process_id}") '
        f"is the declared parent of event {child.id} "
        f'(host="{child.source_host}", parent_process_id="{child.parent_process_id}"). '
        f'PID match: "{matched_pid}". Host match: "{matched_host}".'
    )


async def _find_existing_relationship(
    session: AsyncSession,
    parent_event_id: uuid.UUID,
    child_event_id: uuid.UUID,
) -> Relationship | None:
    """
    Return an existing PROCESS_PARENT_CHILD SPAWNED relationship between the
    given event pair, or None if no such relationship exists.

    This is the application-level idempotency guard.  It prevents duplicate
    creation during repeated sequential execution.  See module docstring for
    the concurrency caveat.
    """
    result = await session.execute(
        select(Relationship).where(
            Relationship.source_event_id == parent_event_id,
            Relationship.target_event_id == child_event_id,
            Relationship.relationship_type == _RELATIONSHIP_TYPE,
            Relationship.creation_method == _CREATION_METHOD,
        )
    )
    return result.scalar_one_or_none()


# ──────────────────────────────────────────────────────────────────────────────
# Main correlation entry point
# ──────────────────────────────────────────────────────────────────────────────


async def correlate_process_parent_child(
    *,
    session: AsyncSession,
    investigation_id: uuid.UUID,
) -> CorrelationResult:
    """
    Discover process parent/child relationships in one investigation.

    Parameters
    ----------
    session:
        An open async SQLAlchemy session.  The caller is responsible for
        committing or rolling back.
    investigation_id:
        The Investigation to correlate.  Only events belonging to this
        investigation are considered.  Cross-investigation correlation is
        impossible by construction.

    Returns
    -------
    CorrelationResult
        Contains the investigation_id, number of new relationships created,
        and number of duplicate pairs skipped.

    Notes
    -----
    The service flushes after each new Relationship is inserted to surface
    DB errors (e.g. FK violations) early, before the caller commits.
    """
    created = 0
    skipped = 0

    # ── 1. Build self-join to find all matching (parent, child) pairs ─────────
    #
    # All predicate conditions are evaluated at the database level:
    #   - same investigation                (JOIN ON)
    #   - parent.process_id IS NOT NULL     (WHERE)
    #   - child.parent_process_id IS NOT NULL (WHERE)
    #   - parent.process_id == child.parent_process_id  (JOIN ON, exact VARCHAR =)
    #   - parent.id != child.id             (JOIN ON, no self-reference)
    #   - parent.source_host IS NOT NULL    (WHERE, host required)
    #   - child.source_host IS NOT NULL     (WHERE, host required)
    #   - parent.source_host == child.source_host  (JOIN ON, exact VARCHAR =)
    #
    # NULL source_host events are excluded: no fallback to PID-only matching.
    parent_alias = aliased(NormalizedEvent)
    child_alias = aliased(NormalizedEvent)

    stmt = (
        select(parent_alias, child_alias)
        .join(
            child_alias,
            and_(
                child_alias.investigation_id == parent_alias.investigation_id,
                child_alias.parent_process_id == parent_alias.process_id,
                child_alias.source_host == parent_alias.source_host,
                child_alias.id != parent_alias.id,
            ),
        )
        .where(
            parent_alias.investigation_id == investigation_id,
            parent_alias.process_id.is_not(None),
            child_alias.parent_process_id.is_not(None),
            parent_alias.source_host.is_not(None),
            child_alias.source_host.is_not(None),
        )
    )

    rows = (await session.execute(stmt)).all()

    logger.debug(
        "correlate_process_parent_child: investigation=%s candidate_pairs=%d",
        investigation_id,
        len(rows),
    )

    # ── 2. Process each matched pair ──────────────────────────────────────────
    for parent, child in rows:
        matched_pid = parent.process_id    # non-None; enforced by JOIN predicate
        matched_host = parent.source_host  # non-None; enforced by JOIN predicate

        # ── 2a. Idempotency check ─────────────────────────────────────────────
        existing = await _find_existing_relationship(session, parent.id, child.id)
        if existing is not None:
            logger.debug(
                "Skipping duplicate: parent=%s child=%s",
                parent.id,
                child.id,
            )
            skipped += 1
            continue

        # ── 2b. Create Relationship ───────────────────────────────────────────
        explanation = _build_explanation(parent, child, matched_pid, matched_host)
        rel = Relationship(
            investigation_id=investigation_id,
            relationship_type=_RELATIONSHIP_TYPE,
            creation_method=_CREATION_METHOD,
            status=_STATUS,
            source_event_id=parent.id,
            source_entity_id=None,
            target_event_id=child.id,
            target_entity_id=None,
            explanation=explanation,
        )
        session.add(rel)
        await session.flush()  # surface FK errors early; caller commits

        # ── 2c. Create RelationshipSupport records ────────────────────────────
        session.add(RelationshipSupport(
            relationship_id=rel.id,
            event_id=parent.id,
            support_reason=_SUPPORT_REASON_PARENT,
        ))
        session.add(RelationshipSupport(
            relationship_id=rel.id,
            event_id=child.id,
            support_reason=_SUPPORT_REASON_CHILD,
        ))
        await session.flush()

        created += 1
        logger.info(
            "Relationship created: id=%s parent_event=%s child_event=%s pid=%s host=%s",
            rel.id,
            parent.id,
            child.id,
            matched_pid,
            matched_host,
        )

    logger.info(
        "correlate_process_parent_child complete: investigation=%s "
        "created=%d skipped_duplicate=%d",
        investigation_id,
        created,
        skipped,
    )

    return CorrelationResult(
        investigation_id=investigation_id,
        relationships_created=created,
        relationships_skipped_duplicate=skipped,
    )
