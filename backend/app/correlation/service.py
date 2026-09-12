"""
Correlation service — Phase 4B / Phase 4C.

PUBLIC API
----------
correlate_process_parent_child(session, investigation_id) -> CorrelationResult

    Discovers SPAWNED relationships between NormalizedEvents in one
    investigation by matching host + process_id (parent) to
    host + parent_process_id (child).

    Does NOT commit the session.  The caller is responsible for commit/rollback.

correlate_process_file_activity(session, investigation_id) -> CorrelationResult

    Discovers CREATED / DELETED relationships between PROCESS_START events
    and FILE_CREATE / FILE_DELETE events in one investigation by matching
    host + process_id across the two event types.

    Does NOT commit the session.  The caller is responsible for commit/rollback.

──────────────────────────────────────────────────────────────────────────────
RULE: PROCESS_PARENT_CHILD (Phase 4B — host-aware)
──────────────────────────────────────────────────────────────────────────────
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

──────────────────────────────────────────────────────────────────────────────
RULE: PROCESS_FILE_ACTIVITY (Phase 4C)
──────────────────────────────────────────────────────────────────────────────
For a PROCESS_START event and a FILE_CREATE or FILE_DELETE event belonging
to the same investigation:

    MATCH(process_event, file_event) iff:
        process_event.investigation_id == file_event.investigation_id
        AND process_event.event_type == "PROCESS_START"
        AND file_event.event_type IN ("FILE_CREATE", "FILE_DELETE")
        AND process_event.process_id IS NOT NULL
        AND file_event.process_id IS NOT NULL
        AND process_event.process_id == file_event.process_id   # exact string equality
        AND process_event.id != file_event.id                   # no self-reference
        AND process_event.source_host IS NOT NULL               # host required
        AND file_event.source_host IS NOT NULL                  # host required
        AND process_event.source_host == file_event.source_host # exact string equality

When matched, one Relationship is created:
    relationship_type = "CREATED"  (if file_event.event_type == "FILE_CREATE")
    relationship_type = "DELETED"  (if file_event.event_type == "FILE_DELETE")
    creation_method   = "PROCESS_FILE_ACTIVITY"
    status            = "SYSTEM_PROPOSED"
    source_event_id   = process_event.id
    target_event_id   = file_event.id
    source_entity_id  = None
    target_entity_id  = None

And two RelationshipSupport rows are created:
    process_event  ->  support_reason = "PROCESS_HOST_PID_MATCH"
    file_event     ->  support_reason = "FILE_HOST_PID_MATCH"

The reason strings record that both host AND PID equality were required.

──────────────────────────────────────────────────────────────────────────────
SEMANTIC CONSTRAINTS (both rules)
──────────────────────────────────────────────────────────────────────────────
- Both events MUST belong to the same investigation.  Candidate pairs are
  produced by a scoped join; cross-investigation correlation is impossible
  by construction.
- Host comparison is exact string equality on the value already stored in
  NormalizedEvent.source_host.  No additional canonicalization is performed
  in the correlation layer.  Phase 3B has already applied canonicalize_host().
- FQDN vs short hostname ("laptop-07" vs "laptop-07.corp.example.com") will
  correctly NOT match because normalization does not resolve FQDN differences.
  This is intentional conservative behavior.
- PID comparison is exact string equality (VARCHAR =) on stored values.
  No coercion, normalization, or parsing of PID representations.
- No temporal window or event ordering predicate is applied.  Rules are
  purely structural.
- Multiple candidate matches are all preserved as SYSTEM_PROPOSED
  relationships for analyst review.  No silent arbitration.

──────────────────────────────────────────────────────────────────────────────
IDEMPOTENCY
──────────────────────────────────────────────────────────────────────────────
Repeated sequential execution over the same events MUST NOT create
duplicate rows.

Strategy: application-layer pre-insert SELECT before each INSERT.
Before creating a Relationship, the service queries for an existing row
matching (source_event_id, target_event_id, relationship_type,
creation_method).  If found, the pair is skipped and counted as
relationships_skipped_duplicate.

This check prevents duplicate creation during repeated sequential
execution.  It does NOT provide a database-level concurrency guarantee.
Concurrent callers may produce duplicates because the pre-insert SELECT
and the subsequent INSERT are not atomic at the DB level.  The relationship
table has no DB-level unique constraint on
(source_event_id, target_event_id, relationship_type, creation_method).

──────────────────────────────────────────────────────────────────────────────
CALLER RESPONSIBILITY
──────────────────────────────────────────────────────────────────────────────
The caller owns the transaction.  This service:
    - calls session.flush() after each INSERT to surface DB errors early
    - never calls session.commit() or session.rollback()

──────────────────────────────────────────────────────────────────────────────
QUERY DESIGN
──────────────────────────────────────────────────────────────────────────────
Candidate pairs are produced by a single SQLAlchemy aliased join on
NormalizedEvent.  All predicate conditions are evaluated at the database
level.  Relevant indexes (ix_normalized_event_event_type,
ix_normalized_event_source_host) are available to the query planner;
whether they are used is determined by the PostgreSQL query planner at
execution time.
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
from app.normalization.events import FILE_CREATE, FILE_DELETE, PROCESS_START

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

# ── Phase 4B constants ───────────────────────────────────────────────────────
_RELATIONSHIP_TYPE = "SPAWNED"
_CREATION_METHOD = "PROCESS_PARENT_CHILD"
_STATUS = "SYSTEM_PROPOSED"
_SUPPORT_REASON_PARENT = "PARENT_PID_MATCH"
_SUPPORT_REASON_CHILD = "CHILD_PID_MATCH"

# ── Phase 4C constants ───────────────────────────────────────────────────────
_CREATION_METHOD_FILE = "PROCESS_FILE_ACTIVITY"
_STATUS_FILE = "SYSTEM_PROPOSED"
_SUPPORT_REASON_PROCESS = "PROCESS_HOST_PID_MATCH"
_SUPPORT_REASON_FILE = "FILE_HOST_PID_MATCH"


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
    source_event_id: uuid.UUID,
    target_event_id: uuid.UUID,
    *,
    relationship_type: str,
    creation_method: str,
) -> Relationship | None:
    """
    Return an existing relationship between the given event pair matching
    the specified relationship_type and creation_method, or None.

    This is the shared application-level idempotency guard used by all
    correlation rules.  It prevents duplicate creation during repeated
    sequential execution.  See module docstring for the concurrency caveat.

    Parameters
    ----------
    source_event_id:
        UUID of the source (e.g. parent / process) NormalizedEvent.
    target_event_id:
        UUID of the target (e.g. child / file) NormalizedEvent.
    relationship_type:
        Exact relationship_type value to match (e.g. "SPAWNED", "CREATED").
    creation_method:
        Exact creation_method value to match (e.g. "PROCESS_PARENT_CHILD").
    """
    result = await session.execute(
        select(Relationship).where(
            Relationship.source_event_id == source_event_id,
            Relationship.target_event_id == target_event_id,
            Relationship.relationship_type == relationship_type,
            Relationship.creation_method == creation_method,
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
        existing = await _find_existing_relationship(
            session, parent.id, child.id,
            relationship_type=_RELATIONSHIP_TYPE,
            creation_method=_CREATION_METHOD,
        )
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


# ──────────────────────────────────────────────────────────────────────────────
# Phase 4C: process → file activity
# ──────────────────────────────────────────────────────────────────────────────


def _relationship_type_for(event_type: str) -> str:
    """
    Map a file event type to its corresponding relationship_type.

    Fail-closed: only FILE_CREATE and FILE_DELETE are recognized.
    Any other value raises ValueError rather than silently producing
    an incorrect relationship type.
    """
    if event_type == FILE_CREATE:
        return "CREATED"
    if event_type == FILE_DELETE:
        return "DELETED"
    raise ValueError(
        f"_relationship_type_for: unrecognized file event type {event_type!r}. "
        f"Expected one of: {FILE_CREATE!r}, {FILE_DELETE!r}."
    )


def _build_file_explanation(
    proc_event: NormalizedEvent,
    file_event: NormalizedEvent,
    matched_pid: str,
    matched_host: str,
    relationship_type: str,
) -> str:
    """
    Return a deterministic, auditable explanation string for a
    PROCESS_FILE_ACTIVITY relationship.

    Contains enough information for an analyst to verify the rule
    independently without querying the database:
    - process event UUID
    - file event UUID
    - matched PID
    - matched host
    - exact file event type
    - resulting relationship type
    """
    return (
        f'Event {proc_event.id} (PROCESS_START, host="{matched_host}", '
        f'process_id="{matched_pid}") '
        f'performed {file_event.event_type} on '
        f'event {file_event.id} '
        f'(host="{file_event.source_host}", process_id="{file_event.process_id}"). '
        f'PID match: "{matched_pid}". Host match: "{matched_host}". '
        f'File event type: "{file_event.event_type}". '
        f'Relationship type: "{relationship_type}".'
    )


async def correlate_process_file_activity(
    *,
    session: AsyncSession,
    investigation_id: uuid.UUID,
) -> CorrelationResult:
    """
    Discover process-to-file-activity relationships in one investigation.

    Matches PROCESS_START events against FILE_CREATE and FILE_DELETE events
    on the same host sharing the same process_id.  Produces:

        PROCESS_START + FILE_CREATE  ->  relationship_type = "CREATED"
        PROCESS_START + FILE_DELETE  ->  relationship_type = "DELETED"

    Parameters
    ----------
    session:
        An open async SQLAlchemy session.  The caller is responsible for
        committing or rolling back.
    investigation_id:
        The Investigation to correlate.  Only events belonging to this
        investigation are considered.

    Returns
    -------
    CorrelationResult
        Contains the investigation_id, number of new relationships created,
        and number of duplicate pairs skipped.

    Notes
    -----
    The service flushes after each new Relationship is inserted to surface
    DB errors (e.g. FK violations) early, before the caller commits.

    Multiple candidate matches (e.g. two PROCESS_START events sharing the
    same host+PID) all produce SYSTEM_PROPOSED relationships.  No silent
    arbitration is performed.
    """
    created = 0
    skipped = 0

    # ── 1. Build join to find all matching (process, file) pairs ──────────────
    #
    # All predicate conditions are evaluated at the database level:
    #   - same investigation                       (JOIN ON)
    #   - process_event.event_type == PROCESS_START (WHERE)
    #   - file_event.event_type IN (FILE_CREATE,
    #                               FILE_DELETE)    (WHERE)
    #   - process_event.process_id IS NOT NULL      (WHERE)
    #   - file_event.process_id IS NOT NULL         (WHERE)
    #   - process_event.process_id
    #       == file_event.process_id                (JOIN ON, exact VARCHAR =)
    #   - process_event.id != file_event.id         (JOIN ON, no self-reference)
    #   - process_event.source_host IS NOT NULL     (WHERE)
    #   - file_event.source_host IS NOT NULL        (WHERE)
    #   - process_event.source_host
    #       == file_event.source_host               (JOIN ON, exact VARCHAR =)
    #
    # NULL source_host or process_id events are excluded; there is no
    # fallback to partial matching.
    proc_alias = aliased(NormalizedEvent)
    file_alias  = aliased(NormalizedEvent)

    stmt = (
        select(proc_alias, file_alias)
        .join(
            file_alias,
            and_(
                file_alias.investigation_id == proc_alias.investigation_id,
                file_alias.process_id       == proc_alias.process_id,
                file_alias.source_host      == proc_alias.source_host,
                file_alias.id               != proc_alias.id,
            ),
        )
        .where(
            proc_alias.investigation_id == investigation_id,
            proc_alias.event_type       == PROCESS_START,
            proc_alias.process_id.is_not(None),
            proc_alias.source_host.is_not(None),
            file_alias.event_type.in_([FILE_CREATE, FILE_DELETE]),
            file_alias.process_id.is_not(None),
            file_alias.source_host.is_not(None),
        )
    )

    rows = (await session.execute(stmt)).all()

    logger.debug(
        "correlate_process_file_activity: investigation=%s candidate_pairs=%d",
        investigation_id,
        len(rows),
    )

    # ── 2. Process each matched pair ──────────────────────────────────────────
    for proc_event, file_event in rows:
        matched_pid  = proc_event.process_id   # non-None; enforced by WHERE
        matched_host = proc_event.source_host  # non-None; enforced by WHERE

        rel_type = _relationship_type_for(file_event.event_type)

        # ── 2a. Idempotency check ─────────────────────────────────────────────
        existing = await _find_existing_relationship(
            session, proc_event.id, file_event.id,
            relationship_type=rel_type,
            creation_method=_CREATION_METHOD_FILE,
        )
        if existing is not None:
            logger.debug(
                "Skipping duplicate file activity: proc=%s file=%s type=%s",
                proc_event.id,
                file_event.id,
                rel_type,
            )
            skipped += 1
            continue

        # ── 2b. Create Relationship ───────────────────────────────────────────
        explanation = _build_file_explanation(
            proc_event, file_event, matched_pid, matched_host, rel_type
        )
        rel = Relationship(
            investigation_id=investigation_id,
            relationship_type=rel_type,
            creation_method=_CREATION_METHOD_FILE,
            status=_STATUS_FILE,
            source_event_id=proc_event.id,
            source_entity_id=None,
            target_event_id=file_event.id,
            target_entity_id=None,
            explanation=explanation,
        )
        session.add(rel)
        await session.flush()  # surface FK errors early; caller commits

        # ── 2c. Create RelationshipSupport records ────────────────────────────
        session.add(RelationshipSupport(
            relationship_id=rel.id,
            event_id=proc_event.id,
            support_reason=_SUPPORT_REASON_PROCESS,
        ))
        session.add(RelationshipSupport(
            relationship_id=rel.id,
            event_id=file_event.id,
            support_reason=_SUPPORT_REASON_FILE,
        ))
        await session.flush()

        created += 1
        logger.info(
            "Relationship created: id=%s proc_event=%s file_event=%s "
            "type=%s pid=%s host=%s",
            rel.id,
            proc_event.id,
            file_event.id,
            rel_type,
            matched_pid,
            matched_host,
        )

    logger.info(
        "correlate_process_file_activity complete: investigation=%s "
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
