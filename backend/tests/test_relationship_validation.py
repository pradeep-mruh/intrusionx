"""
Phase 6A — Relationship Analyst Validation test suite.

Covers confirm_relationship() and reject_relationship() across 31 cases:

  Transition correctness   (1–3)
  Audit record creation    (4–13)
  Timestamp behavior       (14–15)
  Confirm→reject sequence  (16–17)
  Error cases              (18–25)
  Transaction semantics    (26–28)
  Concurrency              (29–31)

SESSION STRATEGY
----------------
Follows the test_reconstruction.py pattern exactly:

  - anyio_backend fixture: scope="session", returns "asyncio"
  - engine fixture: scope="session", pytest_asyncio
  - db_tables fixture: scope="session", pytest_asyncio
  - session fixture: function-scoped, rolls back after each test

Tests use @pytest.mark.anyio (NOT @pytest.mark.asyncio) so that
the anyio runner shares the session-scoped event loop that the engine
and its asyncpg connection pool were created on.

Using @pytest.mark.asyncio (STRICT mode) creates a new per-test event
loop which breaks session-scoped asyncpg connections.

CONCURRENCY TESTS (29–31)
--------------------------
Tests 29–31 use two independent real DB sessions to verify that
SELECT … FOR UPDATE serializes competing analyst decisions at the
PostgreSQL layer.  They commit rows so they manage their own cleanup.

asyncio.gather() runs both coroutines concurrently.  asyncpg opens a
separate connection per AsyncSession from the pool, so the two sessions
compete at the database level.

All tests run against real PostgreSQL.  No mocks.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import Base
from app.models.analyst_action import AnalystAction
from app.models.evidence import Evidence
from app.models.investigation import Investigation
from app.models.normalized_event import NormalizedEvent
from app.models.relationship import Relationship
from app.investigation.service import (
    InvalidRelationshipTransitionError,
    RelationshipNotFoundError,
    confirm_relationship,
    reject_relationship,
)

# ──────────────────────────────────────────────────────────────────────────────
# Database connection
# ──────────────────────────────────────────────────────────────────────────────

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://intrusionx:intrusionx_dev@localhost:5432/intrusionx",
)

# ──────────────────────────────────────────────────────────────────────────────
# Session-scoped fixtures  (mirrors test_reconstruction.py exactly)
# ──────────────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture(scope="session")
async def engine():
    eng = create_async_engine(DATABASE_URL, echo=False)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture(scope="session")
async def db_tables(engine):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


@pytest_asyncio.fixture()
async def session(engine, db_tables):
    """
    Yield a function-scoped AsyncSession inside a rolled-back transaction.

    The transaction is always rolled back on teardown so that no rows are
    permanently committed to the database.
    """
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as sess:
        async with sess.begin():
            yield sess
            await sess.rollback()


# ──────────────────────────────────────────────────────────────────────────────
# Domain helpers
# ──────────────────────────────────────────────────────────────────────────────

_NOW = datetime(2026, 10, 1, 9, 0, 0, tzinfo=timezone.utc)
_ANALYST_A = uuid.uuid4()
_ANALYST_B = uuid.uuid4()


def _make_investigation() -> Investigation:
    return Investigation(
        id=uuid.uuid4(),
        title="Phase 6A Validation Test",
        status="OPEN",
        created_by=_ANALYST_A,
    )


def _make_evidence(investigation_id: uuid.UUID) -> Evidence:
    # Use a per-call random suffix so concurrent test setups do not collide
    # on the unique (investigation_id, content_hash) constraint.
    content = b'{"event":"test"}' + uuid.uuid4().hex.encode("utf-8")
    return Evidence(
        id=uuid.uuid4(),
        investigation_id=investigation_id,
        source_type="STRUCTURED_JSON",
        source_identifier="test_phase6a.json",
        original_content=content.decode("latin-1"),
        content_hash=hashlib.sha256(content).hexdigest(),
        hash_algorithm="SHA-256",
        is_immutable=True,
    )


def _make_event(investigation_id: uuid.UUID, evidence_id: uuid.UUID) -> NormalizedEvent:
    return NormalizedEvent(
        id=uuid.uuid4(),
        investigation_id=investigation_id,
        evidence_id=evidence_id,
        occurred_at=_NOW,
        event_type="PROCESS_START",
        event_category="PROCESS",
        source_host="laptop-07",
    )


def _make_relationship(
    investigation_id: uuid.UUID,
    source_event_id: uuid.UUID,
    target_event_id: uuid.UUID,
    *,
    status: str = "SYSTEM_PROPOSED",
) -> Relationship:
    return Relationship(
        id=uuid.uuid4(),
        investigation_id=investigation_id,
        relationship_type="SPAWNED",
        source_event_id=source_event_id,
        source_entity_id=None,
        target_event_id=target_event_id,
        target_entity_id=None,
        creation_method="PROCESS_PARENT_CHILD",
        status=status,
        explanation="test relationship for Phase 6A",
    )


async def _setup(session: AsyncSession) -> tuple[Investigation, Evidence]:
    """Insert one Investigation + one Evidence record and flush."""
    inv = _make_investigation()
    session.add(inv)
    await session.flush()

    evd = _make_evidence(inv.id)
    session.add(evd)
    await session.flush()

    return inv, evd


async def _setup_relationship(
    session: AsyncSession,
    *,
    status: str = "SYSTEM_PROPOSED",
) -> tuple[Investigation, Relationship]:
    """
    Create and flush a complete minimal domain graph:
    Investigation → Evidence → 2 × NormalizedEvent → Relationship.

    Returns (investigation, relationship).
    """
    inv, evd = await _setup(session)

    e1 = _make_event(inv.id, evd.id)
    e2 = _make_event(inv.id, evd.id)
    session.add_all([e1, e2])
    await session.flush()

    rel = _make_relationship(inv.id, e1.id, e2.id, status=status)
    session.add(rel)
    await session.flush()

    return inv, rel


async def _count_actions(
    session: AsyncSession,
    *,
    relationship_id: uuid.UUID,
) -> int:
    """Count AnalystAction rows for a given relationship within the session."""
    stmt = select(func.count()).where(
        AnalystAction.target_object_id == relationship_id,
        AnalystAction.target_object_type == "RELATIONSHIP",
    )
    result = await session.execute(stmt)
    return result.scalar_one()


async def _get_actions(
    session: AsyncSession,
    *,
    relationship_id: uuid.UUID,
) -> list[AnalystAction]:
    """Return all AnalystAction rows for a given relationship, ordered by acted_at."""
    stmt = (
        select(AnalystAction)
        .where(
            AnalystAction.target_object_id == relationship_id,
            AnalystAction.target_object_type == "RELATIONSHIP",
        )
        .order_by(AnalystAction.acted_at)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


# ──────────────────────────────────────────────────────────────────────────────
# 1–3: Transition correctness
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_01_proposed_to_confirmed(session: AsyncSession):
    """SYSTEM_PROPOSED → ANALYST_CONFIRMED via confirm_relationship."""
    inv, rel = await _setup_relationship(session)

    result = await confirm_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
    )

    assert result.status == "ANALYST_CONFIRMED"
    assert rel.status == "ANALYST_CONFIRMED"


@pytest.mark.anyio
async def test_02_proposed_to_rejected(session: AsyncSession):
    """SYSTEM_PROPOSED → ANALYST_REJECTED via reject_relationship."""
    inv, rel = await _setup_relationship(session)

    result = await reject_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
    )

    assert result.status == "ANALYST_REJECTED"
    assert rel.status == "ANALYST_REJECTED"


@pytest.mark.anyio
async def test_03_confirmed_to_rejected(session: AsyncSession):
    """ANALYST_CONFIRMED → ANALYST_REJECTED via reject_relationship (reversal)."""
    inv, rel = await _setup_relationship(session)

    await confirm_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
    )
    assert rel.status == "ANALYST_CONFIRMED"

    result = await reject_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_B,
        reason="Re-examined evidence contradicts earlier confirmation.",
    )

    assert result.status == "ANALYST_REJECTED"
    assert rel.status == "ANALYST_REJECTED"


# ──────────────────────────────────────────────────────────────────────────────
# 4–13: Audit record correctness
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_04_confirmation_creates_exactly_one_action(session: AsyncSession):
    """confirm_relationship creates exactly one AnalystAction row."""
    inv, rel = await _setup_relationship(session)
    before = await _count_actions(session, relationship_id=rel.id)

    await confirm_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
    )

    after = await _count_actions(session, relationship_id=rel.id)
    assert after - before == 1


@pytest.mark.anyio
async def test_05_rejection_creates_exactly_one_action(session: AsyncSession):
    """reject_relationship creates exactly one AnalystAction row."""
    inv, rel = await _setup_relationship(session)
    before = await _count_actions(session, relationship_id=rel.id)

    await reject_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
    )

    after = await _count_actions(session, relationship_id=rel.id)
    assert after - before == 1


@pytest.mark.anyio
async def test_06_confirmation_audit_action_type(session: AsyncSession):
    """confirm_relationship produces action_type='CONFIRM_RELATIONSHIP'."""
    inv, rel = await _setup_relationship(session)

    await confirm_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
    )

    actions = await _get_actions(session, relationship_id=rel.id)
    assert len(actions) == 1
    assert actions[0].action_type == "CONFIRM_RELATIONSHIP"


@pytest.mark.anyio
async def test_07_rejection_audit_action_type(session: AsyncSession):
    """reject_relationship produces action_type='REJECT_RELATIONSHIP'."""
    inv, rel = await _setup_relationship(session)

    await reject_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
    )

    actions = await _get_actions(session, relationship_id=rel.id)
    assert len(actions) == 1
    assert actions[0].action_type == "REJECT_RELATIONSHIP"


@pytest.mark.anyio
async def test_08_audit_target_object_type_is_relationship(session: AsyncSession):
    """AnalystAction.target_object_type == 'RELATIONSHIP'."""
    inv, rel = await _setup_relationship(session)

    await confirm_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
    )

    actions = await _get_actions(session, relationship_id=rel.id)
    assert actions[0].target_object_type == "RELATIONSHIP"


@pytest.mark.anyio
async def test_09_audit_target_object_id_is_relationship_id(session: AsyncSession):
    """AnalystAction.target_object_id == relationship.id."""
    inv, rel = await _setup_relationship(session)

    await confirm_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
    )

    actions = await _get_actions(session, relationship_id=rel.id)
    assert actions[0].target_object_id == rel.id


@pytest.mark.anyio
async def test_10_audit_investigation_id_correct(session: AsyncSession):
    """AnalystAction.investigation_id == relationship.investigation_id."""
    inv, rel = await _setup_relationship(session)

    await confirm_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
    )

    actions = await _get_actions(session, relationship_id=rel.id)
    assert actions[0].investigation_id == inv.id


@pytest.mark.anyio
async def test_11_audit_analyst_id_correct(session: AsyncSession):
    """AnalystAction.analyst_id == supplied analyst_id."""
    inv, rel = await _setup_relationship(session)
    specific_analyst = uuid.uuid4()

    await confirm_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=specific_analyst,
    )

    actions = await _get_actions(session, relationship_id=rel.id)
    assert actions[0].analyst_id == specific_analyst


@pytest.mark.anyio
async def test_12_reason_is_preserved(session: AsyncSession):
    """Supplied reason is stored in AnalystAction.reason."""
    inv, rel = await _setup_relationship(session)
    test_reason = "Verified parent-child PID chain in memory dump."

    await confirm_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
        reason=test_reason,
    )

    actions = await _get_actions(session, relationship_id=rel.id)
    assert actions[0].reason == test_reason


@pytest.mark.anyio
async def test_13_none_reason_accepted(session: AsyncSession):
    """reason=None is stored as NULL in AnalystAction.reason."""
    inv, rel = await _setup_relationship(session)

    await confirm_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
        reason=None,
    )

    actions = await _get_actions(session, relationship_id=rel.id)
    assert actions[0].reason is None


# ──────────────────────────────────────────────────────────────────────────────
# 14–15: Timestamp behavior
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_14_confirmation_updates_status_changed_at(session: AsyncSession):
    """confirm_relationship sets status_changed_at to a UTC-aware timestamp."""
    inv, rel = await _setup_relationship(session)
    assert rel.status_changed_at is None

    before = datetime.now(timezone.utc)
    await confirm_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
    )
    after = datetime.now(timezone.utc)

    assert rel.status_changed_at is not None
    ts = rel.status_changed_at
    # asyncpg may return naive datetimes; normalize to UTC-aware for comparison
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    assert before <= ts <= after


@pytest.mark.anyio
async def test_15_rejection_after_confirmation_updates_status_changed_at(
    session: AsyncSession,
):
    """ANALYST_CONFIRMED → ANALYST_REJECTED updates status_changed_at again."""
    inv, rel = await _setup_relationship(session)

    await confirm_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
    )
    confirmed_at = rel.status_changed_at

    # Tiny sleep to ensure a distinct second timestamp
    await asyncio.sleep(0.01)

    before_reject = datetime.now(timezone.utc)
    await reject_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_B,
    )
    after_reject = datetime.now(timezone.utc)

    rejected_at = rel.status_changed_at
    if rejected_at is not None and rejected_at.tzinfo is None:
        rejected_at = rejected_at.replace(tzinfo=timezone.utc)
    if confirmed_at is not None and confirmed_at.tzinfo is None:
        confirmed_at = confirmed_at.replace(tzinfo=timezone.utc)

    assert rejected_at is not None
    assert rejected_at != confirmed_at
    assert before_reject <= rejected_at <= after_reject


# ──────────────────────────────────────────────────────────────────────────────
# 16–17: Confirm→reject sequence audit preservation
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_16_confirmed_then_rejected_preserves_confirmation_audit(
    session: AsyncSession,
):
    """
    confirm followed by reject leaves the original CONFIRM_RELATIONSHIP
    AnalystAction row intact.
    """
    inv, rel = await _setup_relationship(session)

    await confirm_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
    )
    await reject_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_B,
    )

    actions = await _get_actions(session, relationship_id=rel.id)
    action_types = [a.action_type for a in actions]
    assert "CONFIRM_RELATIONSHIP" in action_types


@pytest.mark.anyio
async def test_17_confirmed_then_rejected_creates_second_audit(
    session: AsyncSession,
):
    """
    confirm followed by reject creates exactly two AnalystAction rows
    (CONFIRM_RELATIONSHIP and REJECT_RELATIONSHIP).
    """
    inv, rel = await _setup_relationship(session)

    await confirm_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
    )
    await reject_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_B,
    )

    actions = await _get_actions(session, relationship_id=rel.id)
    assert len(actions) == 2
    action_types = {a.action_type for a in actions}
    assert action_types == {"CONFIRM_RELATIONSHIP", "REJECT_RELATIONSHIP"}


# ──────────────────────────────────────────────────────────────────────────────
# 18–19: Not-found / cross-investigation errors
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_18_relationship_not_found_raises(session: AsyncSession):
    """confirm on a non-existent relationship_id raises RelationshipNotFoundError."""
    inv, _ = await _setup(session)

    with pytest.raises(RelationshipNotFoundError):
        await confirm_relationship(
            session=session,
            investigation_id=inv.id,
            relationship_id=uuid.uuid4(),
            analyst_id=_ANALYST_A,
        )


@pytest.mark.anyio
async def test_19_cross_investigation_relationship_raises_not_found(
    session: AsyncSession,
):
    """
    A relationship that exists but belongs to a different investigation raises
    RelationshipNotFoundError — same error as not-found, no existence leakage.
    """
    inv_a, rel = await _setup_relationship(session)
    inv_b, _ = await _setup(session)

    with pytest.raises(RelationshipNotFoundError):
        await confirm_relationship(
            session=session,
            investigation_id=inv_b.id,  # wrong investigation
            relationship_id=rel.id,     # relationship belongs to inv_a
            analyst_id=_ANALYST_A,
        )


# ──────────────────────────────────────────────────────────────────────────────
# 20–25: Invalid transition error cases
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_20_repeated_confirmation_raises(session: AsyncSession):
    """confirm on ANALYST_CONFIRMED raises InvalidRelationshipTransitionError."""
    inv, rel = await _setup_relationship(session)

    await confirm_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
    )

    with pytest.raises(InvalidRelationshipTransitionError):
        await confirm_relationship(
            session=session,
            investigation_id=inv.id,
            relationship_id=rel.id,
            analyst_id=_ANALYST_A,
        )


@pytest.mark.anyio
async def test_21_repeated_rejection_raises(session: AsyncSession):
    """reject on ANALYST_REJECTED raises InvalidRelationshipTransitionError."""
    inv, rel = await _setup_relationship(session)

    await reject_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
    )

    with pytest.raises(InvalidRelationshipTransitionError):
        await reject_relationship(
            session=session,
            investigation_id=inv.id,
            relationship_id=rel.id,
            analyst_id=_ANALYST_A,
        )


@pytest.mark.anyio
async def test_22_rejected_then_confirmed_raises(session: AsyncSession):
    """confirm on ANALYST_REJECTED raises InvalidRelationshipTransitionError."""
    inv, rel = await _setup_relationship(session)

    await reject_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
    )

    with pytest.raises(InvalidRelationshipTransitionError):
        await confirm_relationship(
            session=session,
            investigation_id=inv.id,
            relationship_id=rel.id,
            analyst_id=_ANALYST_A,
        )


@pytest.mark.anyio
async def test_23_invalid_transition_creates_no_action(session: AsyncSession):
    """An invalid transition creates no AnalystAction row."""
    inv, rel = await _setup_relationship(session)

    await confirm_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
    )
    count_after_first = await _count_actions(session, relationship_id=rel.id)

    with pytest.raises(InvalidRelationshipTransitionError):
        await confirm_relationship(
            session=session,
            investigation_id=inv.id,
            relationship_id=rel.id,
            analyst_id=_ANALYST_A,
        )

    count_after_second = await _count_actions(session, relationship_id=rel.id)
    assert count_after_second == count_after_first


@pytest.mark.anyio
async def test_24_invalid_transition_leaves_status_unchanged(session: AsyncSession):
    """An invalid transition does not mutate Relationship.status."""
    inv, rel = await _setup_relationship(session)

    await confirm_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
    )

    with pytest.raises(InvalidRelationshipTransitionError):
        await confirm_relationship(
            session=session,
            investigation_id=inv.id,
            relationship_id=rel.id,
            analyst_id=_ANALYST_A,
        )

    assert rel.status == "ANALYST_CONFIRMED"


@pytest.mark.anyio
async def test_25_invalid_transition_leaves_status_changed_at_unchanged(
    session: AsyncSession,
):
    """An invalid transition does not mutate Relationship.status_changed_at."""
    inv, rel = await _setup_relationship(session)

    await confirm_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel.id,
        analyst_id=_ANALYST_A,
    )
    ts_after_confirm = rel.status_changed_at

    with pytest.raises(InvalidRelationshipTransitionError):
        await confirm_relationship(
            session=session,
            investigation_id=inv.id,
            relationship_id=rel.id,
            analyst_id=_ANALYST_A,
        )

    assert rel.status_changed_at == ts_after_confirm


# ──────────────────────────────────────────────────────────────────────────────
# 26–28: Transaction semantics
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_26_changes_are_flush_visible_within_transaction(session: AsyncSession):
    """
    After confirm_relationship, the updated status is visible in a SELECT
    within the same session — flush makes changes visible without committing.
    """
    inv, rel = await _setup_relationship(session)
    rel_id = rel.id

    await confirm_relationship(
        session=session,
        investigation_id=inv.id,
        relationship_id=rel_id,
        analyst_id=_ANALYST_A,
    )

    stmt = select(Relationship).where(Relationship.id == rel_id)
    result = await session.execute(stmt)
    reloaded = result.scalar_one()
    assert reloaded.status == "ANALYST_CONFIRMED"


@pytest.mark.anyio
async def test_27_service_does_not_commit(engine, db_tables):
    """
    Rolling back the caller's transaction undoes the status change — proving
    the service did not commit independently.
    """
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    inv_id: uuid.UUID
    rel_id: uuid.UUID

    # Commit setup data so other sessions can see it
    async with factory() as setup_sess:
        async with setup_sess.begin():
            inv, rel = await _setup_relationship(setup_sess)
            inv_id = inv.id
            rel_id = rel.id

    try:
        # Confirm inside a session that we then explicitly roll back
        async with factory() as action_sess:
            async with action_sess.begin():
                await confirm_relationship(
                    session=action_sess,
                    investigation_id=inv_id,
                    relationship_id=rel_id,
                    analyst_id=_ANALYST_A,
                )
                await action_sess.rollback()

        # Verify rollback undid both the status mutation and the audit row
        async with factory() as verify_sess:
            async with verify_sess.begin():
                stmt = select(Relationship).where(Relationship.id == rel_id)
                loaded = (await verify_sess.execute(stmt)).scalar_one()
                assert loaded.status == "SYSTEM_PROPOSED"
                assert loaded.status_changed_at is None
                assert await _count_actions(verify_sess, relationship_id=rel_id) == 0

    finally:
        await _cleanup(engine, inv_id, rel_id)


@pytest.mark.anyio
async def test_28_caller_rollback_undoes_status_and_audit(engine, db_tables):
    """
    Caller rolling back the transaction undoes both:
    - Relationship.status mutation
    - AnalystAction insertion
    """
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    inv_id: uuid.UUID
    rel_id: uuid.UUID

    async with factory() as setup_sess:
        async with setup_sess.begin():
            inv, rel = await _setup_relationship(setup_sess)
            inv_id = inv.id
            rel_id = rel.id

    try:
        async with factory() as sess:
            async with sess.begin():
                await confirm_relationship(
                    session=sess,
                    investigation_id=inv_id,
                    relationship_id=rel_id,
                    analyst_id=_ANALYST_A,
                )
                # Verify flush-visible changes within the transaction
                stmt = select(Relationship).where(Relationship.id == rel_id)
                loaded = (await sess.execute(stmt)).scalar_one()
                assert loaded.status == "ANALYST_CONFIRMED"
                assert await _count_actions(sess, relationship_id=rel_id) == 1

                await sess.rollback()

        async with factory() as verify_sess:
            async with verify_sess.begin():
                stmt = select(Relationship).where(Relationship.id == rel_id)
                loaded = (await verify_sess.execute(stmt)).scalar_one()
                assert loaded.status == "SYSTEM_PROPOSED"
                assert await _count_actions(verify_sess, relationship_id=rel_id) == 0

    finally:
        await _cleanup(engine, inv_id, rel_id)


# ──────────────────────────────────────────────────────────────────────────────
# Concurrency helper
# ──────────────────────────────────────────────────────────────────────────────


async def _commit_setup(engine) -> tuple[uuid.UUID, uuid.UUID]:
    """
    Insert a minimal domain graph into the DB and commit.
    Returns (investigation_id, relationship_id).
    """
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as sess:
        async with sess.begin():
            inv, rel = await _setup_relationship(sess)
            return inv.id, rel.id


async def _cleanup(engine, investigation_id: uuid.UUID, relationship_id: uuid.UUID):
    """Delete committed test rows in dependency order."""
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as sess:
        async with sess.begin():
            await sess.execute(
                AnalystAction.__table__.delete().where(
                    AnalystAction.target_object_id == relationship_id
                )
            )
            await sess.execute(
                Relationship.__table__.delete().where(
                    Relationship.id == relationship_id
                )
            )
            await sess.execute(
                NormalizedEvent.__table__.delete().where(
                    NormalizedEvent.investigation_id == investigation_id
                )
            )
            await sess.execute(
                Evidence.__table__.delete().where(
                    Evidence.investigation_id == investigation_id
                )
            )
            await sess.execute(
                Investigation.__table__.delete().where(
                    Investigation.id == investigation_id
                )
            )


# ──────────────────────────────────────────────────────────────────────────────
# 29–31: Concurrency — SELECT … FOR UPDATE serialization
#
# These tests commit rows and manage their own cleanup.
#
# asyncio.gather() runs both coroutines concurrently on the same event loop.
# Each session opens an independent asyncpg connection from the pool, so the
# two sessions genuinely compete at the PostgreSQL layer.
#
# The tests assert the correctness of the terminal state (status and audit
# count) rather than the internal lock-wait ordering, which is non-observable
# from Python and would require pg_locks inspection.
#
# Marked @pytest.mark.integration to allow selective exclusion.
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
@pytest.mark.integration
async def test_29_competing_confirms_serialize(engine, db_tables):
    """
    Two concurrent confirm_relationship calls on the same SYSTEM_PROPOSED
    relationship result in exactly one ANALYST_CONFIRMED row and exactly one
    AnalystAction.  The second session raises InvalidRelationshipTransitionError.
    """
    inv_id, rel_id = await _commit_setup(engine)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    results: list[str] = []

    async def do_confirm():
        async with factory() as sess:
            try:
                async with sess.begin():
                    await confirm_relationship(
                        session=sess,
                        investigation_id=inv_id,
                        relationship_id=rel_id,
                        analyst_id=_ANALYST_A,
                    )
                results.append("ok")
            except InvalidRelationshipTransitionError:
                results.append("invalid_transition")
            except Exception as exc:
                results.append(f"error:{type(exc).__name__}")

    await asyncio.gather(do_confirm(), do_confirm())

    assert results.count("ok") == 1, f"Expected 1 success, got: {results}"
    assert results.count("invalid_transition") == 1, f"Expected 1 failure, got: {results}"

    async with factory() as verify_sess:
        async with verify_sess.begin():
            stmt = select(Relationship).where(Relationship.id == rel_id)
            loaded = (await verify_sess.execute(stmt)).scalar_one()
            assert loaded.status == "ANALYST_CONFIRMED"
            action_count = await _count_actions(verify_sess, relationship_id=rel_id)
            assert action_count == 1

    await _cleanup(engine, inv_id, rel_id)


@pytest.mark.anyio
@pytest.mark.integration
async def test_30_competing_rejects_serialize(engine, db_tables):
    """
    Two concurrent reject_relationship calls on the same SYSTEM_PROPOSED
    relationship result in exactly one ANALYST_REJECTED row and exactly one
    AnalystAction.
    """
    inv_id, rel_id = await _commit_setup(engine)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    results: list[str] = []

    async def do_reject():
        async with factory() as sess:
            try:
                async with sess.begin():
                    await reject_relationship(
                        session=sess,
                        investigation_id=inv_id,
                        relationship_id=rel_id,
                        analyst_id=_ANALYST_A,
                    )
                results.append("ok")
            except InvalidRelationshipTransitionError:
                results.append("invalid_transition")
            except Exception as exc:
                results.append(f"error:{type(exc).__name__}")

    await asyncio.gather(do_reject(), do_reject())

    assert results.count("ok") == 1, f"Expected 1 success, got: {results}"
    assert results.count("invalid_transition") == 1, f"Expected 1 failure, got: {results}"

    async with factory() as verify_sess:
        async with verify_sess.begin():
            stmt = select(Relationship).where(Relationship.id == rel_id)
            loaded = (await verify_sess.execute(stmt)).scalar_one()
            assert loaded.status == "ANALYST_REJECTED"
            action_count = await _count_actions(verify_sess, relationship_id=rel_id)
            assert action_count == 1

    await _cleanup(engine, inv_id, rel_id)


@pytest.mark.anyio
@pytest.mark.integration
async def test_31_confirm_then_reject_lifecycle(engine, db_tables):
    """
    Concurrent confirm + reject on the same SYSTEM_PROPOSED relationship.

    If confirm locks first:
      SYSTEM_PROPOSED → ANALYST_CONFIRMED → ANALYST_REJECTED
      Both succeed; two audit rows.

    If reject locks first:
      SYSTEM_PROPOSED → ANALYST_REJECTED
      confirm then fails (ANALYST_REJECTED is terminal); one audit row.

    Either terminal state is valid.  The test asserts the final state is
    ANALYST_REJECTED and that the audit row count is consistent.
    """
    inv_id, rel_id = await _commit_setup(engine)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    confirm_results: list[str] = []
    reject_results: list[str] = []

    async def do_confirm():
        async with factory() as sess:
            try:
                async with sess.begin():
                    await confirm_relationship(
                        session=sess,
                        investigation_id=inv_id,
                        relationship_id=rel_id,
                        analyst_id=_ANALYST_A,
                    )
                confirm_results.append("ok")
            except InvalidRelationshipTransitionError:
                confirm_results.append("invalid_transition")
            except Exception as exc:
                confirm_results.append(f"error:{type(exc).__name__}")

    async def do_reject():
        async with factory() as sess:
            try:
                async with sess.begin():
                    await reject_relationship(
                        session=sess,
                        investigation_id=inv_id,
                        relationship_id=rel_id,
                        analyst_id=_ANALYST_B,
                    )
                reject_results.append("ok")
            except InvalidRelationshipTransitionError:
                reject_results.append("invalid_transition")
            except Exception as exc:
                reject_results.append(f"error:{type(exc).__name__}")

    await asyncio.gather(do_confirm(), do_reject())

    async with factory() as verify_sess:
        async with verify_sess.begin():
            stmt = select(Relationship).where(Relationship.id == rel_id)
            loaded = (await verify_sess.execute(stmt)).scalar_one()
            # Final state must be ANALYST_REJECTED regardless of lock order
            assert loaded.status == "ANALYST_REJECTED"

            action_count = await _count_actions(verify_sess, relationship_id=rel_id)

            if confirm_results == ["ok"] and reject_results == ["ok"]:
                # confirm locked first: proposed→confirmed→rejected, 2 audit rows
                assert action_count == 2
            elif confirm_results == ["invalid_transition"] and reject_results == ["ok"]:
                # reject locked first: proposed→rejected, confirm failed, 1 audit row
                assert action_count == 1
            else:
                pytest.fail(
                    f"Unexpected concurrent results: "
                    f"confirm={confirm_results}, reject={reject_results}"
                )

    await _cleanup(engine, inv_id, rel_id)
