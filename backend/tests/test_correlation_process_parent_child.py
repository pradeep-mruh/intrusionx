"""
Phase 4A — Correlation Engine: process parent/child rule test suite.

Tests are organized into 7 concern groups:

 1. Positive match (happy path)
 2. PID mismatch
 3. Missing PID fields
 4. Cross-investigation isolation
 5. Self-reference protection
 6. Idempotency
 7. Boundary / negative cases

SESSION STRATEGY
----------------
Follows the test_normalization.py pattern: function-scoped transactional
rollback.  The ``session`` fixture opens a transaction and rolls back after
each test — no rows are committed to the database.

This works because the correlation service never commits (caller owns the
transaction), so all writes made during a test are visible within the same
session and are cleanly rolled back on teardown.

All tests run against real PostgreSQL.  No mocks or monkeypatching of the
database layer.
"""

import os
import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import Base
from app.models.evidence import Evidence
from app.models.investigation import Investigation
from app.models.normalized_event import NormalizedEvent
from app.models.relationship import Relationship, RelationshipSupport
from app.correlation.service import CorrelationResult, correlate_process_parent_child

# ──────────────────────────────────────────────────────────────────────────────
# Database connection
# ──────────────────────────────────────────────────────────────────────────────

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://intrusionx:intrusionx_dev@localhost:5432/intrusionx",
)

# ──────────────────────────────────────────────────────────────────────────────
# Session-scoped fixtures
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
    Yield a function-scoped AsyncSession with an open transaction.

    The transaction is rolled back after each test regardless of outcome,
    so no rows are committed to the database.
    """
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as sess:
        async with sess.begin():
            yield sess
            await sess.rollback()


# ──────────────────────────────────────────────────────────────────────────────
# Domain fixtures and helpers
# ──────────────────────────────────────────────────────────────────────────────

_NOW = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)


def _make_investigation() -> Investigation:
    return Investigation(
        id=uuid.uuid4(),
        title="Phase 4A Correlation Test",
        status="OPEN",
        created_by=uuid.uuid4(),
    )


def _make_evidence(investigation_id: uuid.UUID) -> Evidence:
    import hashlib

    content = b'{"timestamp":"2026-09-01T12:00:00Z","event_type":"process_start"}'
    return Evidence(
        id=uuid.uuid4(),
        investigation_id=investigation_id,
        source_type="STRUCTURED_JSON",
        source_identifier="test_fixture.json",
        original_content=content.decode("utf-8"),
        content_hash=hashlib.sha256(content).hexdigest(),
        hash_algorithm="SHA-256",
        is_immutable=True,
    )


def _make_event(
    investigation_id: uuid.UUID,
    evidence_id: uuid.UUID,
    *,
    process_id: str | None = None,
    parent_process_id: str | None = None,
    event_type: str = "PROCESS_START",
) -> NormalizedEvent:
    return NormalizedEvent(
        id=uuid.uuid4(),
        investigation_id=investigation_id,
        evidence_id=evidence_id,
        occurred_at=_NOW,
        event_type=event_type,
        event_category="PROCESS",
        process_id=process_id,
        parent_process_id=parent_process_id,
    )


async def _setup(session: AsyncSession) -> tuple[Investigation, Evidence]:
    """Insert one Investigation and one Evidence record and flush."""
    inv = _make_investigation()
    session.add(inv)
    await session.flush()

    evd = _make_evidence(inv.id)
    session.add(evd)
    await session.flush()

    return inv, evd


# ──────────────────────────────────────────────────────────────────────────────
# Group 1: Positive match (happy path)
# ──────────────────────────────────────────────────────────────────────────────


class TestPositiveMatch:
    @pytest.mark.anyio
    async def test_match_creates_relationship(self, session: AsyncSession):
        """A matching PID pair produces exactly one Relationship row."""
        inv, evd = await _setup(session)

        parent = _make_event(inv.id, evd.id, process_id="4812")
        child = _make_event(inv.id, evd.id, parent_process_id="4812")
        session.add_all([parent, child])
        await session.flush()

        result = await correlate_process_parent_child(
            session=session, investigation_id=inv.id
        )

        rows = (
            await session.execute(
                select(Relationship).where(
                    Relationship.investigation_id == inv.id
                )
            )
        ).scalars().all()

        assert len(rows) == 1
        rel = rows[0]
        assert rel.relationship_type == "SPAWNED"
        assert rel.creation_method == "PROCESS_PARENT_CHILD"
        assert rel.status == "SYSTEM_PROPOSED"
        assert rel.source_event_id == parent.id
        assert rel.target_event_id == child.id
        assert rel.source_entity_id is None
        assert rel.target_entity_id is None

    @pytest.mark.anyio
    async def test_match_creates_support_records(self, session: AsyncSession):
        """A matching pair produces two RelationshipSupport rows with correct reasons."""
        inv, evd = await _setup(session)

        parent = _make_event(inv.id, evd.id, process_id="4812")
        child = _make_event(inv.id, evd.id, parent_process_id="4812")
        session.add_all([parent, child])
        await session.flush()

        await correlate_process_parent_child(
            session=session, investigation_id=inv.id
        )

        rel = (
            await session.execute(
                select(Relationship).where(Relationship.investigation_id == inv.id)
            )
        ).scalar_one()

        supports = (
            await session.execute(
                select(RelationshipSupport).where(
                    RelationshipSupport.relationship_id == rel.id
                )
            )
        ).scalars().all()

        assert len(supports) == 2
        reasons_by_event = {s.event_id: s.support_reason for s in supports}
        assert reasons_by_event[parent.id] == "PARENT_PID_MATCH"
        assert reasons_by_event[child.id] == "CHILD_PID_MATCH"

    @pytest.mark.anyio
    async def test_explanation_contains_pid(self, session: AsyncSession):
        """Explanation string must reference the matched PID value."""
        inv, evd = await _setup(session)

        parent = _make_event(inv.id, evd.id, process_id="9999")
        child = _make_event(inv.id, evd.id, parent_process_id="9999")
        session.add_all([parent, child])
        await session.flush()

        await correlate_process_parent_child(
            session=session, investigation_id=inv.id
        )

        rel = (
            await session.execute(
                select(Relationship).where(Relationship.investigation_id == inv.id)
            )
        ).scalar_one()

        assert "9999" in rel.explanation
        assert str(parent.id) in rel.explanation
        assert str(child.id) in rel.explanation

    @pytest.mark.anyio
    async def test_result_counts_correct(self, session: AsyncSession):
        """CorrelationResult reports one created and zero skipped."""
        inv, evd = await _setup(session)

        parent = _make_event(inv.id, evd.id, process_id="1234")
        child = _make_event(inv.id, evd.id, parent_process_id="1234")
        session.add_all([parent, child])
        await session.flush()

        result = await correlate_process_parent_child(
            session=session, investigation_id=inv.id
        )

        assert isinstance(result, CorrelationResult)
        assert result.investigation_id == inv.id
        assert result.relationships_created == 1
        assert result.relationships_skipped_duplicate == 0

    @pytest.mark.anyio
    async def test_multiple_independent_pairs_all_matched(self, session: AsyncSession):
        """Three events forming two independent parent/child pairs produce two relationships."""
        inv, evd = await _setup(session)

        # Pair 1: PID 100
        p1 = _make_event(inv.id, evd.id, process_id="100")
        c1 = _make_event(inv.id, evd.id, parent_process_id="100")
        # Pair 2: PID 200
        p2 = _make_event(inv.id, evd.id, process_id="200")
        c2 = _make_event(inv.id, evd.id, parent_process_id="200")
        session.add_all([p1, c1, p2, c2])
        await session.flush()

        result = await correlate_process_parent_child(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 2
        assert result.relationships_skipped_duplicate == 0

        rows = (
            await session.execute(
                select(Relationship).where(Relationship.investigation_id == inv.id)
            )
        ).scalars().all()
        assert len(rows) == 2


# ──────────────────────────────────────────────────────────────────────────────
# Group 2: PID mismatch
# ──────────────────────────────────────────────────────────────────────────────


class TestPIDMismatch:
    @pytest.mark.anyio
    async def test_pid_mismatch_no_relationship(self, session: AsyncSession):
        """Events with non-matching PIDs produce no relationship."""
        inv, evd = await _setup(session)

        e1 = _make_event(inv.id, evd.id, process_id="100")
        e2 = _make_event(inv.id, evd.id, parent_process_id="999")
        session.add_all([e1, e2])
        await session.flush()

        result = await correlate_process_parent_child(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 0
        rows = (
            await session.execute(
                select(Relationship).where(Relationship.investigation_id == inv.id)
            )
        ).scalars().all()
        assert len(rows) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Group 3: Missing PID fields
# ──────────────────────────────────────────────────────────────────────────────


class TestMissingPID:
    @pytest.mark.anyio
    async def test_missing_process_id_no_match(self, session: AsyncSession):
        """Event without process_id cannot be a parent candidate."""
        inv, evd = await _setup(session)

        e1 = _make_event(inv.id, evd.id, process_id=None)
        e2 = _make_event(inv.id, evd.id, parent_process_id="100")
        session.add_all([e1, e2])
        await session.flush()

        result = await correlate_process_parent_child(
            session=session, investigation_id=inv.id
        )
        assert result.relationships_created == 0

    @pytest.mark.anyio
    async def test_missing_parent_process_id_no_match(self, session: AsyncSession):
        """Event without parent_process_id cannot be a child candidate."""
        inv, evd = await _setup(session)

        e1 = _make_event(inv.id, evd.id, process_id="100")
        e2 = _make_event(inv.id, evd.id, parent_process_id=None)
        session.add_all([e1, e2])
        await session.flush()

        result = await correlate_process_parent_child(
            session=session, investigation_id=inv.id
        )
        assert result.relationships_created == 0

    @pytest.mark.anyio
    async def test_both_pids_missing_no_match(self, session: AsyncSession):
        """Events with no process ID fields produce no relationships."""
        inv, evd = await _setup(session)

        e1 = _make_event(inv.id, evd.id, process_id=None, parent_process_id=None)
        e2 = _make_event(inv.id, evd.id, process_id=None, parent_process_id=None)
        session.add_all([e1, e2])
        await session.flush()

        result = await correlate_process_parent_child(
            session=session, investigation_id=inv.id
        )
        assert result.relationships_created == 0


# ──────────────────────────────────────────────────────────────────────────────
# Group 4: Cross-investigation isolation
# ──────────────────────────────────────────────────────────────────────────────


class TestCrossInvestigationIsolation:
    @pytest.mark.anyio
    async def test_cross_investigation_no_relationship(self, session: AsyncSession):
        """
        Two events with matching PIDs in different investigations produce no
        relationship when the rule is run for investigation A.
        """
        # Investigation A
        inv_a = _make_investigation()
        session.add(inv_a)
        await session.flush()
        evd_a = _make_evidence(inv_a.id)
        session.add(evd_a)
        await session.flush()

        # Investigation B
        inv_b = _make_investigation()
        session.add(inv_b)
        await session.flush()
        evd_b = _make_evidence(inv_b.id)
        session.add(evd_b)
        await session.flush()

        # Parent in A, child in B — same PID string "555"
        parent_a = _make_event(inv_a.id, evd_a.id, process_id="555")
        child_b = _make_event(inv_b.id, evd_b.id, parent_process_id="555")
        session.add_all([parent_a, child_b])
        await session.flush()

        result_a = await correlate_process_parent_child(
            session=session, investigation_id=inv_a.id
        )
        result_b = await correlate_process_parent_child(
            session=session, investigation_id=inv_b.id
        )

        # Neither investigation has a complete parent+child pair
        assert result_a.relationships_created == 0
        assert result_b.relationships_created == 0


# ──────────────────────────────────────────────────────────────────────────────
# Group 5: Self-reference protection
# ──────────────────────────────────────────────────────────────────────────────


class TestSelfReferenceProtection:
    @pytest.mark.anyio
    async def test_self_reference_not_created(self, session: AsyncSession):
        """
        A single event where process_id == parent_process_id must not produce
        a self-referential relationship.

        The DB CHECK (ck_relationship_no_self_reference) also enforces this,
        but the application-layer guard (E1.id != E2.id) prevents the attempt
        from reaching the DB at all.
        """
        inv, evd = await _setup(session)

        # One event that appears in both parent and child candidate sets
        e = _make_event(inv.id, evd.id, process_id="100", parent_process_id="100")
        session.add(e)
        await session.flush()

        result = await correlate_process_parent_child(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 0
        rows = (
            await session.execute(
                select(Relationship).where(Relationship.investigation_id == inv.id)
            )
        ).scalars().all()
        assert len(rows) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Group 6: Idempotency
# ──────────────────────────────────────────────────────────────────────────────


class TestIdempotency:
    @pytest.mark.anyio
    async def test_idempotent_second_run_skips(self, session: AsyncSession):
        """
        Running the correlator twice on the same events must produce exactly
        one Relationship and two RelationshipSupport rows in total.

        The second run must report created=0 and skipped=1.
        """
        inv, evd = await _setup(session)

        parent = _make_event(inv.id, evd.id, process_id="7777")
        child = _make_event(inv.id, evd.id, parent_process_id="7777")
        session.add_all([parent, child])
        await session.flush()

        result1 = await correlate_process_parent_child(
            session=session, investigation_id=inv.id
        )
        assert result1.relationships_created == 1
        assert result1.relationships_skipped_duplicate == 0

        result2 = await correlate_process_parent_child(
            session=session, investigation_id=inv.id
        )
        assert result2.relationships_created == 0
        assert result2.relationships_skipped_duplicate == 1

        # Exactly one Relationship row total
        all_rels = (
            await session.execute(
                select(Relationship).where(Relationship.investigation_id == inv.id)
            )
        ).scalars().all()
        assert len(all_rels) == 1

        # Exactly two RelationshipSupport rows total
        all_supports = (
            await session.execute(
                select(RelationshipSupport).where(
                    RelationshipSupport.relationship_id == all_rels[0].id
                )
            )
        ).scalars().all()
        assert len(all_supports) == 2

    @pytest.mark.anyio
    async def test_idempotent_support_not_duplicated(self, session: AsyncSession):
        """
        The uq_relationship_support DB constraint must not be violated on
        repeated runs.  The app-layer skip prevents the second INSERT attempt.
        """
        inv, evd = await _setup(session)

        parent = _make_event(inv.id, evd.id, process_id="8888")
        child = _make_event(inv.id, evd.id, parent_process_id="8888")
        session.add_all([parent, child])
        await session.flush()

        # First run
        await correlate_process_parent_child(
            session=session, investigation_id=inv.id
        )
        # Second run — must not raise IntegrityError
        await correlate_process_parent_child(
            session=session, investigation_id=inv.id
        )

        # Confirm support row count is still exactly 2
        rel = (
            await session.execute(
                select(Relationship).where(Relationship.investigation_id == inv.id)
            )
        ).scalar_one()
        support_count = len(
            (
                await session.execute(
                    select(RelationshipSupport).where(
                        RelationshipSupport.relationship_id == rel.id
                    )
                )
            ).scalars().all()
        )
        assert support_count == 2


# ──────────────────────────────────────────────────────────────────────────────
# Group 7: Boundary / negative cases
# ──────────────────────────────────────────────────────────────────────────────


class TestBoundaryNegative:
    @pytest.mark.anyio
    async def test_process_name_alone_no_match(self, session: AsyncSession):
        """
        Events with matching process_name/parent_process_name but no process_id
        must produce no relationship.

        The rule matches on PID fields only.  Name-only correlation is
        explicitly rejected.
        """
        inv, evd = await _setup(session)

        e1 = _make_event(
            inv.id, evd.id,
            process_id=None,   # no PID
            parent_process_id=None,
        )
        e1.process_name = "powershell.exe"

        e2 = _make_event(
            inv.id, evd.id,
            process_id=None,
            parent_process_id=None,
        )
        e2.parent_process_name = "powershell.exe"

        session.add_all([e1, e2])
        await session.flush()

        result = await correlate_process_parent_child(
            session=session, investigation_id=inv.id
        )
        assert result.relationships_created == 0

    @pytest.mark.anyio
    async def test_empty_investigation_no_relationships(self, session: AsyncSession):
        """Correlating an investigation with no events produces zero relationships."""
        inv = _make_investigation()
        session.add(inv)
        await session.flush()

        result = await correlate_process_parent_child(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 0
        assert result.relationships_skipped_duplicate == 0

    @pytest.mark.anyio
    async def test_one_event_no_relationships(self, session: AsyncSession):
        """A single event with a process_id but no child produces zero relationships."""
        inv, evd = await _setup(session)

        e = _make_event(inv.id, evd.id, process_id="300")
        session.add(e)
        await session.flush()

        result = await correlate_process_parent_child(
            session=session, investigation_id=inv.id
        )
        assert result.relationships_created == 0

    @pytest.mark.anyio
    async def test_pid_string_equality_no_numeric_coercion(self, session: AsyncSession):
        """
        PID matching is exact string equality.  Integer 4812 and hex "0x12CC"
        represent the same numeric value but must NOT match.
        """
        inv, evd = await _setup(session)

        parent = _make_event(inv.id, evd.id, process_id="4812")
        child = _make_event(inv.id, evd.id, parent_process_id="0x12CC")
        session.add_all([parent, child])
        await session.flush()

        result = await correlate_process_parent_child(
            session=session, investigation_id=inv.id
        )
        assert result.relationships_created == 0

    @pytest.mark.anyio
    async def test_relationship_fields_are_correct(self, session: AsyncSession):
        """Verify every field of the created Relationship row is correct."""
        inv, evd = await _setup(session)

        parent = _make_event(inv.id, evd.id, process_id="1111")
        child = _make_event(inv.id, evd.id, parent_process_id="1111")
        session.add_all([parent, child])
        await session.flush()

        await correlate_process_parent_child(
            session=session, investigation_id=inv.id
        )

        rel = (
            await session.execute(
                select(Relationship).where(Relationship.investigation_id == inv.id)
            )
        ).scalar_one()

        assert rel.investigation_id == inv.id
        assert rel.relationship_type == "SPAWNED"
        assert rel.creation_method == "PROCESS_PARENT_CHILD"
        assert rel.status == "SYSTEM_PROPOSED"
        assert rel.source_event_id == parent.id
        assert rel.target_event_id == child.id
        assert rel.source_entity_id is None
        assert rel.target_entity_id is None
        assert rel.explanation != ""
        assert rel.id is not None
