"""
Phase 5A — Reconstruction Service test suite.

Tests are organised into eight concern groups:

 1. Positive: simple linear paths
 2. Negative: zero / empty inputs
 3. Unsupported shapes (skipped — branching, convergence, multi-root)
 4. Cycles (skipped)
 5. Timestamp edge cases (topology always wins)
 6. Relationship status handling
 7. Transaction and step-type behaviour
 8. Result dataclass

SESSION STRATEGY
----------------
Follows the test_correlation_process_parent_child.py pattern: function-
scoped transactional rollback.  The ``session`` fixture opens a
transaction and rolls back after each test — no rows are committed.

build_reconstruction never commits (caller owns the transaction), so all
writes made during a test are visible within the same session and are
cleanly rolled back on teardown.

All tests run against real PostgreSQL.  No mocks.
"""

from __future__ import annotations

import hashlib
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
from app.models.reconstruction import Reconstruction, ReconstructionStep
from app.models.relationship import Relationship
from app.reconstruction.service import ReconstructionResult, build_reconstruction

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
_HOST_A = "laptop-07"


def _make_investigation() -> Investigation:
    return Investigation(
        id=uuid.uuid4(),
        title="Phase 5A Reconstruction Test",
        status="OPEN",
        created_by=uuid.uuid4(),
    )


def _make_evidence(investigation_id: uuid.UUID) -> Evidence:
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
    event_type: str = "PROCESS_START",
    occurred_at: datetime = _NOW,
    source_host: str | None = _HOST_A,
) -> NormalizedEvent:
    return NormalizedEvent(
        id=uuid.uuid4(),
        investigation_id=investigation_id,
        evidence_id=evidence_id,
        occurred_at=occurred_at,
        event_type=event_type,
        event_category="PROCESS",
        source_host=source_host,
    )


def _make_relationship(
    investigation_id: uuid.UUID,
    source_event_id: uuid.UUID,
    target_event_id: uuid.UUID,
    *,
    relationship_type: str = "SPAWNED",
    status: str = "SYSTEM_PROPOSED",
    creation_method: str = "TEST",
    explanation: str = "test relationship",
) -> Relationship:
    return Relationship(
        id=uuid.uuid4(),
        investigation_id=investigation_id,
        relationship_type=relationship_type,
        source_event_id=source_event_id,
        source_entity_id=None,
        target_event_id=target_event_id,
        target_entity_id=None,
        creation_method=creation_method,
        status=status,
        explanation=explanation,
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


async def _get_reconstructions(
    session: AsyncSession, investigation_id: uuid.UUID
) -> list[Reconstruction]:
    rows = (
        await session.execute(
            select(Reconstruction).where(
                Reconstruction.investigation_id == investigation_id
            )
        )
    ).scalars().all()
    return list(rows)


async def _get_steps(
    session: AsyncSession, reconstruction_id: uuid.UUID
) -> list[ReconstructionStep]:
    rows = (
        await session.execute(
            select(ReconstructionStep)
            .where(ReconstructionStep.reconstruction_id == reconstruction_id)
            .order_by(ReconstructionStep.step_order)
        )
    ).scalars().all()
    return list(rows)


# ──────────────────────────────────────────────────────────────────────────────
# Group 1: Positive — simple linear paths
# ──────────────────────────────────────────────────────────────────────────────


class TestPositiveLinearPaths:
    @pytest.mark.anyio
    async def test_single_relationship_two_events(self, session: AsyncSession):
        """One relationship A→B produces one Reconstruction with 3 steps."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        session.add_all([a, b])
        await session.flush()

        rel = _make_relationship(inv.id, a.id, b.id)
        session.add(rel)
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)

        assert result.reconstructions_created == 1
        assert result.steps_created == 3
        assert result.components_skipped_unsupported == 0
        assert result.components_skipped_cycle == 0

        recons = await _get_reconstructions(session, inv.id)
        assert len(recons) == 1

        steps = await _get_steps(session, recons[0].id)
        assert len(steps) == 3
        types = [s.step_type for s in steps]
        assert types == ["EVENT", "RELATIONSHIP", "EVENT"]
        assert steps[0].event_id == a.id
        assert steps[1].relationship_id == rel.id
        assert steps[2].event_id == b.id

    @pytest.mark.anyio
    async def test_linear_path_three_events(self, session: AsyncSession):
        """A→B→C produces one Reconstruction with 5 steps."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        c = _make_event(inv.id, evd.id)
        session.add_all([a, b, c])
        await session.flush()

        rel_ab = _make_relationship(inv.id, a.id, b.id)
        rel_bc = _make_relationship(inv.id, b.id, c.id, relationship_type="CREATED")
        session.add_all([rel_ab, rel_bc])
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)

        assert result.reconstructions_created == 1
        assert result.steps_created == 5

        recons = await _get_reconstructions(session, inv.id)
        steps = await _get_steps(session, recons[0].id)
        types = [s.step_type for s in steps]
        assert types == ["EVENT", "RELATIONSHIP", "EVENT", "RELATIONSHIP", "EVENT"]

        event_ids = [s.event_id for s in steps if s.step_type == "EVENT"]
        rel_ids = [s.relationship_id for s in steps if s.step_type == "RELATIONSHIP"]
        assert event_ids == [a.id, b.id, c.id]
        assert rel_ids == [rel_ab.id, rel_bc.id]

    @pytest.mark.anyio
    async def test_scenario_spawned_and_created(self, session: AsyncSession):
        """
        Replicates the Phase 4A/4C scenario:
        E2 (WINWORD, SPAWNED) → E3 (powershell, CREATED) → E5 (FILE_CREATE).
        Expects 1 Reconstruction, 5 steps.
        """
        inv, evd = await _setup(session)

        e2 = _make_event(inv.id, evd.id, event_type="PROCESS_START")
        e3 = _make_event(inv.id, evd.id, event_type="PROCESS_START")
        e5 = _make_event(inv.id, evd.id, event_type="FILE_CREATE")
        session.add_all([e2, e3, e5])
        await session.flush()

        rel1 = _make_relationship(inv.id, e2.id, e3.id, relationship_type="SPAWNED")
        rel2 = _make_relationship(inv.id, e3.id, e5.id, relationship_type="CREATED")
        session.add_all([rel1, rel2])
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)

        assert result.reconstructions_created == 1
        assert result.steps_created == 5

        recons = await _get_reconstructions(session, inv.id)
        steps = await _get_steps(session, recons[0].id)

        assert steps[0].step_type == "EVENT" and steps[0].event_id == e2.id
        assert steps[1].step_type == "RELATIONSHIP" and steps[1].relationship_id == rel1.id
        assert steps[2].step_type == "EVENT" and steps[2].event_id == e3.id
        assert steps[3].step_type == "RELATIONSHIP" and steps[3].relationship_id == rel2.id
        assert steps[4].step_type == "EVENT" and steps[4].event_id == e5.id

    @pytest.mark.anyio
    async def test_system_proposed_relationship_included(self, session: AsyncSession):
        """SYSTEM_PROPOSED relationships are included in the reconstruction."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        session.add_all([a, b])
        await session.flush()

        rel = _make_relationship(inv.id, a.id, b.id, status="SYSTEM_PROPOSED")
        session.add(rel)
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)
        assert result.reconstructions_created == 1

    @pytest.mark.anyio
    async def test_analyst_confirmed_relationship_included(self, session: AsyncSession):
        """ANALYST_CONFIRMED relationships are included in the reconstruction."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        session.add_all([a, b])
        await session.flush()

        rel = _make_relationship(inv.id, a.id, b.id, status="ANALYST_CONFIRMED")
        session.add(rel)
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)
        assert result.reconstructions_created == 1

    @pytest.mark.anyio
    async def test_reconstruction_status_is_draft(self, session: AsyncSession):
        """Automatically assembled reconstructions start in DRAFT status."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        session.add_all([a, b])
        await session.flush()
        session.add(_make_relationship(inv.id, a.id, b.id))
        await session.flush()

        await build_reconstruction(session=session, investigation_id=inv.id)

        recons = await _get_reconstructions(session, inv.id)
        assert recons[0].status == "DRAFT"

    @pytest.mark.anyio
    async def test_reconstruction_title_format(self, session: AsyncSession):
        """Title of the first chain is 'Relationship chain 1'."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        session.add_all([a, b])
        await session.flush()
        session.add(_make_relationship(inv.id, a.id, b.id))
        await session.flush()

        await build_reconstruction(session=session, investigation_id=inv.id)

        recons = await _get_reconstructions(session, inv.id)
        assert recons[0].title == "Relationship Reconstruction"

    @pytest.mark.anyio
    async def test_description_is_none(self, session: AsyncSession):
        """Service leaves description as None — it is not auto-populated."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        session.add_all([a, b])
        await session.flush()
        session.add(_make_relationship(inv.id, a.id, b.id))
        await session.flush()

        await build_reconstruction(session=session, investigation_id=inv.id)

        recons = await _get_reconstructions(session, inv.id)
        assert recons[0].description is None

    @pytest.mark.anyio
    async def test_step_order_increments_by_10(self, session: AsyncSession):
        """Step orders for A→B→C are exactly [10, 20, 30, 40, 50]."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        c = _make_event(inv.id, evd.id)
        session.add_all([a, b, c])
        await session.flush()
        session.add_all([
            _make_relationship(inv.id, a.id, b.id),
            _make_relationship(inv.id, b.id, c.id),
        ])
        await session.flush()

        await build_reconstruction(session=session, investigation_id=inv.id)

        recons = await _get_reconstructions(session, inv.id)
        steps = await _get_steps(session, recons[0].id)
        assert [s.step_order for s in steps] == [10, 20, 30, 40, 50]

    @pytest.mark.anyio
    async def test_step_types_alternate_event_relationship(self, session: AsyncSession):
        """Step types for A→B→C alternate EVENT / RELATIONSHIP / EVENT / ..."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        c = _make_event(inv.id, evd.id)
        session.add_all([a, b, c])
        await session.flush()
        session.add_all([
            _make_relationship(inv.id, a.id, b.id),
            _make_relationship(inv.id, b.id, c.id),
        ])
        await session.flush()

        await build_reconstruction(session=session, investigation_id=inv.id)

        recons = await _get_reconstructions(session, inv.id)
        steps = await _get_steps(session, recons[0].id)
        assert [s.step_type for s in steps] == [
            "EVENT", "RELATIONSHIP", "EVENT", "RELATIONSHIP", "EVENT"
        ]

    @pytest.mark.anyio
    async def test_two_independent_linear_paths(self, session: AsyncSession):
        """
        Two disconnected linear paths A→B and C→D each produce their own
        Reconstruction row.
        """
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        c = _make_event(inv.id, evd.id)
        d = _make_event(inv.id, evd.id)
        session.add_all([a, b, c, d])
        await session.flush()

        session.add_all([
            _make_relationship(inv.id, a.id, b.id),
            _make_relationship(inv.id, c.id, d.id),
        ])
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)

        assert result.reconstructions_created == 2
        assert result.steps_created == 6  # 3 + 3

        recons = await _get_reconstructions(session, inv.id)
        assert len(recons) == 2
        assert all(r.title == "Relationship Reconstruction" for r in recons)


# ──────────────────────────────────────────────────────────────────────────────
# Group 2: Negative — zero / empty inputs
# ──────────────────────────────────────────────────────────────────────────────


class TestEmptyInputs:
    @pytest.mark.anyio
    async def test_zero_relationships(self, session: AsyncSession):
        """No relationships → empty result, no exception."""
        inv, _ = await _setup(session)

        result = await build_reconstruction(session=session, investigation_id=inv.id)

        assert result.reconstructions_created == 0
        assert result.steps_created == 0
        assert result.components_skipped_unsupported == 0
        assert result.components_skipped_cycle == 0
        assert await _get_reconstructions(session, inv.id) == []

    @pytest.mark.anyio
    async def test_only_rejected_relationships(self, session: AsyncSession):
        """ANALYST_REJECTED relationships are excluded before graph build → 0 results."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        session.add_all([a, b])
        await session.flush()

        session.add(_make_relationship(inv.id, a.id, b.id, status="ANALYST_REJECTED"))
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)
        assert result.reconstructions_created == 0
        assert result.steps_created == 0

    @pytest.mark.anyio
    async def test_isolated_event_no_relationship(self, session: AsyncSession):
        """An event with no relationship edges produces no reconstruction."""
        inv, evd = await _setup(session)

        session.add(_make_event(inv.id, evd.id))
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)
        assert result.reconstructions_created == 0

    @pytest.mark.anyio
    async def test_two_isolated_events(self, session: AsyncSession):
        """Two events with no relationships between them produce no reconstruction."""
        inv, evd = await _setup(session)

        session.add_all([_make_event(inv.id, evd.id), _make_event(inv.id, evd.id)])
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)
        assert result.reconstructions_created == 0


# ──────────────────────────────────────────────────────────────────────────────
# Group 3: Unsupported shapes (skipped)
# ──────────────────────────────────────────────────────────────────────────────


class TestUnsupportedShapes:
    @pytest.mark.anyio
    async def test_branching_graph_skipped(self, session: AsyncSession):
        """A→B and A→C (A has out_degree=2) → component skipped."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        c = _make_event(inv.id, evd.id)
        session.add_all([a, b, c])
        await session.flush()

        session.add_all([
            _make_relationship(inv.id, a.id, b.id),
            _make_relationship(inv.id, a.id, c.id),
        ])
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)

        assert result.reconstructions_created == 0
        assert result.steps_created == 0
        assert result.components_skipped_unsupported >= 1

    @pytest.mark.anyio
    async def test_convergent_graph_skipped(self, session: AsyncSession):
        """A→C and B→C (C has in_degree=2) → component skipped."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        c = _make_event(inv.id, evd.id)
        session.add_all([a, b, c])
        await session.flush()

        session.add_all([
            _make_relationship(inv.id, a.id, c.id),
            _make_relationship(inv.id, b.id, c.id),
        ])
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)

        assert result.reconstructions_created == 0
        assert result.components_skipped_unsupported >= 1

    @pytest.mark.anyio
    async def test_diamond_graph_skipped(self, session: AsyncSession):
        """A→B→D and A→C→D (branching and convergence) → component skipped."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        c = _make_event(inv.id, evd.id)
        d = _make_event(inv.id, evd.id)
        session.add_all([a, b, c, d])
        await session.flush()

        session.add_all([
            _make_relationship(inv.id, a.id, b.id),
            _make_relationship(inv.id, a.id, c.id),
            _make_relationship(inv.id, b.id, d.id),
            _make_relationship(inv.id, c.id, d.id),
        ])
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)

        assert result.reconstructions_created == 0
        assert result.components_skipped_unsupported >= 1


# ──────────────────────────────────────────────────────────────────────────────
# Group 4: Cycles
# ──────────────────────────────────────────────────────────────────────────────


class TestCycles:
    @pytest.mark.anyio
    async def test_cycle_three_nodes_skipped(self, session: AsyncSession):
        """
        A→B→C→A (manually created — Phase 4 rules cannot produce cycles,
        but Phase 5A must detect and skip them).
        """
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        c = _make_event(inv.id, evd.id)
        session.add_all([a, b, c])
        await session.flush()

        # Manually insert cycle — bypass domain service
        session.add_all([
            _make_relationship(inv.id, a.id, b.id),
            _make_relationship(inv.id, b.id, c.id),
            _make_relationship(inv.id, c.id, a.id),
        ])
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)

        assert result.reconstructions_created == 0
        assert result.steps_created == 0
        assert result.components_skipped_cycle >= 1
        assert result.components_skipped_unsupported == 0

    @pytest.mark.anyio
    async def test_two_node_cycle_skipped(self, session: AsyncSession):
        """
        A→B→A (2-cycle): every node has in_degree=1 and out_degree=1.
        If cycle detection ran after linear-shape validation it would be
        misclassified as 'unsupported' (no unique root).  The correct
        result is components_skipped_cycle >= 1.
        """
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        session.add_all([a, b])
        await session.flush()

        session.add_all([
            _make_relationship(inv.id, a.id, b.id),
            _make_relationship(inv.id, b.id, a.id),
        ])
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)

        assert result.reconstructions_created == 0
        assert result.components_skipped_cycle >= 1
        # Must NOT be counted as unsupported — that would be the wrong classification.
        assert result.components_skipped_unsupported == 0


# ──────────────────────────────────────────────────────────────────────────────
# Group 5: Timestamp edge cases (topology always wins)
# ──────────────────────────────────────────────────────────────────────────────


class TestTimestampEdgeCases:
    @pytest.mark.anyio
    async def test_timestamp_inversion_does_not_affect_step_order(
        self, session: AsyncSession
    ):
        """
        A→B where A.occurred_at > B.occurred_at (timestamp inversion).
        Step sequence still follows topology: EVENT A, REL, EVENT B.
        """
        from datetime import timedelta

        inv, evd = await _setup(session)

        later = _NOW
        earlier = _NOW - timedelta(hours=1)

        a = _make_event(inv.id, evd.id, occurred_at=later)   # later timestamp
        b = _make_event(inv.id, evd.id, occurred_at=earlier)  # earlier timestamp
        session.add_all([a, b])
        await session.flush()

        rel = _make_relationship(inv.id, a.id, b.id)
        session.add(rel)
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)

        assert result.reconstructions_created == 1
        assert result.steps_created == 3

        recons = await _get_reconstructions(session, inv.id)
        steps = await _get_steps(session, recons[0].id)

        # Topology wins: source event A (later timestamp) is step 10
        assert steps[0].step_type == "EVENT"
        assert steps[0].event_id == a.id
        assert steps[1].step_type == "RELATIONSHIP"
        assert steps[2].step_type == "EVENT"
        assert steps[2].event_id == b.id

    @pytest.mark.anyio
    async def test_equal_timestamps_do_not_cause_failure(self, session: AsyncSession):
        """
        All events share identical occurred_at.  The service does not
        consult timestamps and must not fail or reorder steps.
        """
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id, occurred_at=_NOW)
        b = _make_event(inv.id, evd.id, occurred_at=_NOW)
        c = _make_event(inv.id, evd.id, occurred_at=_NOW)
        session.add_all([a, b, c])
        await session.flush()

        rel_ab = _make_relationship(inv.id, a.id, b.id)
        rel_bc = _make_relationship(inv.id, b.id, c.id)
        session.add_all([rel_ab, rel_bc])
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)

        assert result.reconstructions_created == 1
        assert result.steps_created == 5


# ──────────────────────────────────────────────────────────────────────────────
# Group 6: Relationship status handling
# ──────────────────────────────────────────────────────────────────────────────


class TestRelationshipStatusHandling:
    @pytest.mark.anyio
    async def test_mixed_proposed_and_confirmed(self, session: AsyncSession):
        """
        A→B (SYSTEM_PROPOSED) and B→C (ANALYST_CONFIRMED) → both included.
        One Reconstruction, 5 steps.
        """
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        c = _make_event(inv.id, evd.id)
        session.add_all([a, b, c])
        await session.flush()

        session.add_all([
            _make_relationship(inv.id, a.id, b.id, status="SYSTEM_PROPOSED"),
            _make_relationship(inv.id, b.id, c.id, status="ANALYST_CONFIRMED"),
        ])
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)
        assert result.reconstructions_created == 1
        assert result.steps_created == 5

    @pytest.mark.anyio
    async def test_rejected_mid_path_surviving_segment_reconstructed(
        self, session: AsyncSession
    ):
        """
        A→B (SYSTEM_PROPOSED), B→C (ANALYST_REJECTED).

        ANALYST_REJECTED is excluded BEFORE graph construction.  The
        effective graph is A→B only.  A→B is a valid 2-event linear path
        and produces 1 Reconstruction with 3 steps.  C is absent — it has
        no included incoming or outgoing edges.

        This is the critical correction from the plan review: a rejected
        mid-path edge must NOT erase the independently eligible A→B edge.
        """
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        c = _make_event(inv.id, evd.id)
        session.add_all([a, b, c])
        await session.flush()

        rel_ab = _make_relationship(inv.id, a.id, b.id, status="SYSTEM_PROPOSED")
        session.add(rel_ab)
        session.add(_make_relationship(inv.id, b.id, c.id, status="ANALYST_REJECTED"))
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)

        assert result.reconstructions_created == 1
        assert result.steps_created == 3

        recons = await _get_reconstructions(session, inv.id)
        steps = await _get_steps(session, recons[0].id)

        assert steps[0].step_type == "EVENT" and steps[0].event_id == a.id
        assert steps[1].step_type == "RELATIONSHIP" and steps[1].relationship_id == rel_ab.id
        assert steps[2].step_type == "EVENT" and steps[2].event_id == b.id

    @pytest.mark.anyio
    async def test_rejected_relationship_absent_from_graph(
        self, session: AsyncSession
    ):
        """Only relationship is ANALYST_REJECTED → effective graph empty → 0 results."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        session.add_all([a, b])
        await session.flush()

        session.add(_make_relationship(inv.id, a.id, b.id, status="ANALYST_REJECTED"))
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)

        assert result.reconstructions_created == 0
        assert result.steps_created == 0

    @pytest.mark.anyio
    async def test_relationship_status_preserved_via_fk(self, session: AsyncSession):
        """
        ReconstructionStep stores relationship_id only.  The underlying
        Relationship.status is queryable via that FK without denormalization.
        """
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        session.add_all([a, b])
        await session.flush()

        rel = _make_relationship(inv.id, a.id, b.id, status="SYSTEM_PROPOSED")
        session.add(rel)
        await session.flush()

        await build_reconstruction(session=session, investigation_id=inv.id)

        recons = await _get_reconstructions(session, inv.id)
        steps = await _get_steps(session, recons[0].id)
        rel_step = next(s for s in steps if s.step_type == "RELATIONSHIP")

        # The step points to the correct relationship_id
        assert rel_step.relationship_id == rel.id

        # The underlying status is readable without any copy into the step
        fetched_rel = (
            await session.execute(
                select(Relationship).where(Relationship.id == rel_step.relationship_id)
            )
        ).scalar_one()
        assert fetched_rel.status == "SYSTEM_PROPOSED"


# ──────────────────────────────────────────────────────────────────────────────
# Group 7: Transaction and step-type behaviour
# ──────────────────────────────────────────────────────────────────────────────


class TestTransactionAndStepTypeBehaviour:
    @pytest.mark.anyio
    async def test_transaction_not_committed(self, session: AsyncSession):
        """
        Rows are flushed (visible within the current session) but not committed.
        After the session fixture rolls back, no rows exist.

        This test verifies the within-session visibility; the rollback is
        performed by the session fixture itself.
        """
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        session.add_all([a, b])
        await session.flush()
        session.add(_make_relationship(inv.id, a.id, b.id))
        await session.flush()

        await build_reconstruction(session=session, investigation_id=inv.id)

        # Reconstruction is visible within this session (flushed)
        recons = await _get_reconstructions(session, inv.id)
        assert len(recons) == 1
        # The fixture will roll back — nothing persists to the DB.

    @pytest.mark.anyio
    async def test_no_gap_steps_generated(self, session: AsyncSession):
        """Phase 5A must not generate any GAP steps."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        c = _make_event(inv.id, evd.id)
        session.add_all([a, b, c])
        await session.flush()
        session.add_all([
            _make_relationship(inv.id, a.id, b.id),
            _make_relationship(inv.id, b.id, c.id),
        ])
        await session.flush()

        await build_reconstruction(session=session, investigation_id=inv.id)

        recons = await _get_reconstructions(session, inv.id)
        steps = await _get_steps(session, recons[0].id)
        assert not any(s.step_type == "GAP" for s in steps)

    @pytest.mark.anyio
    async def test_no_note_steps_generated(self, session: AsyncSession):
        """Phase 5A must not generate any NOTE steps."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        session.add_all([a, b])
        await session.flush()
        session.add(_make_relationship(inv.id, a.id, b.id))
        await session.flush()

        await build_reconstruction(session=session, investigation_id=inv.id)

        recons = await _get_reconstructions(session, inv.id)
        steps = await _get_steps(session, recons[0].id)
        assert not any(s.step_type == "NOTE" for s in steps)

    @pytest.mark.anyio
    async def test_cross_investigation_isolation(self, session: AsyncSession):
        """
        Two investigations each with one A→B path.
        Calling build_reconstruction for investigation 1 produces steps
        only for that investigation.
        """
        inv1, evd1 = await _setup(session)
        inv2, evd2 = await _setup(session)

        a1 = _make_event(inv1.id, evd1.id)
        b1 = _make_event(inv1.id, evd1.id)
        session.add_all([a1, b1])
        await session.flush()
        session.add(_make_relationship(inv1.id, a1.id, b1.id))

        a2 = _make_event(inv2.id, evd2.id)
        b2 = _make_event(inv2.id, evd2.id)
        session.add_all([a2, b2])
        await session.flush()
        session.add(_make_relationship(inv2.id, a2.id, b2.id))
        await session.flush()

        result1 = await build_reconstruction(session=session, investigation_id=inv1.id)

        assert result1.reconstructions_created == 1
        # investigation 2 has no reconstruction yet
        assert await _get_reconstructions(session, inv2.id) == []

    @pytest.mark.anyio
    async def test_event_steps_have_null_relationship_id(self, session: AsyncSession):
        """EVENT steps must have relationship_id=None and gap_id=None."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        session.add_all([a, b])
        await session.flush()
        session.add(_make_relationship(inv.id, a.id, b.id))
        await session.flush()

        await build_reconstruction(session=session, investigation_id=inv.id)

        recons = await _get_reconstructions(session, inv.id)
        steps = await _get_steps(session, recons[0].id)
        for s in steps:
            if s.step_type == "EVENT":
                assert s.event_id is not None
                assert s.relationship_id is None
                assert s.gap_id is None

    @pytest.mark.anyio
    async def test_relationship_steps_have_null_event_id(self, session: AsyncSession):
        """RELATIONSHIP steps must have event_id=None and gap_id=None."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        session.add_all([a, b])
        await session.flush()
        session.add(_make_relationship(inv.id, a.id, b.id))
        await session.flush()

        await build_reconstruction(session=session, investigation_id=inv.id)

        recons = await _get_reconstructions(session, inv.id)
        steps = await _get_steps(session, recons[0].id)
        for s in steps:
            if s.step_type == "RELATIONSHIP":
                assert s.relationship_id is not None
                assert s.event_id is None
                assert s.gap_id is None


# ──────────────────────────────────────────────────────────────────────────────
# Group 8: Result dataclass
# ──────────────────────────────────────────────────────────────────────────────


class TestResultDataclass:
    @pytest.mark.anyio
    async def test_result_is_reconstruction_result(self, session: AsyncSession):
        """build_reconstruction always returns a ReconstructionResult instance."""
        inv, _ = await _setup(session)
        result = await build_reconstruction(session=session, investigation_id=inv.id)
        assert isinstance(result, ReconstructionResult)

    @pytest.mark.anyio
    async def test_result_investigation_id(self, session: AsyncSession):
        """result.investigation_id matches the argument passed to the function."""
        inv, _ = await _setup(session)
        result = await build_reconstruction(session=session, investigation_id=inv.id)
        assert result.investigation_id == inv.id

    @pytest.mark.anyio
    async def test_result_reconstructions_created_zero(self, session: AsyncSession):
        """Zero relationships → reconstructions_created == 0."""
        inv, _ = await _setup(session)
        result = await build_reconstruction(session=session, investigation_id=inv.id)
        assert result.reconstructions_created == 0

    @pytest.mark.anyio
    async def test_result_reconstructions_created_one(self, session: AsyncSession):
        """One linear path → reconstructions_created == 1."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        session.add_all([a, b])
        await session.flush()
        session.add(_make_relationship(inv.id, a.id, b.id))
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)
        assert result.reconstructions_created == 1

    @pytest.mark.anyio
    async def test_result_steps_created(self, session: AsyncSession):
        """A→B→C → steps_created == 5."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        c = _make_event(inv.id, evd.id)
        session.add_all([a, b, c])
        await session.flush()
        session.add_all([
            _make_relationship(inv.id, a.id, b.id),
            _make_relationship(inv.id, b.id, c.id),
        ])
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)
        assert result.steps_created == 5

    @pytest.mark.anyio
    async def test_result_components_skipped_unsupported(
        self, session: AsyncSession
    ):
        """Branching component → components_skipped_unsupported >= 1."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        c = _make_event(inv.id, evd.id)
        session.add_all([a, b, c])
        await session.flush()
        session.add_all([
            _make_relationship(inv.id, a.id, b.id),
            _make_relationship(inv.id, a.id, c.id),
        ])
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)
        assert result.components_skipped_unsupported >= 1

    @pytest.mark.anyio
    async def test_result_components_skipped_cycle(self, session: AsyncSession):
        """Cyclic component → components_skipped_cycle >= 1."""
        inv, evd = await _setup(session)

        a = _make_event(inv.id, evd.id)
        b = _make_event(inv.id, evd.id)
        c = _make_event(inv.id, evd.id)
        session.add_all([a, b, c])
        await session.flush()
        session.add_all([
            _make_relationship(inv.id, a.id, b.id),
            _make_relationship(inv.id, b.id, c.id),
            _make_relationship(inv.id, c.id, a.id),
        ])
        await session.flush()

        result = await build_reconstruction(session=session, investigation_id=inv.id)
        assert result.components_skipped_cycle >= 1
