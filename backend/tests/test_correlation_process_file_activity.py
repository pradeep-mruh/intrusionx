"""
Phase 4C — Correlation Engine: process-to-file-activity rule test suite.

Tests are organized into 9 concern groups:

 1. Positive match — FILE_CREATE  (CREATED relationship)
 2. Positive match — FILE_DELETE  (DELETED relationship)
 3. Explanation content
 4. Negative — PID and host predicates
 5. Event-type filter
 6. Cross-investigation isolation and self-reference
 7. Idempotency
 8. Multiple candidates
 9. Boundary / string semantics

Plus one unit test group for the fail-closed relationship-type mapping.

SESSION STRATEGY
----------------
Follows the established transactional rollback fixture pattern:
the ``session`` fixture opens a transaction and rolls back after each test
regardless of outcome.  No rows are committed to the database.

This works because the correlation service never commits (caller owns the
transaction), so all writes made during a test are visible within the same
session and are cleanly rolled back on teardown.

All tests run against real PostgreSQL.  No mocks or monkeypatching.
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
from app.correlation.service import (
    CorrelationResult,
    correlate_process_file_activity,
    _relationship_type_for,
)

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

# Default host used across tests that exercise positive match.
_HOST_A = "laptop-07"
_HOST_B = "desktop-03"


def _make_investigation() -> Investigation:
    return Investigation(
        id=uuid.uuid4(),
        title="Phase 4C Correlation Test",
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
        source_identifier="test_fixture_4c.json",
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
    process_id: str | None = None,
    source_host: str | None = _HOST_A,
    event_category: str = "PROCESS",
) -> NormalizedEvent:
    """
    Build a NormalizedEvent fixture.

    ``source_host`` defaults to _HOST_A so that positive-match tests satisfy
    the host requirement without repeating the host on every call.

    Pass ``source_host=None`` to create a host-less event for negative tests.
    Pass ``process_id=None`` to create a PID-less event for negative tests.
    """
    return NormalizedEvent(
        id=uuid.uuid4(),
        investigation_id=investigation_id,
        evidence_id=evidence_id,
        occurred_at=_NOW,
        event_type=event_type,
        event_category=event_category,
        process_id=process_id,
        source_host=source_host,
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


async def _get_relationships(
    session: AsyncSession, investigation_id: uuid.UUID
) -> list[Relationship]:
    return (
        await session.execute(
            select(Relationship).where(
                Relationship.investigation_id == investigation_id
            )
        )
    ).scalars().all()


async def _get_supports(
    session: AsyncSession, relationship_id: uuid.UUID
) -> list[RelationshipSupport]:
    return (
        await session.execute(
            select(RelationshipSupport).where(
                RelationshipSupport.relationship_id == relationship_id
            )
        )
    ).scalars().all()


# ──────────────────────────────────────────────────────────────────────────────
# Unit test: fail-closed relationship-type mapping
# ──────────────────────────────────────────────────────────────────────────────


class TestRelationshipTypeMapping:
    """Unit tests for the private fail-closed _relationship_type_for helper."""

    def test_file_create_maps_to_created(self):
        assert _relationship_type_for("FILE_CREATE") == "CREATED"

    def test_file_delete_maps_to_deleted(self):
        assert _relationship_type_for("FILE_DELETE") == "DELETED"

    def test_unsupported_type_raises_value_error(self):
        with pytest.raises(ValueError, match="unrecognized file event type"):
            _relationship_type_for("NETWORK_CONNECTION")

    def test_process_start_raises_value_error(self):
        with pytest.raises(ValueError):
            _relationship_type_for("PROCESS_START")

    def test_empty_string_raises_value_error(self):
        with pytest.raises(ValueError):
            _relationship_type_for("")


# ──────────────────────────────────────────────────────────────────────────────
# Group 1: Positive match — FILE_CREATE → CREATED
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestPositiveMatchFileCreate:
    async def test_process_start_file_create_creates_relationship(
        self, session: AsyncSession
    ):
        """PROCESS_START + FILE_CREATE, same host + same PID → 1 CREATED relationship."""
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="4216", source_host=_HOST_A)
        fc = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="4216",
            source_host=_HOST_A,
        )
        session.add_all([proc, fc])
        await session.flush()

        result = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 1
        assert result.relationships_skipped_duplicate == 0
        assert result.investigation_id == inv.id

    async def test_relationship_fields_file_create(self, session: AsyncSession):
        """Relationship row has correct type, method, status, and event links."""
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="4216")
        fc = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="4216",
        )
        session.add_all([proc, fc])
        await session.flush()

        await correlate_process_file_activity(session=session, investigation_id=inv.id)

        rels = await _get_relationships(session, inv.id)
        assert len(rels) == 1
        rel = rels[0]

        assert rel.relationship_type == "CREATED"
        assert rel.creation_method == "PROCESS_FILE_ACTIVITY"
        assert rel.status == "SYSTEM_PROPOSED"
        assert rel.source_event_id == proc.id
        assert rel.target_event_id == fc.id
        assert rel.source_entity_id is None
        assert rel.target_entity_id is None

    async def test_exactly_two_support_rows_file_create(self, session: AsyncSession):
        """A FILE_CREATE match produces exactly two RelationshipSupport rows."""
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="4216")
        fc = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="4216",
        )
        session.add_all([proc, fc])
        await session.flush()

        await correlate_process_file_activity(session=session, investigation_id=inv.id)

        rel = (await _get_relationships(session, inv.id))[0]
        supports = await _get_supports(session, rel.id)
        assert len(supports) == 2

    async def test_support_reasons_file_create(self, session: AsyncSession):
        """Support reasons are PROCESS_HOST_PID_MATCH and FILE_HOST_PID_MATCH."""
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="4216")
        fc = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="4216",
        )
        session.add_all([proc, fc])
        await session.flush()

        await correlate_process_file_activity(session=session, investigation_id=inv.id)

        rel = (await _get_relationships(session, inv.id))[0]
        supports = await _get_supports(session, rel.id)
        reasons = {s.support_reason for s in supports}

        assert "PROCESS_HOST_PID_MATCH" in reasons
        assert "FILE_HOST_PID_MATCH" in reasons

    async def test_support_row_event_links_file_create(self, session: AsyncSession):
        """Support rows link to the correct process and file events."""
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="4216")
        fc = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="4216",
        )
        session.add_all([proc, fc])
        await session.flush()

        await correlate_process_file_activity(session=session, investigation_id=inv.id)

        rel = (await _get_relationships(session, inv.id))[0]
        supports = await _get_supports(session, rel.id)
        support_map = {s.support_reason: s.event_id for s in supports}

        assert support_map["PROCESS_HOST_PID_MATCH"] == proc.id
        assert support_map["FILE_HOST_PID_MATCH"] == fc.id


# ──────────────────────────────────────────────────────────────────────────────
# Group 2: Positive match — FILE_DELETE → DELETED
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestPositiveMatchFileDelete:
    async def test_process_start_file_delete_creates_relationship(
        self, session: AsyncSession
    ):
        """PROCESS_START + FILE_DELETE, same host + same PID → 1 DELETED relationship."""
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="4216")
        fd = _make_event(
            inv.id, evd.id,
            event_type="FILE_DELETE",
            event_category="FILE",
            process_id="4216",
        )
        session.add_all([proc, fd])
        await session.flush()

        result = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 1

    async def test_relationship_type_file_delete(self, session: AsyncSession):
        """FILE_DELETE match produces relationship_type == 'DELETED'."""
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="4216")
        fd = _make_event(
            inv.id, evd.id,
            event_type="FILE_DELETE",
            event_category="FILE",
            process_id="4216",
        )
        session.add_all([proc, fd])
        await session.flush()

        await correlate_process_file_activity(session=session, investigation_id=inv.id)

        rels = await _get_relationships(session, inv.id)
        assert len(rels) == 1
        assert rels[0].relationship_type == "DELETED"

    async def test_support_reasons_file_delete(self, session: AsyncSession):
        """FILE_DELETE match has identical support reasons to FILE_CREATE."""
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="4216")
        fd = _make_event(
            inv.id, evd.id,
            event_type="FILE_DELETE",
            event_category="FILE",
            process_id="4216",
        )
        session.add_all([proc, fd])
        await session.flush()

        await correlate_process_file_activity(session=session, investigation_id=inv.id)

        rel = (await _get_relationships(session, inv.id))[0]
        supports = await _get_supports(session, rel.id)
        reasons = {s.support_reason for s in supports}

        assert "PROCESS_HOST_PID_MATCH" in reasons
        assert "FILE_HOST_PID_MATCH" in reasons
        assert len(supports) == 2


# ──────────────────────────────────────────────────────────────────────────────
# Group 3: Explanation content
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestExplanationContent:
    async def test_explanation_file_create_contains_required_fields(
        self, session: AsyncSession
    ):
        """
        Explanation must contain: process UUID, file UUID, matched PID,
        matched host, exact file event type, and relationship type.
        """
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="4216", source_host="laptop-07")
        fc = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="4216",
            source_host="laptop-07",
        )
        session.add_all([proc, fc])
        await session.flush()

        await correlate_process_file_activity(session=session, investigation_id=inv.id)

        rel = (await _get_relationships(session, inv.id))[0]
        exp = rel.explanation

        assert str(proc.id) in exp        # process event UUID
        assert str(fc.id) in exp          # file event UUID
        assert "4216" in exp              # matched PID
        assert "laptop-07" in exp         # matched host
        assert "FILE_CREATE" in exp       # exact file event type
        assert "CREATED" in exp           # resulting relationship type

    async def test_explanation_file_delete_contains_required_fields(
        self, session: AsyncSession
    ):
        """Same required fields for FILE_DELETE / DELETED."""
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="9999", source_host="laptop-07")
        fd = _make_event(
            inv.id, evd.id,
            event_type="FILE_DELETE",
            event_category="FILE",
            process_id="9999",
            source_host="laptop-07",
        )
        session.add_all([proc, fd])
        await session.flush()

        await correlate_process_file_activity(session=session, investigation_id=inv.id)

        rel = (await _get_relationships(session, inv.id))[0]
        exp = rel.explanation

        assert str(proc.id) in exp
        assert str(fd.id) in exp
        assert "9999" in exp
        assert "laptop-07" in exp
        assert "FILE_DELETE" in exp
        assert "DELETED" in exp


# ──────────────────────────────────────────────────────────────────────────────
# Group 4: Negative — PID and host predicates
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestNegativePredicates:
    async def test_same_host_pid_mismatch_no_relationship(
        self, session: AsyncSession
    ):
        """Same host, different PID → no relationship."""
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="1111")
        fc = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="2222",      # different PID
        )
        session.add_all([proc, fc])
        await session.flush()

        result = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 0

    async def test_same_pid_different_host_no_relationship(
        self, session: AsyncSession
    ):
        """Same PID, different host → no relationship."""
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="4216", source_host=_HOST_A)
        fc = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="4216",
            source_host=_HOST_B,   # different host
        )
        session.add_all([proc, fc])
        await session.flush()

        result = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 0

    async def test_process_missing_pid_no_relationship(self, session: AsyncSession):
        """Process event with process_id=None → no relationship."""
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id=None)   # PID missing
        fc = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="4216",
        )
        session.add_all([proc, fc])
        await session.flush()

        result = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 0

    async def test_file_event_missing_pid_no_relationship(
        self, session: AsyncSession
    ):
        """File event with process_id=None → no relationship."""
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="4216")
        fc = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id=None,         # PID missing on file event
        )
        session.add_all([proc, fc])
        await session.flush()

        result = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 0

    async def test_process_missing_host_no_relationship(self, session: AsyncSession):
        """Process event with source_host=None → no relationship."""
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="4216", source_host=None)
        fc = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="4216",
            source_host=_HOST_A,
        )
        session.add_all([proc, fc])
        await session.flush()

        result = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 0

    async def test_file_event_missing_host_no_relationship(
        self, session: AsyncSession
    ):
        """File event with source_host=None → no relationship."""
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="4216", source_host=_HOST_A)
        fc = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="4216",
            source_host=None,        # host missing on file event
        )
        session.add_all([proc, fc])
        await session.flush()

        result = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 0


# ──────────────────────────────────────────────────────────────────────────────
# Group 5: Event-type filter
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestEventTypeFilter:
    async def test_file_create_cannot_be_process_source(
        self, session: AsyncSession
    ):
        """
        Source must be PROCESS_START.
        FILE_CREATE + FILE_CREATE same host+PID → no relationship.
        """
        inv, evd = await _setup(session)

        fc1 = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="4216",
        )
        fc2 = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="4216",
        )
        session.add_all([fc1, fc2])
        await session.flush()

        result = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 0

    async def test_network_connection_cannot_be_process_source(
        self, session: AsyncSession
    ):
        """
        Source must be PROCESS_START.
        NETWORK_CONNECTION + FILE_CREATE same host+PID → no relationship.
        """
        inv, evd = await _setup(session)

        nc = _make_event(
            inv.id, evd.id,
            event_type="NETWORK_CONNECTION",
            event_category="NETWORK",
            process_id="4216",
        )
        fc = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="4216",
        )
        session.add_all([nc, fc])
        await session.flush()

        result = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 0

    async def test_process_start_cannot_be_file_target(
        self, session: AsyncSession
    ):
        """
        Target must be FILE_CREATE or FILE_DELETE.
        PROCESS_START + PROCESS_START same host+PID → no relationship.
        """
        inv, evd = await _setup(session)

        proc1 = _make_event(inv.id, evd.id, process_id="4216")
        proc2 = _make_event(inv.id, evd.id, process_id="4216")
        session.add_all([proc1, proc2])
        await session.flush()

        result = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 0

    async def test_network_connection_cannot_be_file_target(
        self, session: AsyncSession
    ):
        """
        Target must be FILE_CREATE or FILE_DELETE.
        PROCESS_START + NETWORK_CONNECTION same host+PID → no relationship.
        """
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="4216")
        nc = _make_event(
            inv.id, evd.id,
            event_type="NETWORK_CONNECTION",
            event_category="NETWORK",
            process_id="4216",
        )
        session.add_all([proc, nc])
        await session.flush()

        result = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 0


# ──────────────────────────────────────────────────────────────────────────────
# Group 6: Cross-investigation isolation and self-reference
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestIsolationAndSelfReference:
    async def test_cross_investigation_no_relationship(
        self, session: AsyncSession
    ):
        """PROCESS_START in inv_A, FILE_CREATE in inv_B → no relationship in either."""
        inv_a = _make_investigation()
        inv_b = _make_investigation()
        session.add_all([inv_a, inv_b])
        await session.flush()

        evd_a = _make_evidence(inv_a.id)
        evd_b = _make_evidence(inv_b.id)
        session.add_all([evd_a, evd_b])
        await session.flush()

        proc = _make_event(inv_a.id, evd_a.id, process_id="4216")
        fc = _make_event(
            inv_b.id, evd_b.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="4216",
        )
        session.add_all([proc, fc])
        await session.flush()

        result_a = await correlate_process_file_activity(
            session=session, investigation_id=inv_a.id
        )
        result_b = await correlate_process_file_activity(
            session=session, investigation_id=inv_b.id
        )

        assert result_a.relationships_created == 0
        assert result_b.relationships_created == 0

    async def test_self_reference_protection(self, session: AsyncSession):
        """
        A single event cannot match itself even if process_id is set.
        The join predicate process_event.id != file_event.id prevents it.
        """
        inv, evd = await _setup(session)

        # A PROCESS_START with process_id — the rule requires a FILE event as
        # target, so a lone PROCESS_START can never match itself under this rule.
        # This test verifies the investigation produces 0 relationships even
        # though the event has a non-null process_id.
        proc = _make_event(inv.id, evd.id, process_id="4216")
        session.add(proc)
        await session.flush()

        result = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 0

    async def test_empty_investigation(self, session: AsyncSession):
        """An investigation with no events produces zero relationships."""
        inv = _make_investigation()
        session.add(inv)
        await session.flush()

        result = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 0
        assert result.relationships_skipped_duplicate == 0


# ──────────────────────────────────────────────────────────────────────────────
# Group 7: Idempotency
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestIdempotency:
    async def test_sequential_idempotency_file_create(self, session: AsyncSession):
        """
        Running correlate_process_file_activity twice over the same events
        produces 1 relationship total; second run reports skipped_duplicate=1.
        """
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="4216")
        fc = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="4216",
        )
        session.add_all([proc, fc])
        await session.flush()

        result1 = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )
        result2 = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert result1.relationships_created == 1
        assert result1.relationships_skipped_duplicate == 0
        assert result2.relationships_created == 0
        assert result2.relationships_skipped_duplicate == 1

        # Total rows in DB must be exactly 1.
        rels = await _get_relationships(session, inv.id)
        assert len(rels) == 1

    async def test_sequential_idempotency_file_delete(self, session: AsyncSession):
        """Same idempotency guarantee for FILE_DELETE / DELETED."""
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="4216")
        fd = _make_event(
            inv.id, evd.id,
            event_type="FILE_DELETE",
            event_category="FILE",
            process_id="4216",
        )
        session.add_all([proc, fd])
        await session.flush()

        result1 = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )
        result2 = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert result1.relationships_created == 1
        assert result2.relationships_skipped_duplicate == 1

        rels = await _get_relationships(session, inv.id)
        assert len(rels) == 1

    async def test_support_rows_not_duplicated_on_repeated_execution(
        self, session: AsyncSession
    ):
        """Support rows must not be duplicated when the service is run twice."""
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="4216")
        fc = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="4216",
        )
        session.add_all([proc, fc])
        await session.flush()

        await correlate_process_file_activity(session=session, investigation_id=inv.id)
        await correlate_process_file_activity(session=session, investigation_id=inv.id)

        rel = (await _get_relationships(session, inv.id))[0]
        supports = await _get_supports(session, rel.id)
        assert len(supports) == 2


# ──────────────────────────────────────────────────────────────────────────────
# Group 8: Multiple candidates
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestMultipleCandidates:
    async def test_one_process_matching_file_create_and_file_delete(
        self, session: AsyncSession
    ):
        """
        One PROCESS_START matching both FILE_CREATE and FILE_DELETE →
        two relationships: one CREATED, one DELETED.
        """
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="4216")
        fc = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="4216",
        )
        fd = _make_event(
            inv.id, evd.id,
            event_type="FILE_DELETE",
            event_category="FILE",
            process_id="4216",
        )
        session.add_all([proc, fc, fd])
        await session.flush()

        result = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 2

        rels = await _get_relationships(session, inv.id)
        rel_types = {r.relationship_type for r in rels}
        assert "CREATED" in rel_types
        assert "DELETED" in rel_types

    async def test_multiple_process_start_candidates_same_host_pid(
        self, session: AsyncSession
    ):
        """
        Two PROCESS_START events sharing the same host+PID, one FILE_CREATE →
        two CREATED relationships are proposed.  No silent winner selection.
        """
        inv, evd = await _setup(session)

        proc1 = _make_event(inv.id, evd.id, process_id="4216")
        proc2 = _make_event(inv.id, evd.id, process_id="4216")
        fc = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="4216",
        )
        session.add_all([proc1, proc2, fc])
        await session.flush()

        result = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 2

        rels = await _get_relationships(session, inv.id)
        source_ids = {r.source_event_id for r in rels}
        assert proc1.id in source_ids
        assert proc2.id in source_ids


# ──────────────────────────────────────────────────────────────────────────────
# Group 9: Boundary / string semantics
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestBoundary:
    async def test_exact_pid_string_equality_no_numeric_coercion(
        self, session: AsyncSession
    ):
        """
        PIDs are compared as strings: '4216' != '04216'.
        No numeric coercion may cause a false match.
        """
        inv, evd = await _setup(session)

        proc = _make_event(inv.id, evd.id, process_id="4216")
        fc = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="04216",     # zero-padded — distinct string
        )
        session.add_all([proc, fc])
        await session.flush()

        result = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 0

    async def test_fqdn_vs_short_host_no_relationship(self, session: AsyncSession):
        """
        Stored host values must match exactly.
        'laptop-07' and 'laptop-07.corp.example.com' are distinct after
        normalization; the rule must not match them.
        """
        inv, evd = await _setup(session)

        proc = _make_event(
            inv.id, evd.id,
            process_id="4216",
            source_host="laptop-07",
        )
        fc = _make_event(
            inv.id, evd.id,
            event_type="FILE_CREATE",
            event_category="FILE",
            process_id="4216",
            source_host="laptop-07.corp.example.com",   # FQDN — distinct
        )
        session.add_all([proc, fc])
        await session.flush()

        result = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert result.relationships_created == 0

    async def test_result_is_correlation_result_instance(
        self, session: AsyncSession
    ):
        """Return value is a CorrelationResult with the correct investigation_id."""
        inv, evd = await _setup(session)

        result = await correlate_process_file_activity(
            session=session, investigation_id=inv.id
        )

        assert isinstance(result, CorrelationResult)
        assert result.investigation_id == inv.id
