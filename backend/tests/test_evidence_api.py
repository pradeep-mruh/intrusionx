"""
Phase 3C — Evidence Ingestion API: test suite.

Architecture
------------
The API endpoint (POST /api/v1/evidence/ingest) owns its own transaction:
it calls Phase 3A (ingest_evidence), Phase 3B (normalize_evidence), and
then commits.  Tests therefore cannot share one long-lived session with the
API request — the API commits inside its own session, while assertions must
read from the database AFTER that commit using a separate session.

Session strategy
~~~~~~~~~~~~~~~~
- ``api_session_factory``: a session factory bound to the test engine.
  The ``get_session`` FastAPI dependency is overridden to yield a fresh
  session from this factory for each API request.  The API commits through
  that session as normal.
- ``db_session``: a short-lived AsyncSession opened in each test **after**
  the API call returns, used only for assertions and cleanup.

Storage isolation
~~~~~~~~~~~~~~~~~
The ``get_storage_root`` FastAPI dependency is overridden in each test to
return an isolated temporary directory (``tmp_path``).  This ensures that
the real ``data/raw/`` directory is never written to during tests.

Cleanup
~~~~~~~
After each test that committed Evidence rows the helper
``_cleanup_investigation`` deletes rows in FK-safe order:
    EventEntityRef → NormalizedEvent → Evidence → Investigation

It uses a fresh, independent session (not the API's session) so there is
no shared mutable state.
"""

import hashlib
import json
import os
import uuid
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.v1.evidence import get_storage_root
from app.core.database import Base, get_session
from app.main import app
from app.models.entity import Entity, EventEntityRef
from app.models.evidence import Evidence
from app.models.investigation import Investigation
from app.models.normalized_event import NormalizedEvent

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://intrusionx:intrusionx_dev@localhost:5432/intrusionx",
)

_ENDPOINT = "/api/v1/evidence/ingest"

# A valid single-event payload used across most tests.
_SAMPLE_EVENT: dict = {
    "timestamp": "2026-01-01T00:00:00Z",
    "event_type": "network_connection",
    "source_ip": "192.168.1.10",
    "destination_ip": "10.0.0.1",
    "source_port": 443,
    "destination_port": 443,
    "host": "sensor-01",
}

_SAMPLE_CONTENT = json.dumps(_SAMPLE_EVENT)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _build_request(investigation_id: uuid.UUID, **overrides) -> dict:
    """Return a minimal valid request body."""
    body = {
        "investigation_id": str(investigation_id),
        "source_identifier": "test.json",
        "content": _SAMPLE_CONTENT,
    }
    body.update(overrides)
    return body


# ---------------------------------------------------------------------------
# Session-scoped engine and table setup
# ---------------------------------------------------------------------------


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
    """Ensure all tables exist once per test session."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


@pytest_asyncio.fixture(scope="session")
async def session_factory(engine, db_tables):
    """Return a session factory bound to the test engine."""
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


# ---------------------------------------------------------------------------
# Per-test fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture()
async def db_session(session_factory) -> AsyncGenerator[AsyncSession, None]:
    """
    Yield a fresh AsyncSession for use in post-request assertions and cleanup.

    This session is completely independent of the session used by the API
    request (which is created and managed by the get_session override below).
    """
    async with session_factory() as sess:
        yield sess


@pytest_asyncio.fixture()
async def investigation(session_factory) -> AsyncGenerator[Investigation, None]:
    """
    Insert a minimal Investigation and yield it.

    Uses its own dedicated session so that the row is committed and visible
    to both the API's session and the assertion session.

    Cleans up all rows created under this investigation (FK-safe order) after
    each test, regardless of whether the test itself called
    ``_cleanup_investigation``.  Tests that already call it explicitly will
    trigger a harmless no-op on teardown.
    """
    inv = Investigation(
        id=uuid.uuid4(),
        title="Phase 3C API Test Investigation",
        status="OPEN",
        created_by=uuid.uuid4(),
    )
    async with session_factory() as sess:
        async with sess.begin():
            sess.add(inv)
    yield inv
    await _cleanup_investigation(session_factory, inv.id)


@pytest_asyncio.fixture()
async def investigation2(session_factory) -> AsyncGenerator[Investigation, None]:
    """A second investigation used in cross-investigation duplicate tests.

    Cleans up after itself on teardown (same strategy as the ``investigation``
    fixture).
    """
    inv = Investigation(
        id=uuid.uuid4(),
        title="Phase 3C API Test Investigation 2",
        status="OPEN",
        created_by=uuid.uuid4(),
    )
    async with session_factory() as sess:
        async with sess.begin():
            sess.add(inv)
    yield inv
    await _cleanup_investigation(session_factory, inv.id)


@pytest.fixture()
def storage_dir(tmp_path) -> Path:
    """Return an isolated temporary directory for evidence file storage."""
    d = tmp_path / "evidence_raw"
    d.mkdir()
    return d


@pytest_asyncio.fixture()
async def client(session_factory, storage_dir) -> AsyncGenerator[AsyncClient, None]:
    """
    Yield an AsyncClient with both critical dependencies overridden:

    - ``get_session``: yields a fresh session from the test engine so the
      API's commits land in the same PostgreSQL instance assertions use,
      without sharing session state.
    - ``get_storage_root``: returns an isolated tmpdir so no files reach
      data/raw/.
    """

    async def _override_get_session() -> AsyncGenerator[AsyncSession, None]:
        async with session_factory() as sess:
            yield sess

    def _override_get_storage_root() -> Path:
        return storage_dir

    app.dependency_overrides[get_session] = _override_get_session
    app.dependency_overrides[get_storage_root] = _override_get_storage_root

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            yield c
    finally:
        app.dependency_overrides.pop(get_session, None)
        app.dependency_overrides.pop(get_storage_root, None)


# ---------------------------------------------------------------------------
# Cleanup helper
# ---------------------------------------------------------------------------


async def _cleanup_investigation(
    session_factory, investigation_id: uuid.UUID
) -> None:
    """
    Delete all rows created for an investigation, in FK-safe order.

    Order:
      1. EventEntityRef  (FK → NormalizedEvent.id and Entity.id)
      2. NormalizedEvent (FK → Evidence.id and Investigation.id)
      3. Entity          (FK → Investigation.id)
      4. Evidence        (FK → Investigation.id)
      5. Investigation

    Uses its own independent session and commits so that rows are truly
    gone before the next test.
    """
    async with session_factory() as sess:
        async with sess.begin():
            # 1. EventEntityRef rows (via NormalizedEvent FK)
            ne_ids_result = await sess.execute(
                select(NormalizedEvent.id).where(
                    NormalizedEvent.investigation_id == investigation_id
                )
            )
            ne_ids = [row[0] for row in ne_ids_result]
            if ne_ids:
                await sess.execute(
                    delete(EventEntityRef).where(
                        EventEntityRef.event_id.in_(ne_ids)
                    )
                )

            # 2. NormalizedEvent
            await sess.execute(
                delete(NormalizedEvent).where(
                    NormalizedEvent.investigation_id == investigation_id
                )
            )

            # 3. Entity  (FK → Investigation)
            await sess.execute(
                delete(Entity).where(
                    Entity.investigation_id == investigation_id
                )
            )

            # 4. Evidence
            await sess.execute(
                delete(Evidence).where(
                    Evidence.investigation_id == investigation_id
                )
            )

            # 5. Investigation
            await sess.execute(
                delete(Investigation).where(Investigation.id == investigation_id)
            )



# ---------------------------------------------------------------------------
# Group 1: Successful ingestion
# ---------------------------------------------------------------------------


class TestSuccessfulIngestion:
    """New evidence returns 201 with correct fields."""

    @pytest.mark.anyio
    async def test_new_evidence_returns_201(
        self, client, investigation, session_factory
    ):
        resp = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        await _cleanup_investigation(session_factory, investigation.id)
        assert resp.status_code == 201

    @pytest.mark.anyio
    async def test_response_contains_evidence_id(
        self, client, investigation, session_factory
    ):
        resp = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        await _cleanup_investigation(session_factory, investigation.id)
        body = resp.json()
        uuid.UUID(body["evidence_id"])  # raises if not a valid UUID

    @pytest.mark.anyio
    async def test_sha256_is_correct(
        self, client, investigation, session_factory
    ):
        resp = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        await _cleanup_investigation(session_factory, investigation.id)
        body = resp.json()
        assert body["content_hash"] == _sha256(_SAMPLE_CONTENT)

    @pytest.mark.anyio
    async def test_hash_is_64_char_lowercase_hex(
        self, client, investigation, session_factory
    ):
        resp = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        await _cleanup_investigation(session_factory, investigation.id)
        h = resp.json()["content_hash"]
        assert len(h) == 64
        assert h == h.lower()
        assert all(c in "0123456789abcdef" for c in h)

    @pytest.mark.anyio
    async def test_is_not_duplicate(
        self, client, investigation, session_factory
    ):
        resp = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        await _cleanup_investigation(session_factory, investigation.id)
        assert resp.json()["is_duplicate"] is False

    @pytest.mark.anyio
    async def test_evidence_is_persisted(
        self, client, investigation, session_factory, db_session
    ):
        resp = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        evidence_id = uuid.UUID(resp.json()["evidence_id"])
        row = await db_session.get(Evidence, evidence_id)
        await _cleanup_investigation(session_factory, investigation.id)
        assert row is not None
        assert row.investigation_id == investigation.id

    @pytest.mark.anyio
    async def test_evidence_is_immutable(
        self, client, investigation, session_factory, db_session
    ):
        resp = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        evidence_id = uuid.UUID(resp.json()["evidence_id"])
        row = await db_session.get(Evidence, evidence_id)
        await _cleanup_investigation(session_factory, investigation.id)
        assert row is not None
        assert row.is_immutable is True

    @pytest.mark.anyio
    async def test_normalized_events_are_persisted(
        self, client, investigation, session_factory, db_session
    ):
        resp = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        evidence_id = uuid.UUID(resp.json()["evidence_id"])
        result = await db_session.execute(
            select(NormalizedEvent).where(
                NormalizedEvent.evidence_id == evidence_id
            )
        )
        events = result.scalars().all()
        await _cleanup_investigation(session_factory, investigation.id)
        assert len(events) == 1

    @pytest.mark.anyio
    async def test_event_count_is_correct(
        self, client, investigation, session_factory
    ):
        resp = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        await _cleanup_investigation(session_factory, investigation.id)
        assert resp.json()["event_count"] == 1

    @pytest.mark.anyio
    async def test_events_created_has_correct_length(
        self, client, investigation, session_factory
    ):
        resp = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        await _cleanup_investigation(session_factory, investigation.id)
        assert len(resp.json()["events_created"]) == 1

    @pytest.mark.anyio
    async def test_event_summary_fields_present(
        self, client, investigation, session_factory
    ):
        resp = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        await _cleanup_investigation(session_factory, investigation.id)
        summary = resp.json()["events_created"][0]
        assert "event_id" in summary
        assert "event_type" in summary
        assert "event_category" in summary
        assert "occurred_at" in summary

    @pytest.mark.anyio
    async def test_event_type_is_canonical(
        self, client, investigation, session_factory
    ):
        resp = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        await _cleanup_investigation(session_factory, investigation.id)
        assert resp.json()["events_created"][0]["event_type"] == "NETWORK_CONNECTION"

    @pytest.mark.anyio
    async def test_event_order_matches_input_order(
        self, client, investigation, session_factory
    ):
        """Multi-event payload: response events are in input order."""
        events = [
            {
                "timestamp": "2026-01-01T00:00:01Z",
                "event_type": "process_start",
                "host": "host-a",
                "process": "cmd.exe",
            },
            {
                "timestamp": "2026-01-01T00:00:02Z",
                "event_type": "user_login",
                "host": "host-a",
                "user": "alice",
            },
        ]
        content = json.dumps(events)
        resp = await client.post(
            _ENDPOINT, json=_build_request(investigation.id, content=content)
        )
        await _cleanup_investigation(session_factory, investigation.id)
        assert resp.status_code == 201
        types = [e["event_type"] for e in resp.json()["events_created"]]
        assert types == ["PROCESS_START", "USER_LOGIN"]

    @pytest.mark.anyio
    async def test_response_event_ids_are_valid_uuids(
        self, client, investigation, session_factory
    ):
        resp = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        await _cleanup_investigation(session_factory, investigation.id)
        for summary in resp.json()["events_created"]:
            uuid.UUID(summary["event_id"])  # raises if invalid


# ---------------------------------------------------------------------------
# Group 2: Duplicate behavior
# ---------------------------------------------------------------------------


class TestDuplicateBehavior:
    """Submitting the same content twice to the same investigation."""

    @pytest.mark.anyio
    async def test_duplicate_returns_200(
        self, client, investigation, session_factory
    ):
        await client.post(_ENDPOINT, json=_build_request(investigation.id))
        resp = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        await _cleanup_investigation(session_factory, investigation.id)
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_duplicate_is_marked_as_duplicate(
        self, client, investigation, session_factory
    ):
        await client.post(_ENDPOINT, json=_build_request(investigation.id))
        resp = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        await _cleanup_investigation(session_factory, investigation.id)
        assert resp.json()["is_duplicate"] is True

    @pytest.mark.anyio
    async def test_duplicate_returns_same_evidence_id(
        self, client, investigation, session_factory
    ):
        r1 = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        r2 = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        await _cleanup_investigation(session_factory, investigation.id)
        assert r1.json()["evidence_id"] == r2.json()["evidence_id"]

    @pytest.mark.anyio
    async def test_duplicate_returns_same_hash(
        self, client, investigation, session_factory
    ):
        r1 = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        r2 = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        await _cleanup_investigation(session_factory, investigation.id)
        assert r1.json()["content_hash"] == r2.json()["content_hash"]

    @pytest.mark.anyio
    async def test_duplicate_has_zero_events(
        self, client, investigation, session_factory
    ):
        await client.post(_ENDPOINT, json=_build_request(investigation.id))
        resp = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        await _cleanup_investigation(session_factory, investigation.id)
        body = resp.json()
        assert body["event_count"] == 0
        assert body["events_created"] == []

    @pytest.mark.anyio
    async def test_duplicate_does_not_create_extra_evidence_rows(
        self, client, investigation, session_factory, db_session
    ):
        await client.post(_ENDPOINT, json=_build_request(investigation.id))
        await client.post(_ENDPOINT, json=_build_request(investigation.id))
        result = await db_session.execute(
            select(Evidence).where(Evidence.investigation_id == investigation.id)
        )
        rows = result.scalars().all()
        await _cleanup_investigation(session_factory, investigation.id)
        assert len(rows) == 1

    @pytest.mark.anyio
    async def test_duplicate_does_not_create_extra_normalized_events(
        self, client, investigation, session_factory, db_session
    ):
        r1 = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        evidence_id = uuid.UUID(r1.json()["evidence_id"])
        await client.post(_ENDPOINT, json=_build_request(investigation.id))
        result = await db_session.execute(
            select(NormalizedEvent).where(
                NormalizedEvent.evidence_id == evidence_id
            )
        )
        events = result.scalars().all()
        await _cleanup_investigation(session_factory, investigation.id)
        assert len(events) == 1

    @pytest.mark.anyio
    async def test_same_content_different_investigation_creates_new_evidence(
        self, client, investigation, investigation2, session_factory, db_session
    ):
        r1 = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        r2 = await client.post(_ENDPOINT, json=_build_request(investigation2.id))
        await _cleanup_investigation(session_factory, investigation.id)
        await _cleanup_investigation(session_factory, investigation2.id)
        assert r1.status_code == 201
        assert r2.status_code == 201
        assert r1.json()["evidence_id"] != r2.json()["evidence_id"]
        assert r2.json()["is_duplicate"] is False


# ---------------------------------------------------------------------------
# Group 3: Request validation (no DB required — schema-level)
# ---------------------------------------------------------------------------


class TestRequestValidation:
    """Pydantic schema validation at the HTTP boundary."""

    @pytest.mark.anyio
    async def test_missing_investigation_id_returns_422(self, client, investigation):
        body = {"source_identifier": "test.json", "content": _SAMPLE_CONTENT}
        resp = await client.post(_ENDPOINT, json=body)
        assert resp.status_code == 422

    @pytest.mark.anyio
    async def test_invalid_uuid_returns_422(self, client, investigation):
        body = _build_request(investigation.id)
        body["investigation_id"] = "not-a-uuid"
        resp = await client.post(_ENDPOINT, json=body)
        assert resp.status_code == 422

    @pytest.mark.anyio
    async def test_missing_source_identifier_returns_422(self, client, investigation):
        body = {
            "investigation_id": str(investigation.id),
            "content": _SAMPLE_CONTENT,
        }
        resp = await client.post(_ENDPOINT, json=body)
        assert resp.status_code == 422

    @pytest.mark.anyio
    async def test_empty_source_identifier_returns_422(self, client, investigation):
        body = _build_request(investigation.id, source_identifier="")
        resp = await client.post(_ENDPOINT, json=body)
        assert resp.status_code == 422

    @pytest.mark.anyio
    async def test_missing_content_returns_422(self, client, investigation):
        body = {
            "investigation_id": str(investigation.id),
            "source_identifier": "test.json",
        }
        resp = await client.post(_ENDPOINT, json=body)
        assert resp.status_code == 422

    @pytest.mark.anyio
    async def test_empty_content_returns_422(self, client, investigation):
        body = _build_request(investigation.id, content="")
        resp = await client.post(_ENDPOINT, json=body)
        assert resp.status_code == 422

    @pytest.mark.anyio
    async def test_extra_field_returns_422(self, client, investigation):
        body = _build_request(investigation.id)
        body["unexpected_field"] = "value"
        resp = await client.post(_ENDPOINT, json=body)
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Group 4: Evidence content validation (Phase 3A errors → 422)
# ---------------------------------------------------------------------------


class TestEvidenceContentValidation:
    """Phase 3A input validation errors surface as 422."""

    @pytest.mark.anyio
    async def test_malformed_json_returns_422(self, client, investigation):
        body = _build_request(investigation.id, content="{not valid json}")
        resp = await client.post(_ENDPOINT, json=body)
        assert resp.status_code == 422

    @pytest.mark.anyio
    async def test_unsafe_source_identifier_returns_422(
        self, client, investigation
    ):
        body = _build_request(
            investigation.id, source_identifier="../../../etc/passwd"
        )
        resp = await client.post(_ENDPOINT, json=body)
        assert resp.status_code == 422

    @pytest.mark.anyio
    async def test_null_byte_in_source_identifier_returns_422(
        self, client, investigation
    ):
        body = _build_request(
            investigation.id, source_identifier="file\x00name.json"
        )
        resp = await client.post(_ENDPOINT, json=body)
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Group 4b: Ingestion error response structure
# ---------------------------------------------------------------------------


class TestIngestionErrorResponseStructure:
    """
    Phase 3A validation errors must return a stable structured response
    consistent with the normalization error contract, without exposing JSON
    parser internals, byte counts, or other implementation details.
    """

    @pytest.mark.anyio
    async def test_invalid_json_response_is_structured(
        self, client, investigation
    ):
        """detail for INVALID_JSON is {message, errors} — not a bare string."""
        resp = await client.post(
            _ENDPOINT,
            json=_build_request(investigation.id, content="{not valid json}"),
        )
        assert resp.status_code == 422
        detail = resp.json()["detail"]
        assert isinstance(detail, dict)
        assert "message" in detail
        assert "errors" in detail
        assert isinstance(detail["errors"], list)
        assert len(detail["errors"]) >= 1

    @pytest.mark.anyio
    async def test_invalid_json_error_code(
        self, client, investigation
    ):
        resp = await client.post(
            _ENDPOINT,
            json=_build_request(investigation.id, content="{not valid json}"),
        )
        assert resp.status_code == 422
        err = resp.json()["detail"]["errors"][0]
        assert err["code"] == "INVALID_JSON"
        assert err["field"] == "content"

    @pytest.mark.anyio
    async def test_invalid_json_does_not_expose_parser_internals(
        self, client, investigation
    ):
        """
        Python's json parser messages (e.g.
        "Expecting property name enclosed in double quotes: line 1 column 2
        (char 1)") must not appear in the API response.
        """
        resp = await client.post(
            _ENDPOINT,
            json=_build_request(investigation.id, content="{not valid json}"),
        )
        reason = resp.json()["detail"]["errors"][0]["reason"]
        assert "line" not in reason
        assert "column" not in reason
        assert "char" not in reason
        assert "Expecting" not in reason

    @pytest.mark.anyio
    async def test_unsafe_source_identifier_response_structure(
        self, client, investigation
    ):
        resp = await client.post(
            _ENDPOINT,
            json=_build_request(
                investigation.id, source_identifier="../../../etc/passwd"
            ),
        )
        assert resp.status_code == 422
        detail = resp.json()["detail"]
        assert isinstance(detail, dict)
        assert "message" in detail
        errors = detail["errors"]
        assert len(errors) >= 1
        assert errors[0]["code"] == "UNSAFE_SOURCE_IDENTIFIER"
        assert errors[0]["field"] == "source_identifier"

    @pytest.mark.anyio
    async def test_unsafe_source_identifier_does_not_expose_path(
        self, client, investigation
    ):
        """The traversal string supplied by the caller must not appear in the response."""
        resp = await client.post(
            _ENDPOINT,
            json=_build_request(
                investigation.id, source_identifier="../../../etc/passwd"
            ),
        )
        detail = resp.json()["detail"]
        assert "etc/passwd" not in str(detail)
        assert "../" not in str(detail)

    @pytest.mark.anyio
    async def test_too_large_evidence_response_structure(
        self, client, investigation
    ):
        """EvidenceTooLargeError must not expose byte counts in the reason."""
        oversized = "x" * (51 * 1024 * 1024)  # 51 MB — exceeds Phase 3A limit
        resp = await client.post(
            _ENDPOINT,
            json=_build_request(investigation.id, content=oversized),
        )
        assert resp.status_code == 422
        detail = resp.json()["detail"]
        assert isinstance(detail, dict)
        err = detail["errors"][0]
        assert err["code"] == "EVIDENCE_TOO_LARGE"
        assert "bytes" not in err["reason"]
        # The exact byte count (53477376) must not appear.
        assert str(51 * 1024 * 1024) not in err["reason"]


# ---------------------------------------------------------------------------
# Group 5: Investigation not found
# ---------------------------------------------------------------------------


class TestInvestigationNotFound:
    """Unknown investigation_id must return 404 before any ingestion occurs."""

    @pytest.mark.anyio
    async def test_nonexistent_investigation_returns_404(self, client):
        body = {
            "investigation_id": str(uuid.uuid4()),
            "source_identifier": "test.json",
            "content": _SAMPLE_CONTENT,
        }
        resp = await client.post(_ENDPOINT, json=body)
        assert resp.status_code == 404

    @pytest.mark.anyio
    async def test_404_no_evidence_created(
        self, client, session_factory, db_session
    ):
        """No Evidence row is created when the investigation is missing."""
        fake_id = uuid.uuid4()
        body = {
            "investigation_id": str(fake_id),
            "source_identifier": "test.json",
            "content": _SAMPLE_CONTENT,
        }
        await client.post(_ENDPOINT, json=body)
        result = await db_session.execute(
            select(Evidence).where(Evidence.investigation_id == fake_id)
        )
        assert result.scalar_one_or_none() is None


# ---------------------------------------------------------------------------
# Group 6: Normalization validation failures (Phase 3B errors → 422)
# ---------------------------------------------------------------------------


class TestNormalizationValidation:
    """Phase 3B validation errors surface as structured 422 responses."""

    @pytest.mark.anyio
    async def test_unknown_event_type_returns_422(self, client, investigation):
        bad = json.dumps({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "totally_unknown_type",
        })
        resp = await client.post(
            _ENDPOINT, json=_build_request(investigation.id, content=bad)
        )
        assert resp.status_code == 422

    @pytest.mark.anyio
    async def test_unknown_event_type_response_structure(
        self, client, investigation
    ):
        bad = json.dumps({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "totally_unknown_type",
        })
        resp = await client.post(
            _ENDPOINT, json=_build_request(investigation.id, content=bad)
        )
        detail = resp.json()["detail"]
        assert "message" in detail
        assert "errors" in detail
        assert isinstance(detail["errors"], list)
        assert len(detail["errors"]) >= 1
        err = detail["errors"][0]
        assert err["code"] == "UNKNOWN_EVENT_TYPE"

    @pytest.mark.anyio
    async def test_invalid_timestamp_returns_422(self, client, investigation):
        bad = json.dumps({
            "timestamp": "not-a-timestamp",
            "event_type": "network_connection",
        })
        resp = await client.post(
            _ENDPOINT, json=_build_request(investigation.id, content=bad)
        )
        assert resp.status_code == 422

    @pytest.mark.anyio
    async def test_naive_timestamp_returns_422(self, client, investigation):
        """Timestamps without timezone info must be rejected."""
        bad = json.dumps({
            "timestamp": "2026-01-01T00:00:00",  # no timezone
            "event_type": "network_connection",
        })
        resp = await client.post(
            _ENDPOINT, json=_build_request(investigation.id, content=bad)
        )
        assert resp.status_code == 422

    @pytest.mark.anyio
    async def test_invalid_ip_returns_422(self, client, investigation):
        bad = json.dumps({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "network_connection",
            "source_ip": "999.999.999.999",
        })
        resp = await client.post(
            _ENDPOINT, json=_build_request(investigation.id, content=bad)
        )
        assert resp.status_code == 422

    @pytest.mark.anyio
    async def test_invalid_port_returns_422(self, client, investigation):
        bad = json.dumps({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "network_connection",
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "source_port": 99999,  # out of range
        })
        resp = await client.post(
            _ENDPOINT, json=_build_request(investigation.id, content=bad)
        )
        assert resp.status_code == 422

    @pytest.mark.anyio
    async def test_partial_multi_event_failure_returns_422(
        self, client, investigation
    ):
        """All-or-nothing: one bad event in a two-event array fails the whole request."""
        events = [
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "event_type": "network_connection",
                "source_ip": "10.0.0.1",
                "destination_ip": "10.0.0.2",
            },
            {
                "timestamp": "2026-01-01T00:00:01Z",
                "event_type": "INVALID_TYPE",
            },
        ]
        content = json.dumps(events)
        resp = await client.post(
            _ENDPOINT, json=_build_request(investigation.id, content=content)
        )
        assert resp.status_code == 422

    @pytest.mark.anyio
    async def test_partial_failure_response_contains_error_codes(
        self, client, investigation
    ):
        events = [
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "event_type": "network_connection",
                "source_ip": "10.0.0.1",
                "destination_ip": "10.0.0.2",
            },
            {
                "timestamp": "2026-01-01T00:00:01Z",
                "event_type": "INVALID_TYPE",
            },
        ]
        content = json.dumps(events)
        resp = await client.post(
            _ENDPOINT, json=_build_request(investigation.id, content=content)
        )
        detail = resp.json()["detail"]
        codes = {e["code"] for e in detail["errors"]}
        assert "UNKNOWN_EVENT_TYPE" in codes


# ---------------------------------------------------------------------------
# Group 7: Transaction behavior after failure
# ---------------------------------------------------------------------------


class TestTransactionBehaviorOnFailure:
    """
    After normalization failure: DB rows are rolled back and orphaned files
    are cleaned up.
    """

    @pytest.mark.anyio
    async def test_no_evidence_row_after_normalization_failure(
        self, client, investigation, session_factory, db_session
    ):
        bad = json.dumps({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "unknown_type",
        })
        resp = await client.post(
            _ENDPOINT, json=_build_request(investigation.id, content=bad)
        )
        assert resp.status_code == 422
        result = await db_session.execute(
            select(Evidence).where(Evidence.investigation_id == investigation.id)
        )
        assert result.scalar_one_or_none() is None
        # investigation was created but never used — clean it up
        await _cleanup_investigation(session_factory, investigation.id)

    @pytest.mark.anyio
    async def test_no_normalized_event_row_after_normalization_failure(
        self, client, investigation, session_factory, db_session
    ):
        bad = json.dumps({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "unknown_type",
        })
        resp = await client.post(
            _ENDPOINT, json=_build_request(investigation.id, content=bad)
        )
        assert resp.status_code == 422
        result = await db_session.execute(
            select(NormalizedEvent).where(
                NormalizedEvent.investigation_id == investigation.id
            )
        )
        assert result.scalar_one_or_none() is None
        await _cleanup_investigation(session_factory, investigation.id)

    @pytest.mark.anyio
    async def test_orphaned_file_is_cleaned_up_after_normalization_failure(
        self, client, investigation, session_factory, storage_dir
    ):
        """
        After a normalization failure the router should remove any file
        that Phase 3A wrote for the (now-rolled-back) Evidence record.
        """
        bad = json.dumps({
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "unknown_type",
        })
        resp = await client.post(
            _ENDPOINT, json=_build_request(investigation.id, content=bad)
        )
        assert resp.status_code == 422
        # storage_dir must be empty — the router cleaned up the orphaned file.
        remaining = list(storage_dir.iterdir())
        await _cleanup_investigation(session_factory, investigation.id)
        assert remaining == [], (
            f"Orphaned files remain in storage_dir: {remaining}"
        )

    @pytest.mark.anyio
    async def test_duplicate_commit_failure_returns_500(
        self, investigation, session_factory, storage_dir, db_session
    ):
        """
        On the duplicate fast-path, if session.commit() raises SQLAlchemyError:
          - HTTP 500 is returned with a generic response (no internal details)
          - Session is rolled back
          - No new Evidence row is created
          - The original evidence file is not deleted
        """
        # ── Phase 1: create the initial evidence normally ─────────────────────
        async def _normal_session() -> AsyncGenerator[AsyncSession, None]:
            async with session_factory() as sess:
                yield sess

        app.dependency_overrides[get_session] = _normal_session
        app.dependency_overrides[get_storage_root] = lambda: storage_dir
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                r1 = await c.post(_ENDPOINT, json=_build_request(investigation.id))
            assert r1.status_code == 201
        finally:
            app.dependency_overrides.pop(get_session, None)
            app.dependency_overrides.pop(get_storage_root, None)

        files_after_creation = list(storage_dir.iterdir())
        assert len(files_after_creation) == 1  # sanity: one evidence file written

        # ── Phase 2: duplicate submission — commit() raises SQLAlchemyError ───
        async def _commit_failing_session() -> AsyncGenerator[AsyncSession, None]:
            async with session_factory() as sess:
                async def _raise() -> None:
                    raise SQLAlchemyError("injected commit failure")

                sess.commit = _raise  # type: ignore[method-assign]
                yield sess

        app.dependency_overrides[get_session] = _commit_failing_session
        app.dependency_overrides[get_storage_root] = lambda: storage_dir
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as c:
                resp = await c.post(_ENDPOINT, json=_build_request(investigation.id))
        finally:
            app.dependency_overrides.pop(get_session, None)
            app.dependency_overrides.pop(get_storage_root, None)

        # ── Assertions ────────────────────────────────────────────────────────
        assert resp.status_code == 500
        body = resp.json()
        assert "detail" in body
        assert "injected" not in str(body["detail"])
        assert "SQLAlchemy" not in str(body["detail"])

        # No new Evidence row was committed (duplicate path never creates rows).
        result = await db_session.execute(
            select(Evidence).where(
                Evidence.investigation_id == investigation.id
            )
        )
        rows = result.scalars().all()
        assert len(rows) == 1, (
            f"Expected 1 evidence row (original), found {len(rows)}"
        )

        # The original evidence file was not deleted.
        files_after_failure = list(storage_dir.iterdir())
        assert len(files_after_failure) == 1, (
            f"Expected 1 file (original), found: {files_after_failure}"
        )


# ---------------------------------------------------------------------------
# Group 8: Lineage
# ---------------------------------------------------------------------------


class TestLineage:
    """Normalized events reference the correct evidence and investigation."""

    @pytest.mark.anyio
    async def test_normalized_event_references_correct_evidence(
        self, client, investigation, session_factory, db_session
    ):
        resp = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        evidence_id = uuid.UUID(resp.json()["evidence_id"])
        event_id = uuid.UUID(resp.json()["events_created"][0]["event_id"])
        event = await db_session.get(NormalizedEvent, event_id)
        await _cleanup_investigation(session_factory, investigation.id)
        assert event is not None
        assert event.evidence_id == evidence_id

    @pytest.mark.anyio
    async def test_normalized_event_references_correct_investigation(
        self, client, investigation, session_factory, db_session
    ):
        resp = await client.post(_ENDPOINT, json=_build_request(investigation.id))
        event_id = uuid.UUID(resp.json()["events_created"][0]["event_id"])
        event = await db_session.get(NormalizedEvent, event_id)
        await _cleanup_investigation(session_factory, investigation.id)
        assert event is not None
        assert event.investigation_id == investigation.id


# ---------------------------------------------------------------------------
# Group 9: Unexpected exception handling
# ---------------------------------------------------------------------------


class TestUnexpectedException:
    """
    Verify that an unexpected (non-SQLAlchemy, non-normalization) exception
    raised after new evidence has been successfully written results in:
      - HTTP 500
      - generic response body (no internal details)
      - no Evidence row persisted
      - no NormalizedEvent row persisted
      - no orphaned file remaining in the storage directory

    The injection point is normalize_evidence(), which is the first
    significant operation performed after Phase 3A successfully writes the
    file and flushes the Evidence row.  Patching it to raise RuntimeError
    simulates any unanticipated failure in that window.
    """

    @pytest.mark.anyio
    async def test_unexpected_exception_returns_500(
        self, client, investigation, session_factory
    ):
        """An unexpected exception after new ingestion returns HTTP 500."""
        with patch(
            "app.api.v1.evidence.normalize_evidence",
            new=AsyncMock(side_effect=RuntimeError("injected unexpected error")),
        ):
            resp = await client.post(
                _ENDPOINT, json=_build_request(investigation.id)
            )
        await _cleanup_investigation(session_factory, investigation.id)
        assert resp.status_code == 500

    @pytest.mark.anyio
    async def test_unexpected_exception_response_is_generic(
        self, client, investigation, session_factory
    ):
        """
        The 500 response body must not contain stack traces, internal
        exception messages, filesystem paths, SQL, or raw evidence.
        """
        with patch(
            "app.api.v1.evidence.normalize_evidence",
            new=AsyncMock(side_effect=RuntimeError("injected unexpected error")),
        ):
            resp = await client.post(
                _ENDPOINT, json=_build_request(investigation.id)
            )
        await _cleanup_investigation(session_factory, investigation.id)
        body = resp.json()
        # The response must have a 'detail' key (FastAPI convention for errors).
        assert "detail" in body
        detail = body["detail"]
        # Internal exception message must not leak.
        assert "injected" not in str(detail)
        assert "RuntimeError" not in str(detail)
        # Filesystem paths must not leak.
        assert "/" not in str(detail)
        # Raw evidence must not leak.
        assert "network_connection" not in str(detail)

    @pytest.mark.anyio
    async def test_unexpected_exception_no_evidence_row(
        self, client, investigation, session_factory, db_session
    ):
        """After an unexpected exception no Evidence row must be committed."""
        with patch(
            "app.api.v1.evidence.normalize_evidence",
            new=AsyncMock(side_effect=RuntimeError("injected unexpected error")),
        ):
            await client.post(_ENDPOINT, json=_build_request(investigation.id))

        result = await db_session.execute(
            select(Evidence).where(Evidence.investigation_id == investigation.id)
        )
        await _cleanup_investigation(session_factory, investigation.id)
        assert result.scalar_one_or_none() is None

    @pytest.mark.anyio
    async def test_unexpected_exception_no_normalized_event_row(
        self, client, investigation, session_factory, db_session
    ):
        """After an unexpected exception no NormalizedEvent row must exist."""
        with patch(
            "app.api.v1.evidence.normalize_evidence",
            new=AsyncMock(side_effect=RuntimeError("injected unexpected error")),
        ):
            await client.post(_ENDPOINT, json=_build_request(investigation.id))

        result = await db_session.execute(
            select(NormalizedEvent).where(
                NormalizedEvent.investigation_id == investigation.id
            )
        )
        await _cleanup_investigation(session_factory, investigation.id)
        assert result.scalar_one_or_none() is None

    @pytest.mark.anyio
    async def test_unexpected_exception_no_orphaned_file(
        self, client, investigation, session_factory, storage_dir
    ):
        """
        After an unexpected exception the router must clean up the evidence
        file that Phase 3A successfully wrote before the failure occurred.
        No file must remain in the isolated storage directory.
        """
        with patch(
            "app.api.v1.evidence.normalize_evidence",
            new=AsyncMock(side_effect=RuntimeError("injected unexpected error")),
        ):
            await client.post(_ENDPOINT, json=_build_request(investigation.id))

        remaining = list(storage_dir.iterdir())
        await _cleanup_investigation(session_factory, investigation.id)
        assert remaining == [], (
            f"Orphaned files remain after unexpected exception: {remaining}"
        )
