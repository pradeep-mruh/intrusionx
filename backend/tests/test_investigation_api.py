import uuid
from datetime import datetime, timezone
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from app.main import app
from app.models.investigation import Investigation
from app.models.evidence import Evidence
from app.models.normalized_event import NormalizedEvent

import os
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
import pytest_asyncio

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://intrusionx:intrusionx_dev@localhost:5432/intrusionx",
)

@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"

@pytest_asyncio.fixture(scope="session")
async def engine():
    eng = create_async_engine(DATABASE_URL, echo=False)
    yield eng
    await eng.dispose()

@pytest.fixture(scope="session")
def api_session_factory(engine):
    return async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

@pytest.mark.anyio
async def test_get_workspace_serialization_ip(api_session_factory):
    """
    Test that the workspace API endpoint can correctly serialize PostgreSQL INET values
    returned as ipaddress.IPv4Address by SQLAlchemy, ensuring the Pydantic 500 regression is covered.
    """
    investigation_id = uuid.uuid4()
    evidence_id = uuid.uuid4()

    # 1. Setup Data in a separate session
    async with api_session_factory() as session:
        inv = Investigation(
            id=investigation_id,
            title="Test Investigation",
            description="Testing IP serialization",
            status="OPEN",
            created_by=uuid.UUID("00000000-0000-0000-0000-000000000001")
        )
        session.add(inv)

        evd = Evidence(
            id=evidence_id,
            investigation_id=investigation_id,
            source_type="STRUCTURED_JSON",
            source_identifier="test.json",
            original_content='{"event":"test"}',
            content_hash="dummyhash",
            hash_algorithm="SHA-256",
            is_immutable=True
        )
        session.add(evd)

        # Create an event with IP addresses
        event = NormalizedEvent(
            id=uuid.uuid4(),
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            occurred_at=datetime.now(timezone.utc),
            event_type="NETWORK_CONNECTION",
            event_category="NETWORK",
            source_host="host1",
            source_ip="192.168.1.100",  # SQLAlchemy INET column
            destination_ip="10.0.0.1",   # SQLAlchemy INET column
            destination_port=443
        )
        session.add(event)
        await session.commit()

    # 2. Call the API
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"/api/v1/investigations/{investigation_id}/workspace")

    # 3. Assertions
    assert response.status_code == 200
    data = response.json()
    assert data["investigation"]["id"] == str(investigation_id)
    assert len(data["events"]) == 1
    assert data["events"][0]["source_ip"] == "192.168.1.100"
    assert data["events"][0]["destination_ip"] == "10.0.0.1"

    # 4. Teardown
    async with api_session_factory() as session:
        await session.delete(event)
        await session.delete(evd)
        await session.delete(inv)
        await session.commit()
