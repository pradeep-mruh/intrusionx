"""
Health endpoint smoke test.

Verifies that the /health endpoint returns HTTP 200 with the expected
response shape.  The database status is not checked here because this test
does not require a running PostgreSQL instance.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
async def test_health_returns_200() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/health")

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_health_response_shape() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/health")

    body = response.json()
    assert "status" in body
    assert "database" in body
    assert "version" in body
    assert body["status"] == "ok"
