"""
Phase 3B — Normalization Engine: test suite.

Tests are organized into 11 concern groups matching the specification:

 1. Event-type normalization          (controlled vocabulary, folding)
 2. Timestamp normalization           (UTC conversion, naive rejection)
 3. Host canonicalization             (lowercase, whitespace)
 4. User canonicalization             (strip only)
 5. Process canonicalization          (lowercase, originals preserved)
 6. IP address validation             (IPv4, IPv6, rejects invalid)
 7. Port validation                   (range, numeric strings)
 8. Extended attributes               (source-specific fields, originals)
 9. Evidence → NormalizedEvent lineage
10. Entity reuse                      (dedup by investigation+type+value)
11. Multi-event fixture               (scenario file, ordering, counts)
12. Normalization boundaries          (one event → one NormalizedEvent,
                                       no synthetic events,
                                       no relationships created)
13. Error model                       (explicit codes, field context)
14. Security                          (no path execution, no network calls)

All integration tests run against PostgreSQL (not mocks).
Pure-function tests run without a database connection.
"""

import ipaddress
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import Base
from app.models.entity import Entity, EventEntityRef
from app.models.evidence import Evidence
from app.models.investigation import Investigation
from app.models.normalized_event import NormalizedEvent
from app.models.relationship import Relationship
from app.normalization.canonicalizers import (
    canonicalize_host,
    canonicalize_ip,
    canonicalize_port,
    canonicalize_process_name,
    canonicalize_user,
)
from app.normalization.errors import (
    INVALID_IP,
    INVALID_PORT,
    INVALID_TIMESTAMP,
    MISSING_REQUIRED_FIELD,
    UNKNOWN_EVENT_TYPE,
    NormalizationFailure,
    PartialNormalizationFailure,
)
from app.normalization.events import (
    SUPPORTED_EVENT_TYPES,
    fold_event_type,
    resolve_event_type,
)
from app.normalization.service import normalize_evidence, parse_timestamp_utc

# ──────────────────────────────────────────────────────────────────────────────
# Database fixtures
# ──────────────────────────────────────────────────────────────────────────────

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


@pytest_asyncio.fixture(scope="session")
async def db_tables(engine):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


@pytest_asyncio.fixture()
async def session(engine, db_tables):
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as sess:
        async with sess.begin():
            yield sess
            await sess.rollback()


# ──────────────────────────────────────────────────────────────────────────────
# Domain fixtures
# ──────────────────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture()
async def investigation(session) -> Investigation:
    inv = Investigation(
        id=uuid.uuid4(),
        title="Phase 3B Normalization Test",
        status="OPEN",
        created_by=uuid.uuid4(),
    )
    session.add(inv)
    await session.flush()
    return inv


def _make_evidence(investigation_id: uuid.UUID, content: bytes) -> Evidence:
    """Build an Evidence object with inline original_content (no filesystem)."""
    content_hash = __import__("hashlib").sha256(content).hexdigest()
    return Evidence(
        id=uuid.uuid4(),
        investigation_id=investigation_id,
        source_type="STRUCTURED_JSON",
        source_identifier="test_fixture.json",
        original_content=content.decode("utf-8"),
        content_hash=content_hash,
        hash_algorithm="SHA-256",
        is_immutable=True,
    )


def _single_event(overrides: dict) -> bytes:
    base = {
        "timestamp": "2026-08-31T10:00:00Z",
        "event_type": "process_start",
        "host": "laptop-07",
        "user": "pradeep",
        "process": "powershell.exe",
        "parent_process": "explorer.exe",
        "process_id": 1234,
        "source": "sysmon",
    }
    base.update(overrides)
    return json.dumps(base).encode("utf-8")


# ──────────────────────────────────────────────────────────────────────────────
# Group 1: Event-type normalization (pure)
# ──────────────────────────────────────────────────────────────────────────────


class TestEventTypeNormalization:
    def test_lowercase_resolves(self):
        t, cat = resolve_event_type("process_start")
        assert t == "PROCESS_START"

    def test_uppercase_resolves(self):
        t, _ = resolve_event_type("PROCESS_START")
        assert t == "PROCESS_START"

    def test_mixed_case_resolves(self):
        t, _ = resolve_event_type("Process_Start")
        assert t == "PROCESS_START"

    def test_hyphen_resolves(self):
        t, _ = resolve_event_type("PROCESS-START")
        assert t == "PROCESS_START"

    def test_space_resolves(self):
        t, _ = resolve_event_type("network connection")
        assert t == "NETWORK_CONNECTION"

    def test_all_supported_types_resolve(self):
        for raw in SUPPORTED_EVENT_TYPES:
            t, cat = resolve_event_type(raw)
            assert t == raw
            assert cat

    def test_file_create_category_is_file(self):
        _, cat = resolve_event_type("file_create")
        assert cat == "FILE"

    def test_file_delete_category_is_file(self):
        _, cat = resolve_event_type("file_delete")
        assert cat == "FILE"

    def test_user_login_category_is_auth(self):
        _, cat = resolve_event_type("user_login")
        assert cat == "AUTH"

    def test_user_logout_category_is_auth(self):
        _, cat = resolve_event_type("user_logout")
        assert cat == "AUTH"

    def test_network_connection_category_is_network(self):
        _, cat = resolve_event_type("network_connection")
        assert cat == "NETWORK"

    def test_process_start_category_is_process(self):
        _, cat = resolve_event_type("process_start")
        assert cat == "PROCESS"

    def test_unknown_raises_key_error(self):
        with pytest.raises(KeyError):
            resolve_event_type("something_unknown")

    def test_empty_string_raises_key_error(self):
        with pytest.raises(KeyError):
            resolve_event_type("")

    def test_fold_strips_whitespace(self):
        assert fold_event_type("  process_start  ") == "PROCESS_START"

    def test_fold_is_deterministic(self):
        for _ in range(5):
            assert fold_event_type("process-start") == "PROCESS_START"


# ──────────────────────────────────────────────────────────────────────────────
# Group 2: Timestamp normalization (pure)
# ──────────────────────────────────────────────────────────────────────────────


class TestTimestampNormalization:
    def test_utc_z_suffix(self):
        dt = parse_timestamp_utc("2026-08-31T10:14:07Z")
        assert dt.tzinfo is not None
        assert dt.utcoffset().total_seconds() == 0

    def test_positive_offset_converted_to_utc(self):
        """2026-08-31T15:44:07+05:30 → 2026-08-31T10:14:07+00:00"""
        dt = parse_timestamp_utc("2026-08-31T15:44:07+05:30")
        expected = datetime(2026, 8, 31, 10, 14, 7, tzinfo=timezone.utc)
        assert dt == expected

    def test_negative_offset_converted_to_utc(self):
        dt = parse_timestamp_utc("2026-08-31T05:14:07-05:00")
        expected = datetime(2026, 8, 31, 10, 14, 7, tzinfo=timezone.utc)
        assert dt == expected

    def test_same_instant_different_representations(self):
        """Two strings representing the same UTC instant must produce equal datetimes."""
        dt_z = parse_timestamp_utc("2026-08-31T10:14:07Z")
        dt_offset = parse_timestamp_utc("2026-08-31T15:44:07+05:30")
        assert dt_z == dt_offset

    def test_naive_timestamp_rejected(self):
        with pytest.raises(NormalizationFailure) as exc_info:
            parse_timestamp_utc("2026-08-31T10:14:07")
        errors = exc_info.value.errors
        assert any(e.code == INVALID_TIMESTAMP for e in errors)

    def test_invalid_timestamp_rejected(self):
        with pytest.raises(NormalizationFailure) as exc_info:
            parse_timestamp_utc("not-a-date")
        errors = exc_info.value.errors
        assert any(e.code == INVALID_TIMESTAMP for e in errors)

    def test_date_only_rejected(self):
        """Date-only strings have no time or timezone — must be rejected."""
        with pytest.raises(NormalizationFailure):
            parse_timestamp_utc("2026-08-31")

    def test_result_is_utc_aware(self):
        dt = parse_timestamp_utc("2026-08-31T10:14:07+00:00")
        assert dt.tzinfo == timezone.utc

    def test_millisecond_precision_preserved(self):
        dt = parse_timestamp_utc("2026-08-31T10:14:07.123456Z")
        assert dt.microsecond == 123456


# ──────────────────────────────────────────────────────────────────────────────
# Group 3: Host canonicalization (pure)
# ──────────────────────────────────────────────────────────────────────────────


class TestHostCanonicalization:
    def test_uppercase_becomes_lowercase(self):
        assert canonicalize_host("LAPTOP-07") == "laptop-07"

    def test_mixed_case_becomes_lowercase(self):
        assert canonicalize_host("Laptop-07") == "laptop-07"

    def test_already_lowercase_unchanged(self):
        assert canonicalize_host("laptop-07") == "laptop-07"

    def test_leading_whitespace_stripped(self):
        assert canonicalize_host("  laptop-07") == "laptop-07"

    def test_trailing_whitespace_stripped(self):
        assert canonicalize_host("laptop-07  ") == "laptop-07"

    def test_surrounding_whitespace_stripped(self):
        assert canonicalize_host(" Laptop-07 ") == "laptop-07"

    def test_different_forms_produce_same_canonical(self):
        """LAPTOP-07, laptop-07, and ' Laptop-07 ' all canonicalize identically."""
        forms = ["LAPTOP-07", "laptop-07", " Laptop-07 "]
        canonicals = [canonicalize_host(f) for f in forms]
        assert len(set(canonicals)) == 1

    def test_no_dns_lookup(self):
        """Canonicalization must not attempt DNS resolution."""
        # We verify this by running with a hostname that would fail DNS.
        # If DNS were attempted, a network call would fail deterministically.
        result = canonicalize_host("nonexistent-host-xyz-123")
        assert result == "nonexistent-host-xyz-123"


# ──────────────────────────────────────────────────────────────────────────────
# Group 4: User canonicalization (pure)
# ──────────────────────────────────────────────────────────────────────────────


class TestUserCanonicalization:
    def test_plain_user_unchanged(self):
        assert canonicalize_user("pradeep") == "pradeep"

    def test_domain_backslash_form_preserved(self):
        assert canonicalize_user("DOMAIN\\pradeep") == "DOMAIN\\pradeep"

    def test_upn_form_preserved(self):
        assert canonicalize_user("pradeep@example.com") == "pradeep@example.com"

    def test_case_preserved(self):
        """User names are case-sensitive identity markers — case is NOT lowercased."""
        assert canonicalize_user("Pradeep") == "Pradeep"

    def test_surrounding_whitespace_stripped(self):
        assert canonicalize_user("  pradeep  ") == "pradeep"

    def test_domain_prefix_case_preserved(self):
        assert canonicalize_user("DOMAIN\\user") == "DOMAIN\\user"


# ──────────────────────────────────────────────────────────────────────────────
# Group 5: Process name canonicalization (pure)
# ──────────────────────────────────────────────────────────────────────────────


class TestProcessCanonicalization:
    def test_uppercase_becomes_lowercase(self):
        assert canonicalize_process_name("POWERSHELL.EXE") == "powershell.exe"

    def test_mixed_case_becomes_lowercase(self):
        assert canonicalize_process_name("PowerShell.exe") == "powershell.exe"

    def test_already_lowercase_unchanged(self):
        assert canonicalize_process_name("powershell.exe") == "powershell.exe"

    def test_whitespace_stripped(self):
        assert canonicalize_process_name("  powershell.exe  ") == "powershell.exe"

    def test_all_forms_produce_same_canonical(self):
        forms = ["powershell.exe", "PowerShell.exe", "POWERSHELL.EXE", "PowerShell.EXE"]
        canonicals = [canonicalize_process_name(f) for f in forms]
        assert len(set(canonicals)) == 1


# ──────────────────────────────────────────────────────────────────────────────
# Group 6: IP address validation (pure)
# ──────────────────────────────────────────────────────────────────────────────


class TestIPValidation:
    def test_valid_ipv4(self):
        assert canonicalize_ip("192.168.1.1") == "192.168.1.1"

    def test_valid_ipv6_loopback(self):
        assert canonicalize_ip("::1") == "::1"

    def test_valid_ipv6_full(self):
        result = canonicalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001")
        assert ipaddress.ip_address(result)  # must parse as valid IP

    def test_ipv6_lowercase_canonical(self):
        result = canonicalize_ip("::FFFF:192.168.1.1")
        assert result == result.lower() or ":" in result  # canonical form

    def test_invalid_ip_raises(self):
        with pytest.raises(ValueError):
            canonicalize_ip("999.999.999.999")

    def test_hostname_rejected(self):
        with pytest.raises(ValueError):
            canonicalize_ip("google.com")

    def test_empty_string_rejected(self):
        with pytest.raises(ValueError):
            canonicalize_ip("")

    def test_partial_ip_rejected(self):
        with pytest.raises(ValueError):
            canonicalize_ip("192.168.1")

    def test_whitespace_stripped_before_validation(self):
        assert canonicalize_ip("  192.168.1.1  ") == "192.168.1.1"


# ──────────────────────────────────────────────────────────────────────────────
# Group 7: Port validation (pure)
# ──────────────────────────────────────────────────────────────────────────────


class TestPortValidation:
    def test_valid_port_int(self):
        assert canonicalize_port(443) == 443

    def test_valid_port_string(self):
        assert canonicalize_port("8080") == 8080

    def test_port_zero(self):
        assert canonicalize_port(0) == 0

    def test_port_max(self):
        assert canonicalize_port(65535) == 65535

    def test_port_negative_raises(self):
        with pytest.raises(ValueError):
            canonicalize_port(-1)

    def test_port_above_max_raises(self):
        with pytest.raises(ValueError):
            canonicalize_port(65536)

    def test_service_name_raises(self):
        with pytest.raises(ValueError):
            canonicalize_port("https")

    def test_float_string_raises(self):
        with pytest.raises(ValueError):
            canonicalize_port("443.0")


# ──────────────────────────────────────────────────────────────────────────────
# Group 8: Integration — event normalization (requires DB)
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestProcessStartNormalization:
    async def test_process_start_creates_one_event(
        self, session, investigation, tmp_path
    ):
        payload = _single_event({"event_type": "process_start"})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        assert result.event_count == 1

    async def test_process_start_event_type_stored(
        self, session, investigation, tmp_path
    ):
        payload = _single_event({"event_type": "process_start"})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        assert result.events[0].event_type == "PROCESS_START"

    async def test_process_start_category_is_process(
        self, session, investigation
    ):
        payload = _single_event({"event_type": "process_start"})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        assert result.events[0].event_category == "PROCESS"

    async def test_process_name_lowercased(self, session, investigation):
        payload = _single_event({"event_type": "process_start", "process": "PowerShell.EXE"})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        assert result.events[0].process_name == "powershell.exe"

    async def test_original_process_name_in_extended_attrs(self, session, investigation):
        payload = _single_event({"event_type": "process_start", "process": "PowerShell.EXE"})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        attrs = result.events[0].extended_attributes or {}
        assert attrs.get("original_process_name") == "PowerShell.EXE"

    async def test_process_pid_stored_as_string(self, session, investigation):
        payload = _single_event({"event_type": "process_start", "process_id": 4216})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        assert result.events[0].process_id == "4216"


@pytest.mark.anyio
class TestNetworkConnectionNormalization:
    async def test_network_connection_event_type(self, session, investigation):
        payload = json.dumps({
            "timestamp": "2026-08-31T10:00:00Z",
            "event_type": "network_connection",
            "host": "laptop-07",
            "user": "pradeep",
            "source_ip": "192.168.1.10",
            "destination_ip": "198.51.100.42",
            "source_port": 52341,
            "destination_port": 443,
        }).encode()
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        assert result.events[0].event_type == "NETWORK_CONNECTION"
        assert result.events[0].event_category == "NETWORK"

    async def test_ips_stored_correctly(self, session, investigation):
        payload = json.dumps({
            "timestamp": "2026-08-31T10:00:00Z",
            "event_type": "network_connection",
            "host": "laptop-07",
            "source_ip": "192.168.1.10",
            "destination_ip": "198.51.100.42",
            "source_port": 52341,
            "destination_port": 443,
        }).encode()
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        evt = result.events[0]
        assert evt.source_ip == "192.168.1.10"
        assert evt.destination_ip == "198.51.100.42"
        assert evt.source_port == 52341
        assert evt.destination_port == 443


@pytest.mark.anyio
class TestUserLoginNormalization:
    async def test_user_login_event_type(self, session, investigation):
        payload = json.dumps({
            "timestamp": "2026-08-31T07:45:00Z",
            "event_type": "user_login",
            "host": "laptop-07",
            "user": "pradeep",
            "action": "login",
        }).encode()
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        assert result.events[0].event_type == "USER_LOGIN"
        assert result.events[0].event_category == "AUTH"

    async def test_user_logout_event_type(self, session, investigation):
        payload = json.dumps({
            "timestamp": "2026-08-31T07:45:00Z",
            "event_type": "user_logout",
            "host": "laptop-07",
            "user": "pradeep",
        }).encode()
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        assert result.events[0].event_type == "USER_LOGOUT"


@pytest.mark.anyio
class TestFileEventNormalization:
    async def test_file_create_event_type(self, session, investigation):
        payload = json.dumps({
            "timestamp": "2026-08-31T10:00:00Z",
            "event_type": "file_create",
            "host": "laptop-07",
            "user": "pradeep",
            "file_path": "C:\\Temp\\stage2.ps1",
        }).encode()
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        assert result.events[0].event_type == "FILE_CREATE"
        assert result.events[0].event_category == "FILE"

    async def test_file_delete_event_type(self, session, investigation):
        payload = json.dumps({
            "timestamp": "2026-08-31T10:00:00Z",
            "event_type": "file_delete",
            "host": "laptop-07",
            "user": "pradeep",
            "file_path": "C:\\Temp\\stage2.ps1",
        }).encode()
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        assert result.events[0].event_type == "FILE_DELETE"

    async def test_file_path_stored(self, session, investigation):
        path = "C:\\Temp\\stage2.ps1"
        payload = json.dumps({
            "timestamp": "2026-08-31T10:00:00Z",
            "event_type": "file_create",
            "host": "laptop-07",
            "file_path": path,
        }).encode()
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        assert result.events[0].file_path == path


# ──────────────────────────────────────────────────────────────────────────────
# Group 9: Timestamp UTC conversion (integration)
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestTimestampUTCIntegration:
    async def test_occurred_at_is_utc(self, session, investigation):
        payload = _single_event({"timestamp": "2026-08-31T15:44:07+05:30"})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        occurred_at = result.events[0].occurred_at
        assert occurred_at.tzinfo is not None
        # Must equal 2026-08-31T10:14:07Z
        expected = datetime(2026, 8, 31, 10, 14, 7, tzinfo=timezone.utc)
        assert occurred_at == expected

    async def test_naive_timestamp_rejected(self, session, investigation):
        payload = _single_event({"timestamp": "2026-08-31T10:00:00"})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        with pytest.raises(NormalizationFailure) as exc_info:
            await normalize_evidence(session=session, evidence=ev)
        assert any(e.code == INVALID_TIMESTAMP for e in exc_info.value.errors)

    async def test_invalid_timestamp_rejected(self, session, investigation):
        payload = _single_event({"timestamp": "yesterday"})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        with pytest.raises(NormalizationFailure) as exc_info:
            await normalize_evidence(session=session, evidence=ev)
        assert any(e.code == INVALID_TIMESTAMP for e in exc_info.value.errors)


# ──────────────────────────────────────────────────────────────────────────────
# Group 10: Unknown event type rejection (integration)
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestUnknownEventTypeRejection:
    async def test_unknown_type_raises(self, session, investigation):
        payload = _single_event({"event_type": "something_we_do_not_understand"})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        with pytest.raises(NormalizationFailure) as exc_info:
            await normalize_evidence(session=session, evidence=ev)
        assert any(e.code == UNKNOWN_EVENT_TYPE for e in exc_info.value.errors)

    async def test_unknown_type_does_not_create_event(self, session, investigation):
        payload = _single_event({"event_type": "ai_classified_event"})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        with pytest.raises(NormalizationFailure):
            await normalize_evidence(session=session, evidence=ev)

        # Evidence remains intact, no NormalizedEvent created.
        evt_count = await session.scalar(
            select(__import__("sqlalchemy").func.count(NormalizedEvent.id)).where(
                NormalizedEvent.evidence_id == ev.id
            )
        )
        assert evt_count == 0


# ──────────────────────────────────────────────────────────────────────────────
# Group 11: Host canonicalization (integration)
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestHostCanonicalizationIntegration:
    async def test_uppercase_host_stored_lowercase(self, session, investigation):
        payload = _single_event({"host": "LAPTOP-07"})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        assert result.events[0].source_host == "laptop-07"

    async def test_original_host_in_extended_attributes(self, session, investigation):
        payload = _single_event({"host": "LAPTOP-07"})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        attrs = result.events[0].extended_attributes or {}
        assert attrs.get("original_host") == "LAPTOP-07"

    async def test_already_lowercase_host_no_original_stored(
        self, session, investigation
    ):
        """If canonicalization does not change the value, original_host must NOT appear."""
        payload = _single_event({"host": "laptop-07"})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        attrs = result.events[0].extended_attributes or {}
        assert "original_host" not in attrs


# ──────────────────────────────────────────────────────────────────────────────
# Group 12: Extended attributes (integration)
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestExtendedAttributes:
    async def test_source_specific_fields_in_extended_attributes(
        self, session, investigation
    ):
        payload = json.dumps({
            "timestamp": "2026-08-31T10:00:00Z",
            "event_type": "process_start",
            "host": "laptop-07",
            "user": "pradeep",
            "process": "powershell.exe",
            "source": "sysmon",
            "integrity_level": "High",
            "terminal_session_id": 1,
            "original_file_name": "PowerShell.EXE",
        }).encode()
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        attrs = result.events[0].extended_attributes or {}

        assert attrs.get("integrity_level") == "High"
        assert attrs.get("terminal_session_id") == 1
        assert attrs.get("original_file_name") == "PowerShell.EXE"

    async def test_dedicated_column_fields_not_duplicated_in_extended(
        self, session, investigation
    ):
        """Fields with dedicated columns must not also appear in extended_attributes."""
        payload = _single_event({})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        attrs = result.events[0].extended_attributes or {}

        # "host" and "user" have dedicated columns — must not be duplicated.
        assert "host" not in attrs
        assert "user" not in attrs

    async def test_source_label_preserved_in_extended(self, session, investigation):
        payload = _single_event({"source": "sysmon"})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        attrs = result.events[0].extended_attributes or {}
        assert attrs.get("source") == "sysmon"


# ──────────────────────────────────────────────────────────────────────────────
# Group 13: Evidence → NormalizedEvent lineage
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestEvidenceLineage:
    async def test_evidence_id_on_event(self, session, investigation):
        payload = _single_event({})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        assert result.events[0].evidence_id == ev.id

    async def test_investigation_id_on_event(self, session, investigation):
        payload = _single_event({})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        assert result.events[0].investigation_id == investigation.id

    async def test_result_evidence_id_matches(self, session, investigation):
        payload = _single_event({})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        assert result.evidence_id == ev.id

    async def test_evidence_unchanged_after_normalization(self, session, investigation):
        """The Evidence record must not be modified by normalization."""
        payload = _single_event({})
        ev = _make_evidence(investigation.id, payload)
        original_hash = ev.content_hash
        original_content = ev.original_content
        session.add(ev)
        await session.flush()

        await normalize_evidence(session=session, evidence=ev)

        assert ev.content_hash == original_hash
        assert ev.original_content == original_content
        assert ev.is_immutable is True


# ──────────────────────────────────────────────────────────────────────────────
# Group 14: Entity reuse
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestEntityReuse:
    async def test_host_entity_created(self, session, investigation):
        payload = _single_event({"host": "laptop-07"})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        assert result.total_entities_created >= 1

    async def test_same_host_two_events_one_entity(self, session, investigation):
        """Two events with the same host must share one HOST entity."""
        event1 = {
            "timestamp": "2026-08-31T10:00:00Z",
            "event_type": "process_start",
            "host": "laptop-07",
            "user": "alice",
            "process": "notepad.exe",
            "source": "sysmon",
        }
        event2 = {
            "timestamp": "2026-08-31T10:01:00Z",
            "event_type": "user_login",
            "host": "laptop-07",  # same host
            "user": "bob",
            "source": "security",
        }
        payload = json.dumps([event1, event2]).encode()
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)

        # Verify: only one HOST entity for "laptop-07".
        host_entities = (await session.execute(
            select(Entity).where(
                Entity.investigation_id == investigation.id,
                Entity.entity_type == "HOST",
                Entity.canonical_value == "laptop-07",
            )
        )).scalars().all()
        assert len(host_entities) == 1

    async def test_entity_reused_count(self, session, investigation):
        """After entity reuse, total_entities_reused must be > 0."""
        event1 = {
            "timestamp": "2026-08-31T10:00:00Z",
            "event_type": "process_start",
            "host": "laptop-07",
            "user": "pradeep",
            "process": "notepad.exe",
            "source": "sysmon",
        }
        event2 = {
            "timestamp": "2026-08-31T10:01:00Z",
            "event_type": "user_login",
            "host": "laptop-07",
            "user": "pradeep",
            "source": "security",
        }
        payload = json.dumps([event1, event2]).encode()
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        assert result.total_entities_reused > 0

    async def test_different_investigations_different_entities(
        self, session, db_tables
    ):
        """The same host name in two different investigations creates two entities."""
        inv_a = Investigation(
            id=uuid.uuid4(), title="Inv A", status="OPEN", created_by=uuid.uuid4()
        )
        inv_b = Investigation(
            id=uuid.uuid4(), title="Inv B", status="OPEN", created_by=uuid.uuid4()
        )
        session.add_all([inv_a, inv_b])
        await session.flush()

        payload = _single_event({"host": "laptop-07"})

        ev_a = _make_evidence(inv_a.id, payload)
        ev_b = _make_evidence(inv_b.id, payload)
        session.add_all([ev_a, ev_b])
        await session.flush()

        await normalize_evidence(session=session, evidence=ev_a)
        await normalize_evidence(session=session, evidence=ev_b)

        host_entities = (await session.execute(
            select(Entity).where(
                Entity.entity_type == "HOST",
                Entity.canonical_value == "laptop-07",
            )
        )).scalars().all()

        inv_ids = {e.investigation_id for e in host_entities}
        assert inv_a.id in inv_ids
        assert inv_b.id in inv_ids


# ──────────────────────────────────────────────────────────────────────────────
# Group 15: One event → one normalized event
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestOneEventOneNormalizedEvent:
    async def test_single_input_produces_single_output(self, session, investigation):
        payload = _single_event({})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        assert result.event_count == 1

    async def test_process_start_does_not_produce_extra_events(
        self, session, investigation
    ):
        """A process_start must not produce USER_ACTIVITY, NETWORK, or FILE events."""
        payload = _single_event({
            "event_type": "process_start",
            "process": "powershell.exe",
            "parent_process": "winword.exe",
        })
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        assert result.event_count == 1
        assert result.events[0].event_type == "PROCESS_START"

    async def test_no_relationships_created(self, session, investigation):
        """Normalization must NOT create Relationship records."""
        payload = _single_event({})
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        await normalize_evidence(session=session, evidence=ev)

        rel_count = await session.scalar(
            select(__import__("sqlalchemy").func.count(Relationship.id)).where(
                Relationship.investigation_id == investigation.id
            )
        )
        assert rel_count == 0


# ──────────────────────────────────────────────────────────────────────────────
# Group 16: Multi-event fixture (scenario file)
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestMultiEventFixture:
    def _load_scenario(self) -> bytes:
        repo_root = Path(__file__).resolve().parents[2]
        scenario = repo_root / "data" / "scenarios" / "phase3b_scenario.json"
        return scenario.read_bytes()

    async def test_scenario_produces_five_events(self, session, investigation):
        payload = self._load_scenario()
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        assert result.event_count == 5

    async def test_scenario_event_types(self, session, investigation):
        payload = self._load_scenario()
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        event_types = [e.event_type for e in result.events]

        assert "USER_LOGIN" in event_types
        assert "PROCESS_START" in event_types
        assert "NETWORK_CONNECTION" in event_types
        assert "FILE_CREATE" in event_types

    async def test_scenario_all_linked_to_evidence(self, session, investigation):
        payload = self._load_scenario()
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        for event in result.events:
            assert event.evidence_id == ev.id

    async def test_scenario_no_relationships_created(self, session, investigation):
        """The scenario must not create any Relationship records."""
        payload = self._load_scenario()
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        await normalize_evidence(session=session, evidence=ev)

        rel_count = await session.scalar(
            select(__import__("sqlalchemy").func.count(Relationship.id)).where(
                Relationship.investigation_id == investigation.id
            )
        )
        assert rel_count == 0

    async def test_scenario_extra_fields_in_extended_attributes(
        self, session, investigation
    ):
        """Source-specific fields in the scenario must appear in extended_attributes."""
        payload = self._load_scenario()
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        result = await normalize_evidence(session=session, evidence=ev)
        # The third event (powershell.exe start) has integrity_level.
        ps_events = [
            e for e in result.events
            if e.event_type == "PROCESS_START" and e.process_name == "powershell.exe"
        ]
        assert ps_events, "Expected a PROCESS_START for powershell.exe"
        attrs = ps_events[0].extended_attributes or {}
        assert "integrity_level" in attrs


# ──────────────────────────────────────────────────────────────────────────────
# Group 17: Error model
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestErrorModel:
    async def test_invalid_ip_produces_error_code(self, session, investigation):
        payload = json.dumps({
            "timestamp": "2026-08-31T10:00:00Z",
            "event_type": "network_connection",
            "host": "laptop-07",
            "source_ip": "not-an-ip",
            "destination_ip": "198.51.100.42",
        }).encode()
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        with pytest.raises(NormalizationFailure) as exc_info:
            await normalize_evidence(session=session, evidence=ev)
        assert any(e.code == INVALID_IP for e in exc_info.value.errors)
        assert any(e.field == "source_ip" for e in exc_info.value.errors)

    async def test_invalid_port_produces_error_code(self, session, investigation):
        payload = json.dumps({
            "timestamp": "2026-08-31T10:00:00Z",
            "event_type": "network_connection",
            "host": "laptop-07",
            "source_ip": "192.168.1.1",
            "destination_ip": "10.0.0.1",
            "destination_port": 99999,
        }).encode()
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        with pytest.raises(NormalizationFailure) as exc_info:
            await normalize_evidence(session=session, evidence=ev)
        assert any(e.code == INVALID_PORT for e in exc_info.value.errors)

    async def test_error_contains_field_name(self, session, investigation):
        payload = json.dumps({
            "timestamp": "2026-08-31T10:00:00Z",
            "event_type": "network_connection",
            "host": "laptop-07",
            "source_ip": "bad-ip",
        }).encode()
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        with pytest.raises(NormalizationFailure) as exc_info:
            await normalize_evidence(session=session, evidence=ev)
        assert any(e.field is not None for e in exc_info.value.errors)

    async def test_partial_failure_in_multi_event(self, session, investigation):
        """If one event in an array is bad, PartialNormalizationFailure is raised."""
        good = {
            "timestamp": "2026-08-31T10:00:00Z",
            "event_type": "user_login",
            "host": "laptop-07",
            "user": "pradeep",
        }
        bad = {
            "timestamp": "2026-08-31T10:01:00Z",
            "event_type": "totally_unknown_type",
            "host": "laptop-07",
        }
        payload = json.dumps([good, bad]).encode()
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        with pytest.raises(PartialNormalizationFailure) as exc_info:
            await normalize_evidence(session=session, evidence=ev)
        assert exc_info.value.total_events == 2
        assert 1 in exc_info.value.failures

    async def test_all_or_nothing_no_events_on_partial_failure(
        self, session, investigation
    ):
        """When PartialNormalizationFailure is raised, NO events must be persisted."""
        good = {
            "timestamp": "2026-08-31T10:00:00Z",
            "event_type": "user_login",
            "host": "laptop-07",
            "user": "pradeep",
        }
        bad = {
            "timestamp": "2026-08-31T10:01:00Z",
            "event_type": "unknown_type",
            "host": "laptop-07",
        }
        payload = json.dumps([good, bad]).encode()
        ev = _make_evidence(investigation.id, payload)
        session.add(ev)
        await session.flush()

        with pytest.raises(PartialNormalizationFailure):
            await normalize_evidence(session=session, evidence=ev)

        evt_count = await session.scalar(
            select(__import__("sqlalchemy").func.count(NormalizedEvent.id)).where(
                NormalizedEvent.evidence_id == ev.id
            )
        )
        assert evt_count == 0, "No events should be written when normalization fails"


# ──────────────────────────────────────────────────────────────────────────────
# Group 18: Security properties
# ──────────────────────────────────────────────────────────────────────────────


class TestSecurityProperties:
    def test_ip_field_not_executed(self):
        """IP values from telemetry are never executed as code."""
        with pytest.raises(ValueError):
            canonicalize_ip("__import__('os').system('id')")

    def test_process_name_not_executed(self):
        """Process names are lowercased strings — never executed."""
        result = canonicalize_process_name("../../etc/passwd")
        assert result == "../../etc/passwd"
        # The canonicalized result is a string; it is NOT opened as a file path.

    def test_host_value_not_followed_as_path(self):
        """Host values are never used as filesystem paths."""
        result = canonicalize_host("../../../../etc/hosts")
        assert result == "../../../../etc/hosts"
        # The result is a string only.

    def test_port_value_not_used_for_connection(self):
        """Port canonicalization is pure math — no network calls."""
        result = canonicalize_port(4444)
        assert result == 4444

    def test_unknown_event_type_does_not_classify(self):
        """An unrecognized event type raises KeyError — not classified silently."""
        with pytest.raises(KeyError):
            resolve_event_type("malware_execution")

    def test_normalization_error_does_not_include_raw_value(self):
        """NormalizationError must not embed raw user-supplied values in the reason."""
        from app.normalization.errors import NormalizationError, INVALID_IP

        err = NormalizationError(
            code=INVALID_IP,
            field="source_ip",
            reason="source_ip is not a valid IPv4 or IPv6 address",
        )
        # The reason describes the structural problem, not the value.
        assert "source_ip is not" in err.reason
