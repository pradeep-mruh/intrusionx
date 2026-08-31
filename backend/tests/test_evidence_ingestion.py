"""
Phase 3A — Evidence Ingestion Core: test suite.

Tests are organized into five concern groups:

1. SHA-256 integrity
   - Hash is computed from the exact original bytes.
   - Changing one byte produces a different hash.
   - Stored file bytes are byte-for-byte identical to the input.

2. Filesystem storage
   - File is written inside data/raw/ (or the test-supplied temp dir).
   - Absolute storage path never escapes the storage root.
   - Stored bytes are byte-for-byte identical to the original input.

3. Duplicate handling
   - Re-submitting identical bytes to the same investigation returns
     the existing Evidence record (is_duplicate=True).
   - No second file is written.
   - Re-submitting to a DIFFERENT investigation creates a new record.

4. Input validation
   - EmptyEvidenceError on empty bytes.
   - EvidenceTooLargeError on oversized payload.
   - InvalidEncodingError on non-UTF-8 bytes.
   - InvalidJSONError on valid UTF-8 that is not JSON.
   - UnsafeFilenameError on source identifiers with path traversal chars.

5. Partial-failure safety
   - Orphaned file is cleaned up if the database flush fails.
"""

import hashlib
import json
import os
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import Base
from app.ingestion.service import (
    HASH_ALGORITHM,
    MAX_EVIDENCE_BYTES,
    SOURCE_TYPE_JSON,
    EmptyEvidenceError,
    EvidenceTooLargeError,
    IngestionResult,
    InvalidEncodingError,
    InvalidJSONError,
    StorageError,
    UnsafeFilenameError,
    compute_sha256,
    ingest_evidence,
    validate_raw_bytes,
    validate_source_identifier,
)
from app.models.evidence import Evidence
from app.models.investigation import Investigation

# ──────────────────────────────────────────────────────────────────────────────
# Database fixtures (async, PostgreSQL)
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
    """Create all tables once per session."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    # Teardown: drop evidence rows but keep schema for other test modules.


@pytest_asyncio.fixture()
async def session(engine, db_tables):
    """Yield a per-test async session that rolls back after each test."""
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as sess:
        async with sess.begin():
            yield sess
            await sess.rollback()


@pytest_asyncio.fixture()
async def investigation(session) -> Investigation:
    """Insert a minimal Investigation for use in ingestion tests."""
    inv = Investigation(
        id=uuid.uuid4(),
        title="Phase 3A Ingestion Test Investigation",
        status="OPEN",
        created_by=uuid.uuid4(),
    )
    session.add(inv)
    await session.flush()
    return inv


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

_SAMPLE_EVENT: dict = {
    "timestamp": "2025-01-01T00:00:00Z",
    "source_ip": "192.168.1.10",
    "destination_ip": "10.0.0.1",
    "event_type": "network_connection",
    "pid": 1234,
    "process_name": "curl",
}


def sample_bytes() -> bytes:
    """Return stable JSON bytes for the sample event."""
    return json.dumps(_SAMPLE_EVENT, separators=(",", ":")).encode("utf-8")


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ──────────────────────────────────────────────────────────────────────────────
# Group 1: SHA-256 integrity (pure, no DB required)
# ──────────────────────────────────────────────────────────────────────────────


class TestComputeSha256:
    def test_known_value(self):
        """
        compute_sha256 must return the same digest as stdlib hashlib.sha256.

        We derive the reference at test-run time so the test remains correct
        regardless of the host Python's FIPS mode or OpenSSL variant.
        """
        reference = hashlib.sha256(b"abc").hexdigest()
        assert compute_sha256(b"abc") == reference

    def test_deterministic(self):
        """Same input always produces the same hash."""
        data = sample_bytes()
        assert compute_sha256(data) == compute_sha256(data)

    def test_different_bytes_different_hash(self):
        """Flipping one byte must produce a different hash."""
        data = sample_bytes()
        corrupted = bytearray(data)
        corrupted[0] ^= 0xFF
        assert compute_sha256(data) != compute_sha256(bytes(corrupted))

    def test_hash_algorithm_constant(self):
        assert HASH_ALGORITHM == "SHA-256"

    def test_output_is_lowercase_hex(self):
        digest = compute_sha256(sample_bytes())
        assert digest == digest.lower()
        assert all(c in "0123456789abcdef" for c in digest)
        assert len(digest) == 64


# ──────────────────────────────────────────────────────────────────────────────
# Group 2: Input validation (pure, no DB required)
# ──────────────────────────────────────────────────────────────────────────────


class TestValidateRawBytes:
    def test_valid_payload_does_not_raise(self):
        validate_raw_bytes(sample_bytes())

    def test_empty_raises(self):
        with pytest.raises(EmptyEvidenceError):
            validate_raw_bytes(b"")

    def test_too_large_raises(self):
        oversized = b"x" * (MAX_EVIDENCE_BYTES + 1)
        with pytest.raises(EvidenceTooLargeError):
            validate_raw_bytes(oversized)

    def test_exactly_max_size_is_accepted(self):
        # Build a JSON string whose total encoded length equals MAX_EVIDENCE_BYTES.
        # Template: {"k":"<padding>"}
        # Overhead byte count: { " k " : " <padding> " }  →  8 bytes
        #   { = 1, "k" = 3, : = 1, " = 1 (open), " = 1 (close), } = 1  → 8
        overhead = len(b'{"k":""}')
        padding_len = MAX_EVIDENCE_BYTES - overhead
        payload = ('{"k":"' + "a" * padding_len + '"}').encode("utf-8")
        assert len(payload) == MAX_EVIDENCE_BYTES
        validate_raw_bytes(payload)  # must not raise

    def test_invalid_utf8_raises(self):
        with pytest.raises(InvalidEncodingError):
            validate_raw_bytes(b"\xff\xfe not utf-8")

    def test_valid_utf8_but_not_json_raises(self):
        with pytest.raises(InvalidJSONError):
            validate_raw_bytes("this is not json".encode("utf-8"))

    def test_json_array_is_accepted(self):
        """Arrays are valid JSON and should be accepted."""
        validate_raw_bytes(b'[{"a":1},{"b":2}]')

    def test_json_number_is_accepted(self):
        """A bare JSON number is valid JSON."""
        validate_raw_bytes(b"42")


class TestValidateSourceIdentifier:
    def test_safe_identifier_does_not_raise(self):
        validate_source_identifier("auth.log.2025-01-01")

    def test_empty_raises(self):
        with pytest.raises(UnsafeFilenameError):
            validate_source_identifier("")

    def test_null_byte_raises(self):
        with pytest.raises(UnsafeFilenameError):
            validate_source_identifier("safe\x00unsafe")

    def test_forward_slash_raises(self):
        with pytest.raises(UnsafeFilenameError):
            validate_source_identifier("../../etc/passwd")

    def test_backslash_raises(self):
        with pytest.raises(UnsafeFilenameError):
            validate_source_identifier("..\\Windows\\System32")

    def test_double_dot_raises(self):
        with pytest.raises(UnsafeFilenameError):
            validate_source_identifier("..")

    def test_dotfile_without_traversal_is_safe(self):
        """A dotfile name with no path separator is fine."""
        validate_source_identifier(".bashrc_export")


# ──────────────────────────────────────────────────────────────────────────────
# Group 3: Filesystem storage (integration, DB required)
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestFilesystemStorage:
    async def test_file_is_written(self, session, investigation, tmp_path):
        """Ingestion must write exactly one file inside storage_root."""
        data = sample_bytes()

        result = await ingest_evidence(
            session=session,
            investigation_id=investigation.id,
            raw_bytes=data,
            source_identifier="auth.log",
            storage_root=tmp_path,
        )

        written = list(tmp_path.iterdir())
        assert len(written) == 1, f"Expected exactly one file, got: {written}"

    async def test_stored_bytes_are_identical(self, session, investigation, tmp_path):
        """The stored file must be byte-for-byte identical to the original input."""
        data = sample_bytes()

        await ingest_evidence(
            session=session,
            investigation_id=investigation.id,
            raw_bytes=data,
            source_identifier="auth.log",
            storage_root=tmp_path,
        )

        files = list(tmp_path.iterdir())
        assert files, "No file was written"
        stored = files[0].read_bytes()
        assert stored == data, "Stored bytes differ from the original input"

    async def test_stored_file_hash_matches_db_hash(
        self, session, investigation, tmp_path
    ):
        """The SHA-256 of the stored file must match Evidence.content_hash."""
        data = sample_bytes()

        result = await ingest_evidence(
            session=session,
            investigation_id=investigation.id,
            raw_bytes=data,
            source_identifier="auth.log",
            storage_root=tmp_path,
        )

        files = list(tmp_path.iterdir())
        stored_hash = sha256_of(files[0].read_bytes())
        assert stored_hash == result.evidence.content_hash

    async def test_filename_is_evidence_uuid(self, session, investigation, tmp_path):
        """The stored file must be named <evidence_id>.json — not the source identifier."""
        result = await ingest_evidence(
            session=session,
            investigation_id=investigation.id,
            raw_bytes=sample_bytes(),
            source_identifier="original_name.log",
            storage_root=tmp_path,
        )

        expected_name = f"{result.evidence.id}.json"
        files = list(tmp_path.iterdir())
        assert files[0].name == expected_name

    async def test_storage_reference_points_to_existing_file(
        self, session, investigation, tmp_path
    ):
        """Evidence.storage_reference must point to a file that exists."""
        result = await ingest_evidence(
            session=session,
            investigation_id=investigation.id,
            raw_bytes=sample_bytes(),
            source_identifier="auth.log",
            storage_root=tmp_path,
        )
        ref = result.evidence.storage_reference
        # storage_reference may be absolute or relative.  Resolve relative paths
        # against the project root (3 parents from service.py).
        p = Path(ref)
        if not p.is_absolute():
            repo_root = Path(__file__).resolve().parents[2]
            p = repo_root / p
        assert p.exists(), f"storage_reference {ref!r} does not point to an existing file"

    async def test_no_tmp_file_left_after_success(
        self, session, investigation, tmp_path
    ):
        """No .tmp_ file must remain after a successful ingest."""
        await ingest_evidence(
            session=session,
            investigation_id=investigation.id,
            raw_bytes=sample_bytes(),
            source_identifier="auth.log",
            storage_root=tmp_path,
        )
        tmp_files = [f for f in tmp_path.iterdir() if f.name.startswith(".tmp_")]
        assert tmp_files == [], f"Orphaned temp files: {tmp_files}"


# ──────────────────────────────────────────────────────────────────────────────
# Group 4: Database record correctness (integration, DB required)
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestDatabaseRecord:
    async def test_evidence_record_created(self, session, investigation, tmp_path):
        """A new Evidence row must be inserted."""
        result = await ingest_evidence(
            session=session,
            investigation_id=investigation.id,
            raw_bytes=sample_bytes(),
            source_identifier="auth.log",
            storage_root=tmp_path,
        )
        assert isinstance(result.evidence, Evidence)
        assert result.evidence.id is not None

    async def test_is_duplicate_false_on_new_record(
        self, session, investigation, tmp_path
    ):
        result = await ingest_evidence(
            session=session,
            investigation_id=investigation.id,
            raw_bytes=sample_bytes(),
            source_identifier="auth.log",
            storage_root=tmp_path,
        )
        assert result.is_duplicate is False

    async def test_hash_algorithm_is_sha256(self, session, investigation, tmp_path):
        result = await ingest_evidence(
            session=session,
            investigation_id=investigation.id,
            raw_bytes=sample_bytes(),
            source_identifier="auth.log",
            storage_root=tmp_path,
        )
        assert result.evidence.hash_algorithm == "SHA-256"

    async def test_source_type_is_structured_json(
        self, session, investigation, tmp_path
    ):
        result = await ingest_evidence(
            session=session,
            investigation_id=investigation.id,
            raw_bytes=sample_bytes(),
            source_identifier="auth.log",
            storage_root=tmp_path,
        )
        assert result.evidence.source_type == SOURCE_TYPE_JSON

    async def test_is_immutable_true(self, session, investigation, tmp_path):
        result = await ingest_evidence(
            session=session,
            investigation_id=investigation.id,
            raw_bytes=sample_bytes(),
            source_identifier="auth.log",
            storage_root=tmp_path,
        )
        assert result.evidence.is_immutable is True

    async def test_content_hash_matches_input(self, session, investigation, tmp_path):
        data = sample_bytes()
        expected_hash = sha256_of(data)
        result = await ingest_evidence(
            session=session,
            investigation_id=investigation.id,
            raw_bytes=data,
            source_identifier="auth.log",
            storage_root=tmp_path,
        )
        assert result.evidence.content_hash == expected_hash

    async def test_source_identifier_stored(self, session, investigation, tmp_path):
        result = await ingest_evidence(
            session=session,
            investigation_id=investigation.id,
            raw_bytes=sample_bytes(),
            source_identifier="my_auth_export.log",
            storage_root=tmp_path,
        )
        assert result.evidence.source_identifier == "my_auth_export.log"

    async def test_investigation_id_stored(self, session, investigation, tmp_path):
        result = await ingest_evidence(
            session=session,
            investigation_id=investigation.id,
            raw_bytes=sample_bytes(),
            source_identifier="auth.log",
            storage_root=tmp_path,
        )
        assert result.evidence.investigation_id == investigation.id

    async def test_original_content_is_null(self, session, investigation, tmp_path):
        """Phase 3A stores on disk; original_content must remain NULL."""
        result = await ingest_evidence(
            session=session,
            investigation_id=investigation.id,
            raw_bytes=sample_bytes(),
            source_identifier="auth.log",
            storage_root=tmp_path,
        )
        assert result.evidence.original_content is None


# ──────────────────────────────────────────────────────────────────────────────
# Group 5: Duplicate handling (integration, DB required)
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestDuplicateHandling:
    async def test_duplicate_same_investigation_returns_existing(
        self, session, investigation, tmp_path
    ):
        """Identical bytes → same investigation → returns existing record."""
        data = sample_bytes()

        first = await ingest_evidence(
            session=session,
            investigation_id=investigation.id,
            raw_bytes=data,
            source_identifier="auth.log",
            storage_root=tmp_path,
        )
        second = await ingest_evidence(
            session=session,
            investigation_id=investigation.id,
            raw_bytes=data,
            source_identifier="auth.log",
            storage_root=tmp_path,
        )

        assert second.is_duplicate is True
        assert second.evidence.id == first.evidence.id

    async def test_duplicate_does_not_write_second_file(
        self, session, investigation, tmp_path
    ):
        """A duplicate must not produce a second file in storage_root."""
        data = sample_bytes()

        await ingest_evidence(
            session=session,
            investigation_id=investigation.id,
            raw_bytes=data,
            source_identifier="auth.log",
            storage_root=tmp_path,
        )
        await ingest_evidence(
            session=session,
            investigation_id=investigation.id,
            raw_bytes=data,
            source_identifier="auth.log",
            storage_root=tmp_path,
        )

        non_tmp = [f for f in tmp_path.iterdir() if not f.name.startswith(".tmp_")]
        assert len(non_tmp) == 1, f"Expected 1 file, got: {non_tmp}"

    async def test_same_bytes_different_investigation_creates_new_record(
        self, session, tmp_path
    ):
        """The same file submitted to two different investigations → two records."""
        data = sample_bytes()

        inv1 = Investigation(
            id=uuid.uuid4(),
            title="Investigation A",
            status="OPEN",
            created_by=uuid.uuid4(),
        )
        inv2 = Investigation(
            id=uuid.uuid4(),
            title="Investigation B",
            status="OPEN",
            created_by=uuid.uuid4(),
        )
        session.add_all([inv1, inv2])
        await session.flush()

        result1 = await ingest_evidence(
            session=session,
            investigation_id=inv1.id,
            raw_bytes=data,
            source_identifier="auth.log",
            storage_root=tmp_path,
        )
        result2 = await ingest_evidence(
            session=session,
            investigation_id=inv2.id,
            raw_bytes=data,
            source_identifier="auth.log",
            storage_root=tmp_path,
        )

        assert result1.is_duplicate is False
        assert result2.is_duplicate is False
        assert result1.evidence.id != result2.evidence.id


# ──────────────────────────────────────────────────────────────────────────────
# Group 6: Partial-failure safety
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestPartialFailureSafety:
    async def test_file_removed_when_db_flush_fails(
        self, session, investigation, tmp_path
    ):
        """
        If session.flush() raises after the file has been written,
        the file must be cleaned up so no orphan remains.

        The ``investigation`` fixture was created (and flushed) before this
        test body runs, so the mock is installed with no prior flush history.
        Every call to session.flush() from this point comes from ingest_evidence
        itself; therefore we unconditionally raise on the first call.
        """
        data = sample_bytes()

        async def failing_flush(*args, **kwargs):
            raise RuntimeError("Simulated database failure")

        session.flush = failing_flush  # type: ignore[assignment]

        with pytest.raises(RuntimeError, match="Simulated database failure"):
            await ingest_evidence(
                session=session,
                investigation_id=investigation.id,
                raw_bytes=data,
                source_identifier="auth.log",
                storage_root=tmp_path,
            )

        remaining = list(tmp_path.iterdir())
        assert remaining == [], f"Orphaned files found after DB failure: {remaining}"


# ──────────────────────────────────────────────────────────────────────────────
# Group 7: Ingestion result contract
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestIngestionResultContract:
    async def test_result_is_frozen_dataclass(self, session, investigation, tmp_path):
        result = await ingest_evidence(
            session=session,
            investigation_id=investigation.id,
            raw_bytes=sample_bytes(),
            source_identifier="auth.log",
            storage_root=tmp_path,
        )
        assert isinstance(result, IngestionResult)
        # Frozen: must raise on attribute assignment.
        with pytest.raises((AttributeError, TypeError)):
            result.is_duplicate = True  # type: ignore[misc]
