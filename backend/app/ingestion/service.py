"""
Evidence ingestion service for Phase 3A.

RESPONSIBILITY
--------------
Accept raw bytes representing JSON security telemetry, verify integrity,
preserve the original bytes byte-for-byte to local storage, and create an
immutable Evidence record in the database.

WHAT THIS MODULE DOES NOT DO
-----------------------------
- Does not parse event semantics.
- Does not create NormalizedEvent objects.
- Does not create Entity objects.
- Does not perform correlation, scoring, or analysis of any kind.
- Does not communicate with external storage (S3, GCS, etc.).

STORAGE STRATEGY (MVP)
-----------------------
Files are written to: data/raw/{evidence_uuid}.json

Partial-failure safety:
  1. Validate input (size, encoding, JSON validity, filename safety).
  2. Calculate SHA-256 from the exact original bytes.
  3. Check for an existing Evidence record with the same hash within the
     same investigation.  If found, return the existing record immediately.
  4. Write bytes to a temporary file inside data/raw/.
  5. Move (atomic rename) the temporary file to its final name.
  6. Insert the Evidence record in PostgreSQL.
  7. If the database insert fails, remove the final file and re-raise.

This avoids orphaned database records that reference missing files and
avoids orphaned files that have no database record.

DUPLICATE HANDLING
------------------
For the same investigation, an exact duplicate (same SHA-256) returns the
existing Evidence record without creating a new file or database row.
This is forensically correct: identical bytes are the same evidence.

FILE SIZE LIMIT
---------------
MAX_EVIDENCE_BYTES = 50 * 1024 * 1024 (50 MB).
Chosen rationale: large enough for realistic single-event JSON telemetry
files or small batch exports during development.  Streaming infrastructure
is deferred to a later phase.

SECURITY
--------
- Caller-supplied filenames are NEVER used as filesystem paths.
- The storage root is resolved to an absolute path and every write is
  checked to remain inside it (path-traversal guard).
- Uploaded bytes are never executed, imported, or followed as paths.
- Raw content is not logged.
"""

import hashlib
import json
import logging
import os
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.evidence import Evidence

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

#: Maximum accepted evidence payload in bytes (50 MB).
MAX_EVIDENCE_BYTES: int = 50 * 1024 * 1024

#: Hash algorithm applied to raw bytes.
HASH_ALGORITHM: str = "SHA-256"

#: Source-type label for JSON security telemetry in Phase 3A.
SOURCE_TYPE_JSON: str = "STRUCTURED_JSON"

#: File extension written to storage.
STORAGE_EXTENSION: str = ".json"


# ──────────────────────────────────────────────────────────────────────────────
# Exceptions
# ──────────────────────────────────────────────────────────────────────────────


class EvidenceIngestionError(Exception):
    """Base class for all ingestion-layer errors."""


class EmptyEvidenceError(EvidenceIngestionError):
    """Raised when the submitted bytes are empty."""


class EvidenceTooLargeError(EvidenceIngestionError):
    """Raised when the submitted bytes exceed MAX_EVIDENCE_BYTES."""


class InvalidEncodingError(EvidenceIngestionError):
    """Raised when the bytes cannot be decoded as UTF-8."""


class InvalidJSONError(EvidenceIngestionError):
    """Raised when the bytes are valid UTF-8 but not valid JSON."""


class UnsafeFilenameError(EvidenceIngestionError):
    """Raised when the caller-supplied source identifier contains dangerous characters."""


class StorageError(EvidenceIngestionError):
    """Raised when a filesystem operation fails during ingestion."""


# ──────────────────────────────────────────────────────────────────────────────
# Result dataclass
# ──────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class IngestionResult:
    """
    Returned by the ingestion service after a successful operation.

    ``is_duplicate`` is True when an identical evidence record already
    existed in the database; the ``evidence`` field contains that existing
    record rather than a newly created one.
    """

    evidence: Evidence
    is_duplicate: bool


# ──────────────────────────────────────────────────────────────────────────────
# Storage root resolution
# ──────────────────────────────────────────────────────────────────────────────


def resolve_storage_root(data_raw_path: str | Path | None = None) -> Path:
    """
    Return an absolute, resolved Path to the raw evidence storage directory.

    If *data_raw_path* is not given, the path is derived relative to this
    file's location:  <repo_root>/data/raw/

    The directory is created if it does not already exist.
    """
    if data_raw_path is not None:
        root = Path(data_raw_path).resolve()
    else:
        # backend/app/ingestion/service.py → backend/ → repo root
        repo_root = Path(__file__).resolve().parents[3]
        root = repo_root / "data" / "raw"

    root.mkdir(parents=True, exist_ok=True)
    return root


# ──────────────────────────────────────────────────────────────────────────────
# Input validation
# ──────────────────────────────────────────────────────────────────────────────


def validate_source_identifier(source_identifier: str) -> None:
    """
    Raise UnsafeFilenameError if *source_identifier* contains characters
    that are dangerous when used in filesystem paths.

    The source identifier is metadata only.  It is NEVER used as a
    filesystem path, but we still reject obviously dangerous values to
    catch misuse early.
    """
    if not source_identifier:
        raise UnsafeFilenameError("source_identifier must not be empty")

    # Reject null bytes
    if "\x00" in source_identifier:
        raise UnsafeFilenameError("source_identifier contains a null byte")

    # Reject path separators and traversal sequences
    dangerous = {"/", "\\", "..", os.sep}
    for char_or_seq in dangerous:
        if char_or_seq in source_identifier:
            raise UnsafeFilenameError(
                f"source_identifier contains unsafe character or sequence: {char_or_seq!r}"
            )


def validate_raw_bytes(raw_bytes: bytes) -> None:
    """
    Validate the submitted evidence bytes.

    Raises:
        EmptyEvidenceError      – if bytes is empty
        EvidenceTooLargeError   – if bytes exceeds MAX_EVIDENCE_BYTES
        InvalidEncodingError    – if bytes is not valid UTF-8
        InvalidJSONError        – if bytes is not valid JSON
    """
    if not raw_bytes:
        raise EmptyEvidenceError("Evidence payload must not be empty")

    if len(raw_bytes) > MAX_EVIDENCE_BYTES:
        raise EvidenceTooLargeError(
            f"Evidence payload exceeds the {MAX_EVIDENCE_BYTES // (1024 * 1024)} MB limit "
            f"({len(raw_bytes)} bytes received)"
        )

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidEncodingError(
            "Evidence payload is not valid UTF-8"
        ) from exc

    try:
        json.loads(text)
    except json.JSONDecodeError as exc:
        raise InvalidJSONError(
            f"Evidence payload is not valid JSON: {exc.msg}"
        ) from exc


# ──────────────────────────────────────────────────────────────────────────────
# SHA-256 calculation
# ──────────────────────────────────────────────────────────────────────────────


def compute_sha256(raw_bytes: bytes) -> str:
    """
    Return the lowercase hex SHA-256 digest of *raw_bytes*.

    The hash is computed from the exact original bytes.  No parsing,
    re-serialization, or transformation is performed.
    """
    return hashlib.sha256(raw_bytes).hexdigest()


# ──────────────────────────────────────────────────────────────────────────────
# Filesystem helpers
# ──────────────────────────────────────────────────────────────────────────────


def _safe_final_path(storage_root: Path, evidence_id: uuid.UUID) -> Path:
    """
    Return the canonical storage path for an Evidence record.

    The filename is derived solely from the server-generated UUID,
    ensuring the caller-supplied source identifier can never influence
    the filesystem path.
    """
    final = (storage_root / f"{evidence_id}{STORAGE_EXTENSION}").resolve()

    # Paranoia guard: ensure the resolved path is still inside storage_root.
    if not str(final).startswith(str(storage_root)):
        raise StorageError(
            f"Computed storage path {final} escapes the storage root {storage_root}"
        )

    return final


def write_evidence_bytes(
    raw_bytes: bytes,
    evidence_id: uuid.UUID,
    storage_root: Path,
) -> Path:
    """
    Atomically write *raw_bytes* to the evidence store.

    Steps:
      1. Write bytes to a NamedTemporaryFile inside *storage_root*.
      2. Flush and fsync the file to ensure durability.
      3. Rename (atomic on POSIX) to the final path.

    Returns the final Path.

    Raises StorageError on any filesystem failure.
    """
    final_path = _safe_final_path(storage_root, evidence_id)

    # Write to a temp file in the same directory so the rename is atomic.
    try:
        fd, tmp_path_str = tempfile.mkstemp(
            dir=storage_root,
            prefix=".tmp_",
            suffix=".json",
        )
        tmp_path = Path(tmp_path_str)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(raw_bytes)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, final_path)
        except Exception:
            # Clean up the temp file if anything goes wrong before the rename.
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise
    except OSError as exc:
        raise StorageError(
            f"Failed to write evidence to {storage_root}: {exc}"
        ) from exc

    return final_path


# ──────────────────────────────────────────────────────────────────────────────
# Duplicate detection
# ──────────────────────────────────────────────────────────────────────────────


async def find_existing_evidence(
    session: AsyncSession,
    investigation_id: uuid.UUID,
    content_hash: str,
) -> Evidence | None:
    """
    Return an existing Evidence record for this investigation with the
    given SHA-256 hash, or None if no such record exists.
    """
    result = await session.execute(
        select(Evidence).where(
            Evidence.investigation_id == investigation_id,
            Evidence.content_hash == content_hash,
        )
    )
    return result.scalar_one_or_none()


# ──────────────────────────────────────────────────────────────────────────────
# Main ingestion entry point
# ──────────────────────────────────────────────────────────────────────────────


async def ingest_evidence(
    *,
    session: AsyncSession,
    investigation_id: uuid.UUID,
    raw_bytes: bytes,
    source_identifier: str,
    storage_root: Path | None = None,
) -> IngestionResult:
    """
    Ingest raw JSON security telemetry as Evidence.

    Parameters
    ----------
    session:
        An open async SQLAlchemy session.  The caller is responsible for
        committing or rolling back.
    investigation_id:
        The Investigation to associate this Evidence with.
    raw_bytes:
        The exact original bytes of the security telemetry file.
        Must not be pre-parsed, reformatted, or re-encoded.
    source_identifier:
        A human-readable label for the source (e.g. the original filename).
        This value is stored as metadata only and is NEVER used as a
        filesystem path.
    storage_root:
        Override the default storage location.  Used in tests to direct
        writes to a temporary directory.  Defaults to data/raw/.

    Returns
    -------
    IngestionResult
        Contains the Evidence ORM instance and a flag indicating whether
        the returned record is a pre-existing duplicate.

    Raises
    ------
    EmptyEvidenceError, EvidenceTooLargeError, InvalidEncodingError,
    InvalidJSONError, UnsafeFilenameError, StorageError
    """
    # ── 1. Validate inputs ────────────────────────────────────────────────────
    validate_source_identifier(source_identifier)
    validate_raw_bytes(raw_bytes)

    # ── 2. Calculate SHA-256 from the exact original bytes ────────────────────
    content_hash = compute_sha256(raw_bytes)

    # ── 3. Resolve storage location ───────────────────────────────────────────
    root = resolve_storage_root(storage_root)

    # ── 4. Check for duplicate within the same investigation ──────────────────
    existing = await find_existing_evidence(session, investigation_id, content_hash)
    if existing is not None:
        logger.info(
            "Duplicate evidence detected for investigation %s (hash=%s). "
            "Returning existing record %s.",
            investigation_id,
            content_hash,
            existing.id,
        )
        return IngestionResult(evidence=existing, is_duplicate=True)

    # ── 5. Generate a server-controlled evidence ID ───────────────────────────
    evidence_id = uuid.uuid4()

    # ── 6. Write bytes to filesystem (atomic) ─────────────────────────────────
    final_path = write_evidence_bytes(raw_bytes, evidence_id, root)

    # Compute a relative storage reference for portability.
    # We store it relative to the repository root so that the path remains
    # valid even if the process working directory changes.
    try:
        repo_root = Path(__file__).resolve().parents[3]
        storage_reference = str(final_path.relative_to(repo_root))
    except ValueError:
        # If the path cannot be made relative (e.g. custom storage_root in
        # tests outside the repo), fall back to the absolute path string.
        storage_reference = str(final_path)

    # ── 7. Create the Evidence database record ────────────────────────────────
    evidence = Evidence(
        id=evidence_id,
        investigation_id=investigation_id,
        source_type=SOURCE_TYPE_JSON,
        source_identifier=source_identifier,
        storage_reference=storage_reference,
        content_hash=content_hash,
        hash_algorithm=HASH_ALGORITHM,
        is_immutable=True,
        # original_content is intentionally left NULL: the file is on disk.
        # source_metadata is populated in a future phase when we know more
        # about the telemetry format.
    )
    session.add(evidence)

    try:
        await session.flush()  # Surface DB errors before the caller commits.
    except Exception:
        # DB insert failed.  Remove the file we just wrote to avoid leaving
        # an orphaned file with no corresponding database record.
        logger.error(
            "Database flush failed for evidence %s. Removing orphaned file %s.",
            evidence_id,
            final_path,
        )
        try:
            final_path.unlink(missing_ok=True)
        except OSError as cleanup_exc:
            logger.error(
                "Failed to clean up orphaned file %s: %s", final_path, cleanup_exc
            )
        raise

    logger.info(
        "Evidence ingested: id=%s investigation=%s hash=%s path=%s",
        evidence_id,
        investigation_id,
        content_hash,
        storage_reference,
    )

    return IngestionResult(evidence=evidence, is_duplicate=False)
