"""
Evidence Ingestion API Router — Phase 3C.

Exposes:
    POST /api/v1/evidence/ingest

This router is a thin HTTP boundary around the existing Phase 3A
(ingestion) and Phase 3B (normalization) services.  It does NOT contain
ingestion logic, hashing, filesystem path construction, or normalization
rules.  Those all live in their respective service modules.

TRANSACTION OWNERSHIP
---------------------
Phase 3A and Phase 3B both flush but do not commit.  This router owns
the transaction boundary:

  - New evidence  → commit after successful normalization → 201
  - Duplicate     → commit immediately after duplicate detection → 200
  - Any failure   → rollback → 422 / 404 / 500

STORAGE ROOT DEPENDENCY
-----------------------
The router exposes a FastAPI dependency ``get_storage_root()`` that
returns the directory Phase 3A should write evidence files to.  In
production this returns None, causing Phase 3A to use its default path
(data/raw/ relative to the repository root).  In tests, the caller
overrides this dependency to redirect writes to a temporary directory,
ensuring the real data/raw/ directory is never written to during tests.

This does NOT modify Phase 3A — it uses Phase 3A's documented
``storage_root`` parameter, which was designed for exactly this purpose.

ORPHANED FILE HANDLING
----------------------
Phase 3A writes the evidence file atomically before flushing to the DB.
If the DB flush inside Phase 3A fails, Phase 3A removes the file itself
(see ingestion/service.py, step 7).

If Phase 3A succeeds (file written + Evidence row flushed) but a
subsequent step fails (normalization, commit, or unexpected exception),
the DB rollback removes the Evidence row, leaving the file orphaned on
disk.  In that case this router attempts to clean up the file using
Phase 3A's public ``resolve_storage_root()`` and the path stored in
``evidence.storage_reference``.

Path resolution follows Phase 3A's own convention:
  - Phase 3A stores an absolute path when storage_root is outside the
    repository tree (the ``except ValueError`` fallback in service.py).
  - Phase 3A stores a relative path (relative to repo root) otherwise.
  In both cases: resolve_storage_root(storage_root) provides the base
  when the reference is relative; absolute references are used as-is.

This cleanup is best-effort: filesystem and PostgreSQL cannot be made
atomic without distributed transactions.  An orphaned file that has no
Evidence DB row is harmless and can be removed by a maintenance job.

500 RESPONSES
-------------
Internal errors (StorageError, SQLAlchemyError, unexpected exceptions)
do NOT leak stack traces, SQL, filesystem paths, or raw evidence to
callers.  All unexpected exceptions trigger explicit rollback and
orphaned-file cleanup before returning a generic 500.
"""

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.ingestion import (
    EmptyEvidenceError,
    EvidenceIngestionError,
    EvidenceTooLargeError,
    InvalidEncodingError,
    InvalidJSONError,
    StorageError,
    UnsafeFilenameError,
    ingest_evidence,
    resolve_storage_root,
)
from app.models.investigation import Investigation
from app.normalization import (
    NormalizationFailure,
    PartialNormalizationFailure,
    normalize_evidence,
)
from app.schemas.ingestion import (
    EvidenceIngestRequest,
    EvidenceIngestResponse,
    NormalizedEventSummary,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/evidence", tags=["evidence"])


# ---------------------------------------------------------------------------
# Storage root dependency
# ---------------------------------------------------------------------------


def get_storage_root() -> Path | None:
    """
    FastAPI dependency that returns the evidence storage root directory.

    Returns None in production, which causes Phase 3A to use its default
    location (data/raw/ relative to the repository root).

    Tests override this dependency to redirect writes to a temporary
    directory, keeping the real data/raw/ directory clean.
    """
    return None


# ---------------------------------------------------------------------------
# Orphaned-file cleanup helper
# ---------------------------------------------------------------------------


def _try_remove_orphaned_file(
    storage_reference: str | None,
    storage_root: Path | None,
) -> None:
    """
    Best-effort removal of a newly-written evidence file that became
    orphaned because a subsequent DB rollback removed its Evidence row.

    Must only be called for newly-created evidence (is_duplicate=False)
    after a rollback.  Never call this for duplicate evidence.

    Path resolution delegates entirely to Phase 3A's public
    ``resolve_storage_root()``:
      - Absolute storage_reference (e.g. from an out-of-tree test tmpdir):
        used directly, no root resolution needed.
      - Relative storage_reference (production default layout):
        resolved against resolve_storage_root(storage_root), which is the
        same root Phase 3A used when it wrote the file.

    This avoids any duplicated repository-root convention in Phase 3C.

    Note on side effect: ``resolve_storage_root()`` creates the storage
    directory if it does not already exist.  On this error-cleanup path that
    is intentional and acceptable — in production the directory already
    exists (Phase 3A created it before this helper is ever called), and in
    tests the tmpdir override is always pre-created by the ``storage_dir``
    fixture.  No new storage abstraction is introduced to avoid this side
    effect.
    """
    if storage_reference is None:
        return

    ref = Path(storage_reference)
    if not ref.is_absolute():
        # Relative paths are relative to the storage root Phase 3A used.
        # resolve_storage_root() is Phase 3A's public function and owns the
        # convention.  We pass storage_root so it resolves to the same base.
        ref = resolve_storage_root(storage_root) / ref

    try:
        ref.unlink(missing_ok=True)
        logger.info("Removed orphaned evidence file: %s", ref)
    except OSError as exc:
        logger.warning(
            "Could not remove orphaned evidence file %s: %s", ref, exc
        )


# ---------------------------------------------------------------------------
# Ingestion error → structured API response mapping (M1)
# ---------------------------------------------------------------------------


def _ingestion_error_to_detail(exc: EvidenceIngestionError) -> dict:
    """
    Return a stable, structured error detail dict for a Phase 3A
    EvidenceIngestionError, consistent with the normalization error contract:

        {message, errors: [{code, field, reason}]}

    Stable error codes (clients may rely on these across versions):
        EMPTY_EVIDENCE            – content field is empty
        EVIDENCE_TOO_LARGE        – content exceeds the size limit
        INVALID_ENCODING          – content is not valid UTF-8
        INVALID_JSON              – content is not valid JSON
        UNSAFE_SOURCE_IDENTIFIER  – source_identifier contains unsafe chars
        INGESTION_ERROR           – any other EvidenceIngestionError subclass

    None of the ``reason`` strings expose JSON parser internals
    (line/column/char positions), byte counts, filesystem paths, stack
    traces, or exception repr().

    ``StorageError`` is a subclass of ``EvidenceIngestionError`` but is
    caught by the more-specific ``except StorageError`` handler before
    reaching this function, so it never appears here.
    """
    if isinstance(exc, EmptyEvidenceError):
        code, field, reason = (
            "EMPTY_EVIDENCE",
            "content",
            "Evidence content must not be empty.",
        )
    elif isinstance(exc, EvidenceTooLargeError):
        code, field, reason = (
            "EVIDENCE_TOO_LARGE",
            "content",
            "Evidence content exceeds the maximum allowed size.",
        )
    elif isinstance(exc, InvalidEncodingError):
        code, field, reason = (
            "INVALID_ENCODING",
            "content",
            "Evidence content is not valid UTF-8.",
        )
    elif isinstance(exc, InvalidJSONError):
        code, field, reason = (
            "INVALID_JSON",
            "content",
            "Evidence content is not valid JSON.",
        )
    elif isinstance(exc, UnsafeFilenameError):
        code, field, reason = (
            "UNSAFE_SOURCE_IDENTIFIER",
            "source_identifier",
            "source_identifier contains unsafe characters or sequences.",
        )
    else:
        # Unknown future EvidenceIngestionError subclass.
        code, field, reason = (
            "INGESTION_ERROR",
            None,
            "Evidence could not be ingested.",
        )

    return {
        "message": "Evidence ingestion failed.",
        "errors": [{"code": code, "field": field, "reason": reason}],
    }


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/ingest",
    status_code=status.HTTP_201_CREATED,
    response_model=EvidenceIngestResponse,
    summary="Ingest raw evidence and normalize it",
    response_description=(
        "201 when new evidence is ingested; "
        "200 when identical content was already ingested for this investigation."
    ),
)
async def ingest_evidence_endpoint(
    request: EvidenceIngestRequest,
    http_response: Response,
    session: AsyncSession = Depends(get_session),
    storage_root: Path | None = Depends(get_storage_root),
) -> EvidenceIngestResponse:
    """
    Accept raw JSON security telemetry, store it as immutable Evidence,
    and normalize it into structured NormalizedEvent records.

    Steps:
      1. Verify the investigation exists (404 if not).
      2. Encode content to UTF-8 bytes and call Phase 3A ingest_evidence().
      3. If duplicate: commit and return 200.
      4. If new: call Phase 3B normalize_evidence(), commit, return 201.

    On ingestion or normalization validation error: rollback and return 422.
    On storage or database error: rollback and return 500 (no internal
    details exposed to the caller).
    On any unexpected exception after new evidence has been written to disk:
    explicit rollback, best-effort orphaned-file cleanup, generic 500.
    """
    # ── 1. Verify the investigation exists ───────────────────────────────────
    investigation = await session.get(Investigation, request.investigation_id)
    if investigation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation {request.investigation_id} not found.",
        )

    # ── 2. Encode content and ingest (Phase 3A) ───────────────────────────────
    raw_bytes = request.content.encode("utf-8")

    try:
        ingestion_result = await ingest_evidence(
            session=session,
            investigation_id=request.investigation_id,
            raw_bytes=raw_bytes,
            source_identifier=request.source_identifier,
            storage_root=storage_root,
        )
    except StorageError as exc:
        await session.rollback()
        logger.error("Storage error during evidence ingestion: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal storage error occurred.",
        ) from exc
    except EvidenceIngestionError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=_ingestion_error_to_detail(exc),
        ) from exc

    evidence = ingestion_result.evidence

    # ── 3. Duplicate fast-path ────────────────────────────────────────────────
    if ingestion_result.is_duplicate:
        try:
            await session.commit()
        except SQLAlchemyError as exc:
            await session.rollback()
            logger.error("Database commit failed (duplicate path): %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An internal database error occurred.",
            ) from exc

        # Override the route's default 201 with 200 for duplicates.
        http_response.status_code = status.HTTP_200_OK
        return EvidenceIngestResponse(
            evidence_id=evidence.id,
            content_hash=evidence.content_hash,
            is_duplicate=True,
            event_count=0,
            events_created=[],
        )

    # From this point, a new Evidence file has been written to disk and the
    # Evidence row has been flushed (but not committed).  Any failure from
    # here must rollback the session and attempt orphaned-file cleanup.

    # ── 4. Normalize new evidence (Phase 3B) ──────────────────────────────────
    try:
        norm_result = await normalize_evidence(session=session, evidence=evidence)
    except (NormalizationFailure, PartialNormalizationFailure) as exc:
        await session.rollback()
        _try_remove_orphaned_file(evidence.storage_reference, storage_root)

        if isinstance(exc, NormalizationFailure):
            errors = [
                {"code": e.code, "field": e.field, "reason": e.reason}
                for e in exc.errors
            ]
        else:  # PartialNormalizationFailure
            errors = [
                {
                    "code": err.code,
                    "field": err.field,
                    "reason": err.reason,
                    "event_index": idx,
                }
                for idx, errs in sorted(exc.failures.items())
                for err in errs
            ]

        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"message": "Evidence normalization failed.", "errors": errors},
        ) from exc
    except SQLAlchemyError as exc:
        await session.rollback()
        _try_remove_orphaned_file(evidence.storage_reference, storage_root)
        logger.error("Database error during normalization: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal database error occurred.",
        ) from exc
    except Exception as exc:  # noqa: BLE001
        # Unexpected error after new evidence was written.  Roll back the DB
        # session and clean up the newly-written file to avoid orphans.
        await session.rollback()
        _try_remove_orphaned_file(evidence.storage_reference, storage_root)
        logger.exception(
            "Unexpected exception during normalization for evidence %s", evidence.id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected internal error occurred.",
        ) from exc

    # ── 5. Commit ──────────────────────────────────────────────────────────────
    try:
        await session.commit()
    except SQLAlchemyError as exc:
        await session.rollback()
        # File is on disk but DB was not committed.  Attempt cleanup.
        # This cannot be made fully atomic without distributed transactions.
        _try_remove_orphaned_file(evidence.storage_reference, storage_root)
        logger.error("Database commit failed after normalization: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal database error occurred.",
        ) from exc
    except Exception as exc:  # noqa: BLE001
        # Unexpected error during commit.  Same treatment as above.
        await session.rollback()
        _try_remove_orphaned_file(evidence.storage_reference, storage_root)
        logger.exception(
            "Unexpected exception during commit for evidence %s", evidence.id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected internal error occurred.",
        ) from exc

    # ── 6. Build response (events in input order, as returned by Phase 3B) ────
    events_created = [
        NormalizedEventSummary(
            event_id=ev.id,
            event_type=ev.event_type,
            event_category=ev.event_category,
            occurred_at=ev.occurred_at,
        )
        for ev in norm_result.events
    ]

    return EvidenceIngestResponse(
        evidence_id=evidence.id,
        content_hash=evidence.content_hash,
        is_duplicate=False,
        event_count=norm_result.event_count,
        events_created=events_created,
    )
