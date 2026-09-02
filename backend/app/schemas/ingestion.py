"""
Phase 3C — Evidence Ingestion API schemas.

These Pydantic models define the HTTP request/response contract for:

    POST /api/v1/evidence/ingest

They are intentionally separate from the existing EvidenceCreate /
EvidenceRead schemas in evidence.py.  EvidenceCreate exposes
server-computed fields (content_hash, storage_reference, hash_algorithm)
that must never be accepted from callers.  These schemas present only the
correct external API surface.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Request schema
# ---------------------------------------------------------------------------


class EvidenceIngestRequest(BaseModel):
    """
    Request body for POST /api/v1/evidence/ingest.

    The caller supplies only what they know: which investigation this
    evidence belongs to, a human-readable source label, and the raw
    JSON content.  All other fields (content hash, storage reference,
    hash algorithm, evidence ID, source type) are computed server-side.
    """

    model_config = ConfigDict(extra="forbid")

    investigation_id: UUID
    """UUID of an existing Investigation.  The endpoint returns 404 if
    no matching row exists."""

    source_identifier: str = Field(..., min_length=1, max_length=1000)
    """Human-readable label for the evidence source (e.g. original
    filename, agent name).  Stored as metadata only — never used as a
    filesystem path."""

    content: str = Field(..., min_length=1)
    """Raw JSON security telemetry as a UTF-8 string.

    The string is re-encoded to bytes (UTF-8) before being passed to the
    ingestion service.  The SHA-256 is computed from those exact bytes,
    so the hash is deterministic for the same string.

    Server-side constraints (enforced by Phase 3A):
      - Must not be empty (min_length=1 catches this at schema level too)
      - Must be <= 50 MB after encoding to bytes
      - Must be valid JSON (single object or array of objects)
    """


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class NormalizedEventSummary(BaseModel):
    """
    Lightweight summary of one NormalizedEvent produced during ingestion.

    Only the fields needed to identify the event and its temporal position
    are included.  Full event details are available via future GET endpoints.
    """

    model_config = ConfigDict(from_attributes=True)

    event_id: UUID
    event_type: str
    event_category: str
    occurred_at: datetime


class EvidenceIngestResponse(BaseModel):
    """
    Response body for POST /api/v1/evidence/ingest.

    HTTP 201 is returned when new evidence is ingested and normalized.
    HTTP 200 is returned when the same SHA-256 was already ingested for
    this investigation (is_duplicate=True).
    """

    evidence_id: UUID
    """Server-assigned UUID of the Evidence record.  On duplicate
    submission, this is the UUID of the *existing* record."""

    content_hash: str
    """SHA-256 hex digest of the ingested bytes, lowercase, 64 characters.
    Clients may verify this against their own hash of the content string
    encoded as UTF-8."""

    is_duplicate: bool
    """True when identical content (same SHA-256) was already ingested for
    this investigation.  No new Evidence row or NormalizedEvent rows were
    created in that case."""

    event_count: int
    """Number of NormalizedEvent records produced.  Zero when
    is_duplicate is True (normalization is not re-run on duplicates)."""

    events_created: list[NormalizedEventSummary]
    """Summaries of each NormalizedEvent produced, in input order.
    Empty list when is_duplicate is True."""
