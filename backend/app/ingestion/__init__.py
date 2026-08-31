"""
Ingestion module.

Responsible for receiving raw security evidence and persisting it in its
original, unmodified form.

Phase 3A capabilities:
- Accept raw JSON security telemetry (bytes).
- Validate: non-empty, ≤ 50 MB, valid UTF-8, valid JSON.
- Reject unsafe source identifiers (path traversal characters).
- Compute SHA-256 from the exact original bytes.
- Write byte-for-byte identical copy to data/raw/<uuid>.json.
- Create an immutable Evidence database record.
- Return existing record immediately on exact duplicate (same hash,
  same investigation) — idempotent ingestion.
- Remove the on-disk file atomically if the database flush fails.

No business logic lives here.  Ingestion is a boundary layer.
"""

from app.ingestion.service import (
    HASH_ALGORITHM,
    MAX_EVIDENCE_BYTES,
    SOURCE_TYPE_JSON,
    EmptyEvidenceError,
    EvidenceIngestionError,
    EvidenceTooLargeError,
    IngestionResult,
    InvalidEncodingError,
    InvalidJSONError,
    StorageError,
    UnsafeFilenameError,
    ingest_evidence,
    resolve_storage_root,
)

__all__ = [
    "HASH_ALGORITHM",
    "MAX_EVIDENCE_BYTES",
    "SOURCE_TYPE_JSON",
    "EmptyEvidenceError",
    "EvidenceIngestionError",
    "EvidenceTooLargeError",
    "IngestionResult",
    "InvalidEncodingError",
    "InvalidJSONError",
    "StorageError",
    "UnsafeFilenameError",
    "ingest_evidence",
    "resolve_storage_root",
]
