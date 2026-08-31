"""
Normalization module — Phase 3B.

Converts preserved raw JSON security telemetry into a common
NormalizedEvent representation that the rest of the pipeline can reason
about uniformly.

Phase 3B capabilities:
- Parse single-object and array-of-objects JSON evidence.
- Validate all events before writing any normalized records (all-or-nothing).
- Resolve event types against a controlled vocabulary.
- Normalize timestamps to UTC; reject naive timestamps.
- Canonicalize host (lowercase), user (strip only), process (lowercase).
- Validate and canonicalize IPv4/IPv6 addresses and port numbers.
- Forward source-specific fields to extended_attributes.
- Preserve original values in extended_attributes when canonicalization changes them.
- Create or reuse Entity records by (investigation_id, entity_type, canonical_value).
- Link every NormalizedEvent to its source Evidence record.
- Produce explicit, structured NormalizationError objects on failure.

Normalization is deterministic: same input always produces the same output.
Normalization is representation only: no security semantics, no inference.
"""

from app.normalization.errors import (
    INVALID_FIELD_TYPE,
    INVALID_FIELD_VALUE,
    INVALID_IP,
    INVALID_PORT,
    INVALID_TIMESTAMP,
    MISSING_REQUIRED_FIELD,
    UNKNOWN_EVENT_TYPE,
    NormalizationError,
    NormalizationFailure,
    PartialNormalizationFailure,
)
from app.normalization.events import (
    EVENT_TYPE_REGISTRY,
    SUPPORTED_EVENT_TYPES,
    resolve_event_type,
)
from app.normalization.service import (
    NormalizationResult,
    SingleEventResult,
    normalize_evidence,
)

__all__ = [
    # Errors
    "INVALID_FIELD_TYPE",
    "INVALID_FIELD_VALUE",
    "INVALID_IP",
    "INVALID_PORT",
    "INVALID_TIMESTAMP",
    "MISSING_REQUIRED_FIELD",
    "UNKNOWN_EVENT_TYPE",
    "NormalizationError",
    "NormalizationFailure",
    "PartialNormalizationFailure",
    # Registry
    "EVENT_TYPE_REGISTRY",
    "SUPPORTED_EVENT_TYPES",
    "resolve_event_type",
    # Service
    "NormalizationResult",
    "SingleEventResult",
    "normalize_evidence",
]
