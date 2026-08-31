"""
Normalization error types for Phase 3B.

Every normalization failure is represented as a NormalizationError instance.
The error code identifies the failure category; the message and context
fields give the investigator enough information to understand what went wrong
without exposing the entire raw evidence payload.

Error codes
-----------
MISSING_REQUIRED_FIELD   – A field that must be present is absent or null.
INVALID_FIELD_TYPE       – A field has the wrong Python/JSON type.
INVALID_TIMESTAMP        – Timestamp is malformed, missing timezone, or
                           represents a non-UTC-aware datetime.
UNKNOWN_EVENT_TYPE       – event_type is not in the supported registry.
INVALID_IP               – source_ip or destination_ip is not a valid
                           IPv4 or IPv6 address.
INVALID_PORT             – source_port or destination_port is outside
                           the valid range 0–65535.
INVALID_FIELD_VALUE      – A field is well-typed but semantically invalid
                           (e.g. empty string where a value is required).

NormalizationFailure
--------------------
Raised (or collected) when one or more NormalizationError instances prevent
a valid NormalizedEvent from being produced.

PartialNormalizationFailure
---------------------------
Raised when an evidence file contains multiple events and one or more of
them could not be normalized.  Because Phase 3B uses the all-or-nothing
strategy, this causes the entire normalization of that Evidence to fail.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ──────────────────────────────────────────────────────────────────────────────
# Error codes
# ──────────────────────────────────────────────────────────────────────────────

MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
INVALID_FIELD_TYPE = "INVALID_FIELD_TYPE"
INVALID_TIMESTAMP = "INVALID_TIMESTAMP"
UNKNOWN_EVENT_TYPE = "UNKNOWN_EVENT_TYPE"
INVALID_IP = "INVALID_IP"
INVALID_PORT = "INVALID_PORT"
INVALID_FIELD_VALUE = "INVALID_FIELD_VALUE"


# ──────────────────────────────────────────────────────────────────────────────
# Error dataclass
# ──────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class NormalizationError:
    """
    A single normalization failure for one field in one event.

    Attributes
    ----------
    code:
        Machine-readable error code (one of the constants above).
    field:
        The name of the failing field (e.g. "timestamp", "event_type").
        None when the error applies to the whole event (e.g. wrong top-level
        JSON type).
    reason:
        A human-readable English description.  Must not contain the raw
        evidence value — only structural/semantic information.
    event_index:
        Zero-based index of the event within a multi-event file.
        None for single-event inputs.
    """

    code: str
    field: str | None
    reason: str
    event_index: int | None = None

    def __str__(self) -> str:
        loc = f"event[{self.event_index}]" if self.event_index is not None else "event"
        field_part = f".{self.field}" if self.field else ""
        return f"[{self.code}] {loc}{field_part}: {self.reason}"


# ──────────────────────────────────────────────────────────────────────────────
# Exceptions
# ──────────────────────────────────────────────────────────────────────────────


class NormalizationFailure(Exception):
    """
    Raised when an event cannot be normalized.

    Contains one or more NormalizationError instances describing why.
    """

    def __init__(self, errors: list[NormalizationError]) -> None:
        if not errors:
            raise ValueError("NormalizationFailure requires at least one error")
        self.errors = errors
        super().__init__("; ".join(str(e) for e in errors))

    @classmethod
    def single(
        cls,
        code: str,
        field: str | None,
        reason: str,
        event_index: int | None = None,
    ) -> "NormalizationFailure":
        """Convenience constructor for a single-error failure."""
        return cls([NormalizationError(code=code, field=field, reason=reason, event_index=event_index)])


class PartialNormalizationFailure(Exception):
    """
    Raised when a multi-event Evidence file contains at least one invalid
    event.

    Because Phase 3B uses all-or-nothing normalization, the caller should
    treat this as a complete failure for the Evidence record.

    Attributes
    ----------
    failures:
        Mapping of event_index → list of NormalizationError for that event.
    total_events:
        Total number of events that were attempted.
    """

    def __init__(
        self,
        failures: dict[int, list[NormalizationError]],
        total_events: int,
    ) -> None:
        self.failures = failures
        self.total_events = total_events
        bad = sorted(failures)
        summary = ", ".join(
            f"event[{i}]: {len(failures[i])} error(s)" for i in bad
        )
        super().__init__(
            f"{len(bad)} of {total_events} event(s) failed normalization: {summary}"
        )
