"""
Pydantic input schema for raw JSON security telemetry events.

This schema validates the structure of a single parsed JSON event object
BEFORE normalization.  It is intentionally permissive about optional fields
because real telemetry sources include/omit fields inconsistently.

Required fields:
    timestamp   – ISO-8601 string; must carry timezone information.
    event_type  – string; will be resolved through the event type registry.

All other fields are optional.  Unknown fields are captured in the schema's
extra-fields mechanism and forwarded to the normalizer for extended_attributes
handling.

Timestamp validation rules
---------------------------
- Must be parseable as an ISO-8601 datetime string.
- Must include explicit timezone information (Z, +HH:MM, -HH:MM).
- Naive datetimes (no timezone) are REJECTED — we cannot guess the offset.
- Timestamps with timezone are converted to UTC internally.

These rules are enforced in the normalization layer (not here) because:
1. We want a NormalizationError with rich context rather than a generic
   Pydantic ValidationError.
2. We want the timestamp as a raw string so we can produce precise error
   messages referencing the field name.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class RawEventInput(BaseModel):
    """
    The validated structure of a single raw JSON telemetry event.

    Extra fields are allowed and collected in model_extra so that
    source-specific fields can be forwarded to extended_attributes.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    # ── Required ─────────────────────────────────────────────────────────────
    timestamp: str = Field(
        ...,
        description="ISO-8601 timestamp string.  Must include timezone.",
    )
    event_type: str = Field(
        ...,
        description="Raw event type string; will be normalized to canonical form.",
    )

    # ── Common optional fields ────────────────────────────────────────────────
    source: str | None = Field(
        default=None,
        description="Name of the telemetry source (e.g. 'sysmon', 'zeek').",
    )
    host: str | None = Field(
        default=None,
        description="Originating host name or identifier.",
    )
    user: str | None = Field(
        default=None,
        description="User account associated with the event.",
    )

    # Process fields
    process: str | None = Field(
        default=None,
        description="Process name involved in the event.",
    )
    parent_process: str | None = Field(
        default=None,
        description="Parent process name.",
    )
    process_id: int | str | None = Field(
        default=None,
        description="Process identifier (PID).  Stored as string.",
    )
    parent_process_id: int | str | None = Field(
        default=None,
        description="Parent process identifier.",
    )

    # Network fields
    source_ip: str | None = Field(
        default=None,
        description="Source IPv4 or IPv6 address string.",
    )
    destination_ip: str | None = Field(
        default=None,
        description="Destination IPv4 or IPv6 address string.",
    )
    source_port: int | str | None = Field(
        default=None,
        description="Source port number (0–65535) or numeric string.",
    )
    destination_port: int | str | None = Field(
        default=None,
        description="Destination port number (0–65535) or numeric string.",
    )

    # File field
    file_path: str | None = Field(
        default=None,
        description="File system path affected by the event.",
    )

    # Domain
    domain: str | None = Field(
        default=None,
        description="Domain name associated with the event.",
    )

    # Action
    action: str | None = Field(
        default=None,
        description="Action performed (e.g. 'start', 'connect', 'create').",
    )
    action_result: str | None = Field(
        default=None,
        description="Result of the action: SUCCESS, FAILURE, or UNKNOWN.",
    )

    def extra_fields(self) -> dict:
        """
        Return a dict of fields that are not part of the declared schema.

        These are source-specific attributes that the normalizer will
        store in NormalizedEvent.extended_attributes.
        """
        known = set(self.model_fields)
        return {k: v for k, v in (self.model_extra or {}).items() if k not in known}
