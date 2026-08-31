"""
Normalization service for Phase 3B.

PUBLIC API
----------
normalize_evidence(session, evidence) -> NormalizationResult

    Reads the raw bytes from a preserved Evidence record, parses the JSON,
    normalizes each event, creates NormalizedEvent records, creates or reuses
    Entity records, and links them via EventEntityRef.

    Uses all-or-nothing semantics: if any event fails validation, the entire
    operation raises PartialNormalizationFailure and no normalized state is
    written.

    Does NOT commit the session.  The caller is responsible for commit/rollback.

STRATEGY: ALL-OR-NOTHING
-------------------------
A multi-event Evidence file either fully normalizes or fully fails.
Rationale: partial normalized state (some events present, others absent)
is harder to explain forensically than a clean failure.  The raw Evidence
always remains intact regardless of normalization outcome.

ENTITY REUSE
------------
Before creating a new Entity, the service queries for an existing row with:
    (investigation_id, entity_type, canonical_value)
The database also enforces this via a UniqueConstraint, but we check first to
avoid unique-constraint exceptions in normal operation.

EXTENDED ATTRIBUTES STRATEGY
------------------------------
Fields that have a dedicated NormalizedEvent column are placed there.
Source-specific fields (present in the JSON but not in the schema) are
forwarded to extended_attributes.  If a canonicalization step changes the
original value, the original is added under "original_<field>" in
extended_attributes.

Specifically:
- original_host   – if host canonicalization changed the value
- original_process_name – if process name canonicalization changed the value
- All extra JSON fields not covered by RawEventInput's declared fields

SECURITY
--------
- Field values are never executed, followed as paths, or used in shell commands.
- The source_identifier and field names from telemetry are not used as
  filesystem paths.
- IP/port values are parsed by stdlib ipaddress/int, not string-formatted
  into SQL.
- SQLAlchemy parameterized queries prevent SQL injection.
- No external network calls are made during normalization.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entity import Entity, EventEntityRef
from app.models.evidence import Evidence
from app.models.normalized_event import NormalizedEvent
from app.normalization.canonicalizers import (
    canonicalize_host,
    canonicalize_ip,
    canonicalize_port,
    canonicalize_process_name,
    canonicalize_user,
)
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
    FILE_CREATE,
    FILE_DELETE,
    NETWORK_CONNECTION,
    PROCESS_START,
    USER_LOGIN,
    USER_LOGOUT,
    resolve_event_type,
)
from app.normalization.schemas import RawEventInput

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Result types
# ──────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SingleEventResult:
    """Result from normalizing one event within an Evidence record."""

    normalized_event: NormalizedEvent
    entities_created: int
    entities_reused: int


@dataclass
class NormalizationResult:
    """Result from normalizing a complete Evidence record."""

    evidence_id: uuid.UUID
    events: list[NormalizedEvent] = field(default_factory=list)
    total_entities_created: int = 0
    total_entities_reused: int = 0

    @property
    def event_count(self) -> int:
        return len(self.events)


# ──────────────────────────────────────────────────────────────────────────────
# Timestamp parsing
# ──────────────────────────────────────────────────────────────────────────────


def parse_timestamp_utc(raw: str, event_index: int | None = None) -> datetime:
    """
    Parse an ISO-8601 timestamp string and return a UTC-aware datetime.

    Uses stdlib datetime.fromisoformat() which on Python ≥ 3.11 accepts
    the 'Z' suffix and all ±HH:MM offsets natively.

    Rules:
    - Must be parseable as ISO-8601.
    - Must carry explicit timezone information.
    - Naive timestamps (no timezone) are REJECTED.
    - Timezone-aware timestamps are converted to UTC.

    Raises:
        NormalizationFailure – with code INVALID_TIMESTAMP.
    """
    try:
        dt = datetime.fromisoformat(raw)
    except (ValueError, OverflowError):
        raise NormalizationFailure.single(
            code=INVALID_TIMESTAMP,
            field="timestamp",
            reason="Cannot parse timestamp string as ISO-8601",
            event_index=event_index,
        )

    if dt.tzinfo is None:
        raise NormalizationFailure.single(
            code=INVALID_TIMESTAMP,
            field="timestamp",
            reason=(
                "Timestamp has no timezone information.  "
                "All timestamps must carry explicit UTC offset or 'Z' suffix.  "
                "Timezone cannot be assumed."
            ),
            event_index=event_index,
        )

    return dt.astimezone(timezone.utc)


# ──────────────────────────────────────────────────────────────────────────────
# Action result validation
# ──────────────────────────────────────────────────────────────────────────────

_VALID_ACTION_RESULTS = frozenset({"SUCCESS", "FAILURE", "UNKNOWN"})


def validate_action_result(
    raw: str | None, event_index: int | None = None
) -> str | None:
    if raw is None:
        return None
    normalized = raw.strip().upper()
    if normalized not in _VALID_ACTION_RESULTS:
        raise NormalizationFailure.single(
            code=INVALID_FIELD_VALUE,
            field="action_result",
            reason=f"action_result must be one of: SUCCESS, FAILURE, UNKNOWN",
            event_index=event_index,
        )
    return normalized


# ──────────────────────────────────────────────────────────────────────────────
# Single-event normalization (pure: validates and builds NormalizedEvent)
# ──────────────────────────────────────────────────────────────────────────────


def _normalize_single_event(
    raw_input: RawEventInput,
    investigation_id: uuid.UUID,
    evidence_id: uuid.UUID,
    event_index: int | None = None,
) -> tuple[NormalizedEvent, dict]:
    """
    Validate and map one RawEventInput to a NormalizedEvent ORM object.

    Returns:
        (NormalizedEvent, entity_specs) where entity_specs is a dict
        describing entities that should be created/reused for this event.
        entity_specs maps role → (entity_type, canonical_value, attributes).

    Raises:
        NormalizationFailure on any validation error.

    Note: This function does NOT flush to the DB.  Entity creation is
    handled by the caller so that reuse can be tracked session-wide.
    """
    errors: list[NormalizationError] = []

    # ── Event type ────────────────────────────────────────────────────────────
    try:
        canonical_type, category = resolve_event_type(raw_input.event_type)
    except KeyError:
        from app.normalization.events import SUPPORTED_EVENT_TYPES
        errors.append(
            NormalizationError(
                code=UNKNOWN_EVENT_TYPE,
                field="event_type",
                reason=(
                    f"Event type {raw_input.event_type!r} is not recognized.  "
                    f"Supported types: {', '.join(SUPPORTED_EVENT_TYPES)}"
                ),
                event_index=event_index,
            )
        )
        # Cannot continue without a valid type.
        raise NormalizationFailure(errors)

    # ── Timestamp ─────────────────────────────────────────────────────────────
    occurred_at = parse_timestamp_utc(raw_input.timestamp, event_index=event_index)

    # ── Host ──────────────────────────────────────────────────────────────────
    extended: dict = {}
    source_host: str | None = None

    if raw_input.host is not None:
        canonical_host = canonicalize_host(raw_input.host)
        if canonical_host != raw_input.host:
            extended["original_host"] = raw_input.host
        source_host = canonical_host

    # ── User ──────────────────────────────────────────────────────────────────
    source_user: str | None = None
    if raw_input.user is not None:
        source_user = canonicalize_user(raw_input.user)

    # ── Process name ──────────────────────────────────────────────────────────
    process_name: str | None = None
    if raw_input.process is not None:
        canonical_proc = canonicalize_process_name(raw_input.process)
        if canonical_proc != raw_input.process:
            extended["original_process_name"] = raw_input.process
        process_name = canonical_proc

    # ── Parent process name ───────────────────────────────────────────────────
    parent_process_name: str | None = None
    if raw_input.parent_process is not None:
        canonical_parent = canonicalize_process_name(raw_input.parent_process)
        if canonical_parent != raw_input.parent_process:
            extended["original_parent_process_name"] = raw_input.parent_process
        parent_process_name = canonical_parent

    # ── Process ID ───────────────────────────────────────────────────────────
    process_id: str | None = None
    if raw_input.process_id is not None:
        process_id = str(raw_input.process_id)
        if len(process_id) > 20:
            errors.append(NormalizationError(
                code=INVALID_FIELD_VALUE,
                field="process_id",
                reason="process_id exceeds maximum length of 20 characters",
                event_index=event_index,
            ))

    parent_process_id: str | None = None
    if raw_input.parent_process_id is not None:
        parent_process_id = str(raw_input.parent_process_id)
        if len(parent_process_id) > 20:
            errors.append(NormalizationError(
                code=INVALID_FIELD_VALUE,
                field="parent_process_id",
                reason="parent_process_id exceeds maximum length of 20 characters",
                event_index=event_index,
            ))

    # ── IP addresses ──────────────────────────────────────────────────────────
    source_ip: str | None = None
    if raw_input.source_ip is not None:
        try:
            source_ip = canonicalize_ip(raw_input.source_ip)
        except ValueError:
            errors.append(NormalizationError(
                code=INVALID_IP,
                field="source_ip",
                reason="source_ip is not a valid IPv4 or IPv6 address",
                event_index=event_index,
            ))

    destination_ip: str | None = None
    if raw_input.destination_ip is not None:
        try:
            destination_ip = canonicalize_ip(raw_input.destination_ip)
        except ValueError:
            errors.append(NormalizationError(
                code=INVALID_IP,
                field="destination_ip",
                reason="destination_ip is not a valid IPv4 or IPv6 address",
                event_index=event_index,
            ))

    # ── Ports ─────────────────────────────────────────────────────────────────
    source_port: int | None = None
    if raw_input.source_port is not None:
        try:
            source_port = canonicalize_port(raw_input.source_port)
        except ValueError:
            errors.append(NormalizationError(
                code=INVALID_PORT,
                field="source_port",
                reason="source_port must be an integer in range 0–65535",
                event_index=event_index,
            ))

    destination_port: int | None = None
    if raw_input.destination_port is not None:
        try:
            destination_port = canonicalize_port(raw_input.destination_port)
        except ValueError:
            errors.append(NormalizationError(
                code=INVALID_PORT,
                field="destination_port",
                reason="destination_port must be an integer in range 0–65535",
                event_index=event_index,
            ))

    # ── Action result ─────────────────────────────────────────────────────────
    try:
        action_result = validate_action_result(raw_input.action_result, event_index)
    except NormalizationFailure as exc:
        errors.extend(exc.errors)
        action_result = None

    # ── File path ─────────────────────────────────────────────────────────────
    file_path: str | None = raw_input.file_path

    # ── Domain ────────────────────────────────────────────────────────────────
    domain: str | None = raw_input.domain

    # ── Action ───────────────────────────────────────────────────────────────
    action: str | None = raw_input.action

    # ── Extended attributes ───────────────────────────────────────────────────
    # Merge source-specific extra fields (not declared in RawEventInput) into
    # extended attributes.  Declared fields that already have dedicated columns
    # are NOT duplicated here.
    extra = raw_input.extra_fields()
    if extra:
        extended.update(extra)

    # Include "source" in extended_attributes for traceability.
    if raw_input.source is not None:
        extended["source"] = raw_input.source

    # ── Fail if any errors accumulated ───────────────────────────────────────
    if errors:
        raise NormalizationFailure(errors)

    # ── Build NormalizedEvent ─────────────────────────────────────────────────
    event = NormalizedEvent(
        investigation_id=investigation_id,
        evidence_id=evidence_id,
        occurred_at=occurred_at,
        event_type=canonical_type,
        event_category=category,
        source_host=source_host,
        source_user=source_user,
        process_name=process_name,
        process_id=process_id,
        parent_process_name=parent_process_name,
        parent_process_id=parent_process_id,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        file_path=file_path,
        domain=domain,
        action=action,
        action_result=action_result,
        extended_attributes=extended if extended else None,
    )

    # ── Determine entity specs for this event ─────────────────────────────────
    # entity_specs: list of (role, entity_type, canonical_value, attributes)
    entity_specs: list[tuple[str, str, str, dict | None]] = []

    if source_host:
        entity_specs.append(("SOURCE_HOST", "HOST", source_host, None))

    if source_user:
        entity_specs.append(("ACTING_USER", "USER", source_user, None))

    if canonical_type in (PROCESS_START, FILE_CREATE, FILE_DELETE):
        if process_name:
            entity_specs.append(("ACTING_PROCESS", "PROCESS", process_name, None))
        if parent_process_name:
            entity_specs.append(("PARENT_PROCESS", "PROCESS", parent_process_name, None))

    if canonical_type == NETWORK_CONNECTION:
        if source_ip:
            entity_specs.append(("SOURCE_IP", "IP_ADDRESS", source_ip, None))
        if destination_ip:
            entity_specs.append(("DESTINATION_IP", "IP_ADDRESS", destination_ip, None))

    if canonical_type in (FILE_CREATE, FILE_DELETE):
        if file_path:
            entity_specs.append(("TARGET_FILE", "FILE", file_path, None))

    return event, entity_specs


# ──────────────────────────────────────────────────────────────────────────────
# Entity reuse helper
# ──────────────────────────────────────────────────────────────────────────────


async def _get_or_create_entity(
    session: AsyncSession,
    investigation_id: uuid.UUID,
    entity_type: str,
    canonical_value: str,
    attributes: dict | None,
    occurred_at: datetime,
    entity_cache: dict[tuple[str, str], Entity],
) -> tuple[Entity, bool]:
    """
    Return an existing Entity or create a new one.

    Uses a per-call cache keyed by (entity_type, canonical_value) to avoid
    repeated DB queries within a single normalize_evidence() call.

    Returns:
        (entity, was_created)
    """
    cache_key = (entity_type, canonical_value)
    if cache_key in entity_cache:
        return entity_cache[cache_key], False

    result = await session.execute(
        select(Entity).where(
            Entity.investigation_id == investigation_id,
            Entity.entity_type == entity_type,
            Entity.canonical_value == canonical_value,
        )
    )
    existing = result.scalar_one_or_none()

    if existing is not None:
        entity_cache[cache_key] = existing
        return existing, False

    entity = Entity(
        investigation_id=investigation_id,
        entity_type=entity_type,
        canonical_value=canonical_value,
        attributes=attributes,
        first_seen_at=occurred_at,
        last_seen_at=occurred_at,
    )
    session.add(entity)
    await session.flush()  # obtain ID for EventEntityRef FK
    entity_cache[cache_key] = entity
    return entity, True


# ──────────────────────────────────────────────────────────────────────────────
# Evidence reading helpers
# ──────────────────────────────────────────────────────────────────────────────


def _read_evidence_bytes(evidence: Evidence) -> bytes:
    """
    Return the raw bytes of an Evidence record.

    Reads from storage_reference (filesystem) if available.
    Falls back to original_content (inline text) otherwise.

    Raises:
        NormalizationFailure – if neither source is available.
        NormalizationFailure – if the storage file cannot be read.
    """
    if evidence.storage_reference is not None:
        ref = Path(evidence.storage_reference)
        if not ref.is_absolute():
            # Resolve relative paths from the repo root.
            repo_root = Path(__file__).resolve().parents[3]
            ref = repo_root / ref
        try:
            return ref.read_bytes()
        except OSError as exc:
            raise NormalizationFailure.single(
                code="STORAGE_READ_ERROR",
                field=None,
                reason=f"Cannot read evidence file: {exc.strerror}",
            )

    if evidence.original_content is not None:
        return evidence.original_content.encode("utf-8")

    raise NormalizationFailure.single(
        code=MISSING_REQUIRED_FIELD,
        field=None,
        reason="Evidence record has neither storage_reference nor original_content",
    )


def _parse_evidence_events(raw_bytes: bytes) -> list[RawEventInput]:
    """
    Parse raw evidence bytes into a list of RawEventInput objects.

    Supports two JSON structures:
      - A single JSON object  → treated as one event
      - A JSON array of objects → each element is one event

    Returns a non-empty list.

    Raises:
        NormalizationFailure – if the JSON is invalid or has unexpected structure.
    """
    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise NormalizationFailure.single(
            code=INVALID_FIELD_TYPE,
            field=None,
            reason="Evidence bytes are not valid UTF-8 JSON",
        )

    if isinstance(data, dict):
        items = [data]
    elif isinstance(data, list):
        if not data:
            raise NormalizationFailure.single(
                code=INVALID_FIELD_VALUE,
                field=None,
                reason="Evidence JSON array contains no events",
            )
        items = data
    else:
        raise NormalizationFailure.single(
            code=INVALID_FIELD_TYPE,
            field=None,
            reason="Evidence JSON must be an object or array of objects",
        )

    parsed: list[RawEventInput] = []
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            raise NormalizationFailure.single(
                code=INVALID_FIELD_TYPE,
                field=None,
                reason=f"Event at index {idx} is not a JSON object",
                event_index=idx,
            )
        # Validate structure with Pydantic; missing required fields surface here.
        from pydantic import ValidationError

        try:
            parsed.append(RawEventInput.model_validate(item))
        except ValidationError as exc:
            errors = []
            for e in exc.errors():
                loc = ".".join(str(l) for l in e["loc"]) if e["loc"] else None
                errors.append(
                    NormalizationError(
                        code=MISSING_REQUIRED_FIELD if e["type"] == "missing" else INVALID_FIELD_TYPE,
                        field=loc,
                        reason=e["msg"],
                        event_index=idx,
                    )
                )
            raise NormalizationFailure(errors)

    return parsed


# ──────────────────────────────────────────────────────────────────────────────
# Main public API
# ──────────────────────────────────────────────────────────────────────────────


async def normalize_evidence(
    *,
    session: AsyncSession,
    evidence: Evidence,
) -> NormalizationResult:
    """
    Normalize all events contained in a preserved Evidence record.

    Parameters
    ----------
    session:
        An open async SQLAlchemy session.  The caller is responsible for
        committing or rolling back.
    evidence:
        The Evidence ORM instance to normalize.  Must have investigation_id
        set and either storage_reference or original_content populated.

    Returns
    -------
    NormalizationResult
        Contains all created NormalizedEvent instances and entity statistics.

    Raises
    ------
    NormalizationFailure
        If the evidence bytes cannot be read or parsed, or if a
        single-event evidence file contains an invalid event.
    PartialNormalizationFailure
        If a multi-event evidence file contains one or more invalid events.
        Under the all-or-nothing strategy this is also a complete failure.

    Transaction safety:
        The raw Evidence record is NEVER modified.
        If normalization fails after some DB writes have occurred,
        the caller's rollback will undo those writes.
        Flushing is done incrementally for Entity creation; NormalizedEvent
        objects are flushed together at the end.
    """
    investigation_id = evidence.investigation_id
    evidence_id = evidence.id

    # ── 1. Read raw bytes ─────────────────────────────────────────────────────
    raw_bytes = _read_evidence_bytes(evidence)

    # ── 2. Parse JSON into event inputs ───────────────────────────────────────
    raw_inputs = _parse_evidence_events(raw_bytes)

    # ── 3. Validate ALL events before writing any DB records ──────────────────
    #  (all-or-nothing: validate phase)
    pre_validated: list[tuple[NormalizedEvent, list[tuple[str, str, str, dict | None]]]] = []
    failures: dict[int, list[NormalizationError]] = {}

    for idx, raw_input in enumerate(raw_inputs):
        try:
            event_obj, entity_specs = _normalize_single_event(
                raw_input=raw_input,
                investigation_id=investigation_id,
                evidence_id=evidence_id,
                event_index=idx if len(raw_inputs) > 1 else None,
            )
            pre_validated.append((event_obj, entity_specs))
        except NormalizationFailure as exc:
            failures[idx] = exc.errors

    if failures:
        # For a single-event file: re-raise as NormalizationFailure so callers
        # can catch it without also handling PartialNormalizationFailure.
        # PartialNormalizationFailure is only meaningful for multi-event files
        # where a subset of events failed.
        if len(raw_inputs) == 1:
            raise NormalizationFailure(failures[0])
        raise PartialNormalizationFailure(
            failures=failures,
            total_events=len(raw_inputs),
        )

    # ── 4. Write NormalizedEvents and Entities (all valid) ────────────────────
    result = NormalizationResult(evidence_id=evidence_id)
    entity_cache: dict[tuple[str, str], Entity] = {}

    for event_obj, entity_specs in pre_validated:
        session.add(event_obj)
        await session.flush()  # obtain ID for EventEntityRef

        for role, entity_type, canonical_value, attributes in entity_specs:
            entity, was_created = await _get_or_create_entity(
                session=session,
                investigation_id=investigation_id,
                entity_type=entity_type,
                canonical_value=canonical_value,
                attributes=attributes,
                occurred_at=event_obj.occurred_at,
                entity_cache=entity_cache,
            )

            ref = EventEntityRef(
                event_id=event_obj.id,
                entity_id=entity.id,
                role=role,
            )
            session.add(ref)

            if was_created:
                result.total_entities_created += 1
            else:
                result.total_entities_reused += 1

        result.events.append(event_obj)

    await session.flush()

    logger.info(
        "Normalized evidence %s: %d event(s), %d entities created, %d reused",
        evidence_id,
        result.event_count,
        result.total_entities_created,
        result.total_entities_reused,
    )

    return result
