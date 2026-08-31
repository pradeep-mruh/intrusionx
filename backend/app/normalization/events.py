"""
Event type registry for the IntrusionX normalization engine.

This module defines the controlled vocabulary of event types and
their mapping to event categories.  It is the single authoritative
source for both the normalizer and the test suite.

Design rules:
- Event types are uppercase strings with underscores.
- Every event type maps to exactly one event category.
- The category is stored on NormalizedEvent.event_category.
- Unknown types MUST be rejected — not guessed, not coerced silently.

NORMALIZATION RULES (case/separator folding)
--------------------------------------------
Input strings are pre-processed before lookup:
  1. Strip surrounding whitespace.
  2. Convert to uppercase.
  3. Replace hyphens and spaces with underscores.

Examples:
  "process_start"   → PROCESS_START
  "PROCESS_START"   → PROCESS_START  (already canonical)
  "PROCESS-START"   → PROCESS_START  (hyphen → underscore)
  "network connection" → NETWORK_CONNECTION (space → underscore)

Anything that does NOT map to a recognized type after this folding is
rejected with an UNKNOWN_EVENT_TYPE error.  No fuzzy matching.
"""

from __future__ import annotations

# ──────────────────────────────────────────────────────────────────────────────
# Event categories  (must match ck_normalized_event_action_result NOT required;
# but event_category has no DB CHECK — values are validated here).
# ──────────────────────────────────────────────────────────────────────────────

CATEGORY_PROCESS = "PROCESS"
CATEGORY_NETWORK = "NETWORK"
CATEGORY_FILE = "FILE"
CATEGORY_AUTH = "AUTH"

# ──────────────────────────────────────────────────────────────────────────────
# Canonical event types
# ──────────────────────────────────────────────────────────────────────────────

PROCESS_START = "PROCESS_START"
NETWORK_CONNECTION = "NETWORK_CONNECTION"
FILE_CREATE = "FILE_CREATE"
FILE_DELETE = "FILE_DELETE"
USER_LOGIN = "USER_LOGIN"
USER_LOGOUT = "USER_LOGOUT"

# ──────────────────────────────────────────────────────────────────────────────
# Registry: canonical_event_type → event_category
# ──────────────────────────────────────────────────────────────────────────────

EVENT_TYPE_REGISTRY: dict[str, str] = {
    PROCESS_START: CATEGORY_PROCESS,
    NETWORK_CONNECTION: CATEGORY_NETWORK,
    FILE_CREATE: CATEGORY_FILE,
    FILE_DELETE: CATEGORY_FILE,
    USER_LOGIN: CATEGORY_AUTH,
    USER_LOGOUT: CATEGORY_AUTH,
}

# Sorted tuple for use in error messages.
SUPPORTED_EVENT_TYPES: tuple[str, ...] = tuple(sorted(EVENT_TYPE_REGISTRY))


def fold_event_type(raw: str) -> str:
    """
    Apply deterministic folding to a raw event_type string.

    This is a pre-processing step only.  The folded result is then looked
    up in EVENT_TYPE_REGISTRY.  If not found, an error must be raised by
    the caller.

    Steps:
      1. Strip surrounding whitespace.
      2. Convert to uppercase.
      3. Replace hyphens and spaces with underscores.
    """
    return raw.strip().upper().replace("-", "_").replace(" ", "_")


def resolve_event_type(raw: str) -> tuple[str, str]:
    """
    Resolve a raw event_type string to (canonical_type, category).

    Raises KeyError if the type is not in the registry after folding.
    The caller is responsible for converting KeyError to a domain error.
    """
    folded = fold_event_type(raw)
    category = EVENT_TYPE_REGISTRY[folded]
    return folded, category
