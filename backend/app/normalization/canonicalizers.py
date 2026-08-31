"""
Field canonicalization helpers for the normalization engine.

Each function takes a raw value from the parsed JSON and returns a
canonical representation suitable for storage in NormalizedEvent or
Entity.canonical_value.

Design rules
------------
- Every function is pure (no I/O, no DB, no network calls).
- Every function is deterministic: same input → same output, always.
- Canonicalization never interprets security semantics.  A function that
  lowercases a hostname does not decide whether the host is malicious.
- Where canonicalization changes the original value, the caller is
  responsible for preserving the original in extended_attributes if
  forensic context requires it.

Host canonicalization
---------------------
Rule: strip whitespace, convert to lowercase.
Rationale: LAPTOP-07 and laptop-07 are the same physical host. Case
differences are an artifact of log sources, not meaningful distinctions.
Original is preserved in extended_attributes["original_host"] when changed.

User canonicalization
---------------------
Rule: strip accidental surrounding whitespace only.
The form of the username (plain, DOMAIN\\user, user@domain) carries
identity semantics that we must not collapse.  These forms may or may not
represent the same principal — that determination belongs to the entity
resolution phase (future).

Process canonicalization
------------------------
Rule: strip whitespace, convert to lowercase.
Rationale: PowerShell.exe and powershell.exe are the same binary on Windows.
Preserving case would create spurious entity duplicates.
Full paths and parent names preserve useful forensic context and are
retained as-is within their fields.

IP address canonicalization
---------------------------
Rule: parse with stdlib ipaddress, return canonical text representation.
- 192.168.001.001 → 192.168.1.1 (IPv4 leading zeros removed)
- ::FFFF:127.0.0.1 → ::ffff:127.0.0.1 (IPv6 lowercased, compressed)
Invalid addresses raise ValueError (caller converts to NormalizationError).

Port canonicalization
---------------------
Rule: accept int or numeric string; validate 0 ≤ port ≤ 65535.
No service-name → port mapping.
Invalid values raise ValueError.
"""

from __future__ import annotations

import ipaddress


# ──────────────────────────────────────────────────────────────────────────────
# Host
# ──────────────────────────────────────────────────────────────────────────────


def canonicalize_host(raw: str) -> str:
    """
    Return the canonical host identifier.

    Steps:
      1. Strip surrounding whitespace.
      2. Convert to lowercase.

    The caller should check whether the result differs from the original
    and store the original in extended_attributes["original_host"] if so.
    """
    return raw.strip().lower()


# ──────────────────────────────────────────────────────────────────────────────
# User
# ──────────────────────────────────────────────────────────────────────────────


def canonicalize_user(raw: str) -> str:
    """
    Return the canonical user representation.

    Only strips accidental surrounding whitespace.  The form of the username
    (plain, DOMAIN\\user, user@domain) is preserved exactly because those
    forms may carry distinct identity semantics.

    Example:
        "  pradeep  " → "pradeep"
        "DOMAIN\\pradeep" → "DOMAIN\\pradeep"   (unchanged)
        "pradeep@example.com" → "pradeep@example.com"  (unchanged)
    """
    return raw.strip()


# ──────────────────────────────────────────────────────────────────────────────
# Process name
# ──────────────────────────────────────────────────────────────────────────────


def canonicalize_process_name(raw: str) -> str:
    """
    Return the canonical process name.

    Steps:
      1. Strip surrounding whitespace.
      2. Convert to lowercase.

    Rationale: on Windows, PowerShell.exe, powershell.exe, and
    POWERSHELL.EXE all refer to the same binary.  Lowercase is chosen as
    the canonical form.

    Full executable paths and command-line arguments are NOT stripped here;
    the caller passes only the process name field.  If the source provides
    a full path, the caller should split it appropriately.

    The caller should check whether the result differs from the original
    and store the original in extended_attributes["original_process_name"].
    """
    return raw.strip().lower()


# ──────────────────────────────────────────────────────────────────────────────
# IP addresses
# ──────────────────────────────────────────────────────────────────────────────


def canonicalize_ip(raw: str) -> str:
    """
    Parse and return the canonical textual IP address.

    Supports IPv4 and IPv6.  Uses stdlib ipaddress for validation and
    canonical formatting.

    Raises:
        ValueError: if raw is not a valid IPv4 or IPv6 address.

    Examples:
        "192.168.001.001" → ValueError (Python ipaddress rejects leading zeros)
        "192.168.1.1"     → "192.168.1.1"
        "::1"             → "::1"
        "::FFFF:127.0.0.1" → "::ffff:127.0.0.1"
    """
    stripped = raw.strip()
    # ipaddress.ip_address() accepts both IPv4Address and IPv6Address strings
    # and raises ValueError for invalid input.
    addr = ipaddress.ip_address(stripped)
    return str(addr)


# ──────────────────────────────────────────────────────────────────────────────
# Ports
# ──────────────────────────────────────────────────────────────────────────────

_PORT_MIN = 0
_PORT_MAX = 65535


def canonicalize_port(raw: int | str) -> int:
    """
    Validate and return the port as an integer.

    Accepts:
        - An integer directly.
        - A string containing a decimal integer (e.g. "443").

    Does NOT accept:
        - Service names (e.g. "https", "ssh").
        - Negative values.
        - Values above 65535.

    Raises:
        ValueError: if the port is invalid.
    """
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped.isdigit():
            raise ValueError(
                f"Port must be a decimal integer, got: {stripped!r}"
            )
        port = int(stripped)
    elif isinstance(raw, int):
        port = raw
    else:
        raise ValueError(f"Port must be int or numeric string, got: {type(raw).__name__}")

    if not (_PORT_MIN <= port <= _PORT_MAX):
        raise ValueError(
            f"Port {port} is out of range {_PORT_MIN}–{_PORT_MAX}"
        )
    return port
