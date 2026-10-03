"""
Investigation module — Phase 6A.

Phase 6A public API
-------------------
confirm_relationship  — accept a SYSTEM_PROPOSED relationship.
reject_relationship   — reject a SYSTEM_PROPOSED or ANALYST_CONFIRMED
                        relationship.

Both functions update Relationship.status and Relationship.status_changed_at,
append an immutable AnalystAction audit record, and flush within the
caller-owned transaction.

Every analyst action is an immutable audit record.  Actions are appended,
never overwritten.
"""

from app.investigation.service import (
    InvalidRelationshipTransitionError,
    RelationshipNotFoundError,
    confirm_relationship,
    reject_relationship,
)

__all__ = [
    "confirm_relationship",
    "reject_relationship",
    "RelationshipNotFoundError",
    "InvalidRelationshipTransitionError",
]
