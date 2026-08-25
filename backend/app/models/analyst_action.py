"""
AnalystAction model.

AnalystAction is an append-only audit log of every investigator decision.
Every important change to the domain is recorded here.

CRITICAL: This table is append-only by policy.
  - Application layer enforces no UPDATE/DELETE endpoints for analyst_action.
  - acted_at is always set server-side (the application calls NOW()).
    Client-supplied timestamps are ignored to prevent backdating.

previous_state and new_state are JSONB snapshots of the relevant fields
at the time of the action.  This makes the audit log self-contained —
it does not depend on reading the current state of other tables.
"""

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.mixins import UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.investigation import Investigation

_ACTION_TYPES = (
    "CONFIRM_RELATIONSHIP",
    "REJECT_RELATIONSHIP",
    "CONNECT_EVENTS",
    "DISCONNECT_EVENTS",
    "CONFIRM_RECONSTRUCTION_STEP",
    "REJECT_RECONSTRUCTION_STEP",
    "ADD_INVESTIGATION_NOTE",
    "MARK_EVIDENCE_RELEVANT",
    "RESOLVE_CONFLICT",
    "DISMISS_CONFLICT",
    "CONFIRM_HYPOTHESIS",
    "REJECT_HYPOTHESIS",
    "CLOSE_INVESTIGATION",
)

_TARGET_OBJECT_TYPES = (
    "RELATIONSHIP",
    "EVENT",
    "RECONSTRUCTION",
    "RECONSTRUCTION_STEP",
    "HYPOTHESIS",
    "EVIDENCE",
    "CONFLICT",
    "GAP",
    "INVESTIGATION",
)


class AnalystAction(UUIDPrimaryKeyMixin, Base):
    """
    Append-only audit record of an analyst's decision.

    Audit questions answered:
      Who?   analyst_id
      What?  action_type + target_object_type + target_object_id
      When?  acted_at (server-side)
      Why?   reason + previous_state → new_state
    """

    __tablename__ = "analyst_action"
    __table_args__ = (
        CheckConstraint(
            f"action_type IN {_ACTION_TYPES}",
            name="ck_analyst_action_type",
        ),
        CheckConstraint(
            f"target_object_type IN {_TARGET_OBJECT_TYPES}",
            name="ck_analyst_action_target_type",
        ),
        Index("ix_analyst_action_investigation_id", "investigation_id"),
        Index("ix_analyst_action_analyst_id", "analyst_id"),
        Index("ix_analyst_action_action_type", "action_type"),
        Index("ix_analyst_action_target_object_id", "target_object_id"),
        Index("ix_analyst_action_acted_at", "acted_at"),
        Index(
            "ix_analyst_action_investigation_acted_at",
            "investigation_id",
            "acted_at",
        ),
    )

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigation.id", ondelete="RESTRICT"),
        nullable=False,
    )
    analyst_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    target_object_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target_object_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )
    previous_state: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    new_state: Mapped[dict] = mapped_column(JSONB, nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    acted_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationships
    investigation: Mapped["Investigation"] = relationship(
        "Investigation", back_populates="analyst_actions"
    )
