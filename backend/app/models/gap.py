"""
EvidenceGap and GapEvent models.

An EvidenceGap is a first-class entity representing missing telemetry.
The system never invents events to fill a gap — it surfaces the gap
explicitly so the investigator must acknowledge what is unknown.

GapEvent is a junction table linking an EvidenceGap to its surrounding
NormalizedEvents with an explicit role (PRECEDING or FOLLOWING).
This makes telemetry-gap context queryable without relying solely
on reconstruction narrative step ordering.
"""

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.mixins import UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.hypothesis import HypothesisElement
    from app.models.investigation import Investigation
    from app.models.normalized_event import NormalizedEvent
    from app.models.reconstruction import ReconstructionStep


class EvidenceGap(UUIDPrimaryKeyMixin, Base):
    """
    An explicit representation of a period of missing telemetry.

    gap_start and gap_end define the known time window where telemetry
    is absent.  Both are nullable — a gap may be temporally unbounded.
    """

    __tablename__ = "evidence_gap"
    __table_args__ = (
        CheckConstraint(
            "gap_end IS NULL OR gap_start IS NULL OR gap_end > gap_start",
            name="ck_evidence_gap_time_order",
        ),
        CheckConstraint(
            "status IN ('OPEN', 'EXPLAINED', 'UNRESOLVABLE')",
            name="ck_evidence_gap_status",
        ),
        Index("ix_evidence_gap_investigation_id", "investigation_id"),
        Index("ix_evidence_gap_start", "gap_start"),
        Index("ix_evidence_gap_end", "gap_end"),
        Index("ix_evidence_gap_status", "status"),
    )

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigation.id", ondelete="RESTRICT"),
        nullable=False,
    )
    gap_start: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    gap_end: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="OPEN", server_default="OPEN"
    )
    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # Relationships
    investigation: Mapped["Investigation"] = relationship(
        "Investigation", back_populates="gaps"
    )
    gap_events: Mapped[list["GapEvent"]] = relationship(
        "GapEvent", back_populates="gap", lazy="noload"
    )
    reconstruction_steps: Mapped[list["ReconstructionStep"]] = relationship(
        "ReconstructionStep", back_populates="gap", lazy="noload"
    )
    hypothesis_elements: Mapped[list["HypothesisElement"]] = relationship(
        "HypothesisElement", back_populates="gap", lazy="noload"
    )


class GapEvent(UUIDPrimaryKeyMixin, Base):
    """
    Junction table linking an EvidenceGap to preceding or following events.

    Provides explicit structured boundary context for missing telemetry windows.
    """

    __tablename__ = "gap_event"
    __table_args__ = (
        UniqueConstraint("gap_id", "event_id", "role", name="uq_gap_event_role"),
        CheckConstraint(
            "role IN ('PRECEDING', 'FOLLOWING')",
            name="ck_gap_event_role",
        ),
        Index("ix_gap_event_gap_id", "gap_id"),
        Index("ix_gap_event_event_id", "event_id"),
        Index("ix_gap_event_gap_role", "gap_id", "role"),
    )

    gap_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_gap.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("normalized_event.id", ondelete="RESTRICT"),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(String(50), nullable=False)

    # Relationships
    gap: Mapped["EvidenceGap"] = relationship("EvidenceGap", back_populates="gap_events")
    event: Mapped["NormalizedEvent"] = relationship(
        "NormalizedEvent", back_populates="gap_events"
    )
