"""
Reconstruction and ReconstructionStep models.

A Reconstruction is a candidate narrative — a proposed attack chain.
It must not be treated as absolute truth.

ReconstructionStep is an ordered element within a Reconstruction.
A step can reference an event, a relationship, or an evidence gap.
This allows incomplete reconstructions: unknown sections are represented
by GAP steps rather than invented events.

Step ordering uses integer gaps (10, 20, 30...) to allow insertions
without renumbering.
"""

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship as sa_relationship

from app.core.database import Base
from app.models.mixins import UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.gap import EvidenceGap
    from app.models.hypothesis import Hypothesis, HypothesisElement
    from app.models.investigation import Investigation
    from app.models.normalized_event import NormalizedEvent
    from app.models.relationship import Relationship


class Reconstruction(UUIDPrimaryKeyMixin, Base):
    """A candidate attack narrative assembled from events and relationships."""

    __tablename__ = "reconstruction"
    __table_args__ = (
        CheckConstraint(
            "status IN ('DRAFT', 'UNDER_REVIEW', 'ACCEPTED', 'REJECTED')",
            name="ck_reconstruction_status",
        ),
        Index("ix_reconstruction_investigation_id", "investigation_id"),
        Index("ix_reconstruction_status", "status"),
    )

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigation.id", ondelete="RESTRICT"),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="DRAFT", server_default="DRAFT"
    )
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Relationships
    investigation: Mapped["Investigation"] = sa_relationship(
        "Investigation", back_populates="reconstructions"
    )
    steps: Mapped[list["ReconstructionStep"]] = sa_relationship(
        "ReconstructionStep",
        back_populates="reconstruction",
        order_by="ReconstructionStep.step_order",
        lazy="noload",
    )
    hypotheses: Mapped[list["Hypothesis"]] = sa_relationship(
        "Hypothesis", back_populates="reconstruction", lazy="noload"
    )


class ReconstructionStep(UUIDPrimaryKeyMixin, Base):
    """
    An ordered element within a Reconstruction.

    step_type determines which FK is set:
      EVENT        → event_id is set
      RELATIONSHIP → relationship_id is set
      GAP          → gap_id is set
      NOTE         → no FK, analyst_note carries the content
    """

    __tablename__ = "reconstruction_step"
    __table_args__ = (
        UniqueConstraint(
            "reconstruction_id", "step_order", name="uq_reconstruction_step_order"
        ),
        CheckConstraint(
            "step_type IN ('EVENT', 'RELATIONSHIP', 'GAP', 'NOTE')",
            name="ck_reconstruction_step_type",
        ),
        # Mutual exclusion based on step_type
        CheckConstraint(
            "(step_type = 'EVENT' AND event_id IS NOT NULL AND relationship_id IS NULL AND gap_id IS NULL) OR "
            "(step_type = 'RELATIONSHIP' AND relationship_id IS NOT NULL AND event_id IS NULL AND gap_id IS NULL) OR "
            "(step_type = 'GAP' AND gap_id IS NOT NULL AND event_id IS NULL AND relationship_id IS NULL) OR "
            "(step_type = 'NOTE' AND event_id IS NULL AND relationship_id IS NULL AND gap_id IS NULL)",
            name="ck_reconstruction_step_fk_match",
        ),
        Index("ix_reconstruction_step_reconstruction_id", "reconstruction_id"),
        Index("ix_reconstruction_step_event_id", "event_id"),
        Index("ix_reconstruction_step_relationship_id", "relationship_id"),
        Index("ix_reconstruction_step_gap_id", "gap_id"),
    )

    reconstruction_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("reconstruction.id", ondelete="CASCADE"),
        nullable=False,
    )
    step_order: Mapped[int] = mapped_column(Integer, nullable=False)
    step_type: Mapped[str] = mapped_column(String(50), nullable=False)
    event_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("normalized_event.id", ondelete="RESTRICT"),
        nullable=True,
    )
    relationship_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("relationship.id", ondelete="RESTRICT"),
        nullable=True,
    )
    gap_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_gap.id", ondelete="RESTRICT"),
        nullable=True,
    )
    analyst_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    reconstruction: Mapped["Reconstruction"] = sa_relationship(
        "Reconstruction", back_populates="steps"
    )
    event: Mapped["NormalizedEvent | None"] = sa_relationship(
        "NormalizedEvent",
        primaryjoin="ReconstructionStep.event_id == NormalizedEvent.id",
        back_populates="reconstruction_steps",
    )
    relationship: Mapped["Relationship | None"] = sa_relationship(
        "Relationship",
        primaryjoin="ReconstructionStep.relationship_id == Relationship.id",
        back_populates="reconstruction_steps",
    )
    gap: Mapped["EvidenceGap | None"] = sa_relationship(
        "EvidenceGap", back_populates="reconstruction_steps"
    )
    hypothesis_elements: Mapped[list["HypothesisElement"]] = sa_relationship(
        "HypothesisElement", back_populates="reconstruction_step", lazy="noload"
    )
