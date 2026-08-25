"""
Hypothesis and HypothesisElement models.

A Hypothesis is a named, competing interpretation of the investigation.
Multiple hypotheses can reference overlapping evidence.

HypothesisElement links a Hypothesis to the specific evidence or steps it
draws on using explicit typed foreign keys (event_id, relationship_id,
reconstruction_step_id, evidence_id, gap_id). A CHECK constraint ensures
that exactly one foreign key is populated per element.

IMPORTANT: No probability scores, no AI confidence scores. The analyst's
status field is the only verdict: SUPPORTED, REJECTED, UNRESOLVED.
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
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship as sa_relationship

from app.core.database import Base
from app.models.mixins import UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.evidence import Evidence
    from app.models.gap import EvidenceGap
    from app.models.investigation import Investigation
    from app.models.normalized_event import NormalizedEvent
    from app.models.reconstruction import Reconstruction, ReconstructionStep
    from app.models.relationship import Relationship


class Hypothesis(UUIDPrimaryKeyMixin, Base):
    """
    A named interpretation of the investigation.

    One investigation may have multiple competing hypotheses.
    Hypotheses may share overlapping evidence (via HypothesisElement).
    """

    __tablename__ = "hypothesis"
    __table_args__ = (
        CheckConstraint(
            "status IN ('SUPPORTED', 'REJECTED', 'UNRESOLVED')",
            name="ck_hypothesis_status",
        ),
        Index("ix_hypothesis_investigation_id", "investigation_id"),
        Index("ix_hypothesis_status", "status"),
    )

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigation.id", ondelete="RESTRICT"),
        nullable=False,
    )
    reconstruction_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("reconstruction.id", ondelete="SET NULL"),
        nullable=True,
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="UNRESOLVED", server_default="UNRESOLVED"
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
        "Investigation", back_populates="hypotheses"
    )
    reconstruction: Mapped["Reconstruction | None"] = sa_relationship(
        "Reconstruction", back_populates="hypotheses"
    )
    elements: Mapped[list["HypothesisElement"]] = sa_relationship(
        "HypothesisElement", back_populates="hypothesis", lazy="noload"
    )


class HypothesisElement(UUIDPrimaryKeyMixin, Base):
    """
    Links a Hypothesis to the evidence or step it draws on.

    Uses explicit nullable foreign keys with a CHECK constraint enforcing
    that exactly one target FK is populated.
    """

    __tablename__ = "hypothesis_element"
    __table_args__ = (
        CheckConstraint(
            "("
            "(CASE WHEN event_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN relationship_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN reconstruction_step_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN evidence_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN gap_id IS NOT NULL THEN 1 ELSE 0 END)"
            ") = 1",
            name="ck_hypothesis_element_exactly_one_fk",
        ),
        Index("ix_hypothesis_element_hypothesis_id", "hypothesis_id"),
        Index("ix_hypothesis_element_event_id", "event_id"),
        Index("ix_hypothesis_element_relationship_id", "relationship_id"),
        Index("ix_hypothesis_element_reconstruction_step_id", "reconstruction_step_id"),
        Index("ix_hypothesis_element_evidence_id", "evidence_id"),
        Index("ix_hypothesis_element_gap_id", "gap_id"),
    )

    hypothesis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("hypothesis.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Explicit typed foreign keys
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
    reconstruction_step_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("reconstruction_step.id", ondelete="RESTRICT"),
        nullable=True,
    )
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence.id", ondelete="RESTRICT"),
        nullable=True,
    )
    gap_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_gap.id", ondelete="RESTRICT"),
        nullable=True,
    )

    analyst_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    hypothesis: Mapped["Hypothesis"] = sa_relationship(
        "Hypothesis", back_populates="elements"
    )
    event: Mapped["NormalizedEvent | None"] = sa_relationship(
        "NormalizedEvent", back_populates="hypothesis_elements"
    )
    relationship: Mapped["Relationship | None"] = sa_relationship(
        "Relationship",
        primaryjoin="HypothesisElement.relationship_id == Relationship.id",
        back_populates="hypothesis_elements",
    )
    reconstruction_step: Mapped["ReconstructionStep | None"] = sa_relationship(
        "ReconstructionStep", back_populates="hypothesis_elements"
    )
    evidence: Mapped["Evidence | None"] = sa_relationship(
        "Evidence", back_populates="hypothesis_elements"
    )
    gap: Mapped["EvidenceGap | None"] = sa_relationship(
        "EvidenceGap", back_populates="hypothesis_elements"
    )
